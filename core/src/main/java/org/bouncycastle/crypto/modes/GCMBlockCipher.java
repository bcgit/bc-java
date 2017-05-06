package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.gcm.GCMExponentiator;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.modes.gcm.Tables1kGCMExponentiator;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implements the Galois/Counter mode (GCM) detailed in
 * NIST Special Publication 800-38D.
 */
public class GCMBlockCipher
    implements AEADBlockCipher
{
    private static final int BLOCK_SIZE = 16;

    // not final due to a compiler bug
    private BlockCipher   cipher;
    private GCMMultiplier multiplier;
    private GCMExponentiator exp;

    // These fields are set by init and not modified by processing
    private boolean             forEncryption;
    private boolean             initialised;
    private int                 macSize;
    private byte[]              lastKey;
    private byte[]              nonce;
    private byte[]              initialAssociatedText;
    private byte[]              H;
    private byte[]              J0;

    // These fields are modified during processing
    private byte[]      bufBlock;
    private byte[]      macBlock;
    private byte[]      S, S_at, S_atPre;
    private byte[]      counter;
    private int         blocksRemaining;
    private int         bufOff;
    private long        totalLength;
    private byte[]      atBlock;
    private int         atBlockPos;
    private long        atLength;
    private long        atLengthPre;

    public GCMBlockCipher(BlockCipher c)
    {
        this(c, null);
    }

    public GCMBlockCipher(BlockCipher c, GCMMultiplier m)
    {
        if (c.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException(
                "cipher required with a block size of " + BLOCK_SIZE + ".");
        }

        if (m == null)
        {
            // TODO Consider a static property specifying default multiplier
            m = new Tables8kGCMMultiplier();
        }

        this.cipher = c;
        this.multiplier = m;
    }

    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/GCM";
    }

    /**
     * NOTE: MAC sizes from 32 bits to 128 bits (must be a multiple of 8) are supported. The default is 128 bits.
     * Sizes less than 96 are not recommended, but are supported for specialized applications.
     */
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        this.macBlock = null;
        this.initialised = true;

        KeyParameter keyParam;
        byte[] newNonce = null;

        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            newNonce = param.getNonce();
            initialAssociatedText = param.getAssociatedText();

            int macSizeBits = param.getMacSize();
            if (macSizeBits < 32 || macSizeBits > 128 || macSizeBits % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits / 8;
            keyParam = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;

            newNonce = param.getIV();
            initialAssociatedText  = null;
            macSize = 16;
            keyParam = (KeyParameter)param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }

        int bufLength = forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize);
        this.bufBlock = new byte[bufLength];

        if (newNonce == null || newNonce.length < 1)
        {
            throw new IllegalArgumentException("IV must be at least 1 byte");
        }

        if (forEncryption)
        {
            if (nonce != null && Arrays.areEqual(nonce, newNonce))
            {
                if (keyParam == null)
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }
                if (lastKey != null && Arrays.areEqual(lastKey, keyParam.getKey()))
                {
                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
                }
            }
        }

        nonce = newNonce;
        if (keyParam != null)
        {
            lastKey = keyParam.getKey();
        }

        // TODO Restrict macSize to 16 if nonce length not 12?

        // Cipher always used in forward mode
        // if keyParam is null we're reusing the last key.
        if (keyParam != null)
        {
            cipher.init(true, keyParam);

            this.H = new byte[BLOCK_SIZE];
            cipher.processBlock(H, 0, H, 0);

            // GCMMultiplier tables don't change unless the key changes (and are expensive to init)
            multiplier.init(H);
            exp = null;
        }
        else if (this.H == null)
        {
            throw new IllegalArgumentException("Key must be specified in initial init");
        }

        this.J0 = new byte[BLOCK_SIZE];

        if (nonce.length == 12)
        {
            System.arraycopy(nonce, 0, J0, 0, nonce.length);
            this.J0[BLOCK_SIZE - 1] = 0x01;
        }
        else
        {
            gHASH(J0, nonce, nonce.length);
            byte[] X = new byte[BLOCK_SIZE];
            Pack.longToBigEndian((long)nonce.length * 8, X, 8);
            gHASHBlock(J0, X);
        }

        this.S = new byte[BLOCK_SIZE];
        this.S_at = new byte[BLOCK_SIZE];
        this.S_atPre = new byte[BLOCK_SIZE];
        this.atBlock = new byte[BLOCK_SIZE];
        this.atBlockPos = 0;
        this.atLength = 0;
        this.atLengthPre = 0;
        this.counter = Arrays.clone(J0);
        this.blocksRemaining = -2;      // page 8, len(P) <= 2^39 - 256, 1 block used by tag but done on J0
        this.bufOff = 0;
        this.totalLength = 0;

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    public byte[] getMac()
    {
        if (macBlock == null)
        {
            return new byte[macSize];
        }
        return Arrays.clone(macBlock);
    }

    public int getOutputSize(int len)
    {
        int totalData = len + bufOff;

        if (forEncryption)
        {
            return totalData + macSize;
        }

        return totalData < macSize ? 0 : totalData - macSize;
    }

    public int getUpdateOutputSize(int len)
    {
        int totalData = len + bufOff;
        if (!forEncryption)
        {
            if (totalData < macSize)
            {
                return 0;
            }
            totalData -= macSize;
        }
        return totalData - totalData % BLOCK_SIZE;
    }

    public void processAADByte(byte in)
    {
        checkStatus();
        atBlock[atBlockPos] = in;
        if (++atBlockPos == BLOCK_SIZE)
        {
            // Hash each block as it fills
            gHASHBlock(S_at, atBlock);
            atBlockPos = 0;
            atLength += BLOCK_SIZE;
        }
    }

    public void processAADBytes(byte[] in, int inOff, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            atBlock[atBlockPos] = in[inOff + i];
            if (++atBlockPos == BLOCK_SIZE)
            {
                // Hash each block as it fills
                gHASHBlock(S_at, atBlock);
                atBlockPos = 0;
                atLength += BLOCK_SIZE;
            }
        }
    }

    private void initCipher()
    {
        if (atLength > 0)
        {
            System.arraycopy(S_at, 0, S_atPre, 0, BLOCK_SIZE);
            atLengthPre = atLength;
        }

        // Finish hash for partial AAD block
        if (atBlockPos > 0)
        {
            gHASHPartial(S_atPre, atBlock, 0, atBlockPos);
            atLengthPre += atBlockPos;
        }

        if (atLengthPre > 0)
        {
            System.arraycopy(S_atPre, 0, S, 0, BLOCK_SIZE);
        }
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        checkStatus();
        
        bufBlock[bufOff] = in;
        if (++bufOff == bufBlock.length)
        {
            outputBlock(out, outOff);
            return BLOCK_SIZE;
        }
        return 0;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        checkStatus();

        if (in.length < (inOff + len))
        {
            throw new DataLengthException("Input buffer too short");
        }
        int resultLen = 0;

        for (int i = 0; i < len; ++i)
        {
            bufBlock[bufOff] = in[inOff + i];
            if (++bufOff == bufBlock.length)
            {
                outputBlock(out, outOff + resultLen);
                resultLen += BLOCK_SIZE;
            }
        }

        return resultLen;
    }

    private void outputBlock(byte[] output, int offset)
    {
        if (output.length < (offset + BLOCK_SIZE))
        {
            throw new OutputLengthException("Output buffer too short");
        }
        if (totalLength == 0)
        {
            initCipher();
        }
        gCTRBlock(bufBlock, output, offset);
        if (forEncryption)
        {
            bufOff = 0;
        }
        else
        {
            System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, macSize);
            bufOff = macSize;
        }
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        checkStatus();

        if (totalLength == 0)
        {
            initCipher();
        }

        int extra = bufOff;

        if (forEncryption)
        {
            if (out.length < (outOff + extra + macSize))
            {
                throw new OutputLengthException("Output buffer too short");
            }
        }
        else
        {
            if (extra < macSize)
            {
                throw new InvalidCipherTextException("data too short");
            }
            extra -= macSize;

            if (out.length < (outOff + extra))
            {
                throw new OutputLengthException("Output buffer too short");
            }
        }

        if (extra > 0)
        {
            gCTRPartial(bufBlock, 0, extra, out, outOff);
        }

        atLength += atBlockPos;

        if (atLength > atLengthPre)
        {
            /*
             *  Some AAD was sent after the cipher started. We determine the difference b/w the hash value
             *  we actually used when the cipher started (S_atPre) and the final hash value calculated (S_at).
             *  Then we carry this difference forward by multiplying by H^c, where c is the number of (full or
             *  partial) cipher-text blocks produced, and adjust the current hash.
             */

            // Finish hash for partial AAD block
            if (atBlockPos > 0)
            {
                gHASHPartial(S_at, atBlock, 0, atBlockPos);
            }

            // Find the difference between the AAD hashes
            if (atLengthPre > 0)
            {
                GCMUtil.xor(S_at, S_atPre);
            }

            // Number of cipher-text blocks produced
            long c = ((totalLength * 8) + 127) >>> 7;

            // Calculate the adjustment factor
            byte[] H_c = new byte[16];
            if (exp == null)
            {
                exp = new Tables1kGCMExponentiator();
                exp.init(H);
            }
            exp.exponentiateX(c, H_c);

            // Carry the difference forward
            GCMUtil.multiply(S_at, H_c);

            // Adjust the current hash
            GCMUtil.xor(S, S_at);
        }

        // Final gHASH
        byte[] X = new byte[BLOCK_SIZE];
        Pack.longToBigEndian(atLength * 8, X, 0);
        Pack.longToBigEndian(totalLength * 8, X, 8);

        gHASHBlock(S, X);

        // T = MSBt(GCTRk(J0,S))
        byte[] tag = new byte[BLOCK_SIZE];
        cipher.processBlock(J0, 0, tag, 0);
        GCMUtil.xor(tag, S);

        int resultLen = extra;

        // We place into macBlock our calculated value for T
        this.macBlock = new byte[macSize];
        System.arraycopy(tag, 0, macBlock, 0, macSize);

        if (forEncryption)
        {
            // Append T to the message
            System.arraycopy(macBlock, 0, out, outOff + bufOff, macSize);
            resultLen += macSize;
        }
        else
        {
            // Retrieve the T value from the message and compare to calculated one
            byte[] msgMac = new byte[macSize];
            System.arraycopy(bufBlock, extra, msgMac, 0, macSize);
            if (!Arrays.constantTimeAreEqual(this.macBlock, msgMac))
            {
                throw new InvalidCipherTextException("mac check in GCM failed");
            }
        }

        reset(false);

        return resultLen;
    }

    public void reset()
    {
        reset(true);
    }

    private void reset(
        boolean clearMac)
    {
        cipher.reset();

        // note: we do not reset the nonce.

        S = new byte[BLOCK_SIZE];
        S_at = new byte[BLOCK_SIZE];
        S_atPre = new byte[BLOCK_SIZE];
        atBlock = new byte[BLOCK_SIZE];
        atBlockPos = 0;
        atLength = 0;
        atLengthPre = 0;
        counter = Arrays.clone(J0);
        blocksRemaining = -2;
        bufOff = 0;
        totalLength = 0;

        if (bufBlock != null)
        {
            Arrays.fill(bufBlock, (byte)0);
        }

        if (clearMac)
        {
            macBlock = null;
        }

        if (forEncryption)
        {
            initialised = false;
        }
        else
        {
            if (initialAssociatedText != null)
            {
                processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
            }
        }
    }

    private void gCTRBlock(byte[] block, byte[] out, int outOff)
    {
        byte[] tmp = getNextCounterBlock();

        GCMUtil.xor(tmp, block);
        System.arraycopy(tmp, 0, out, outOff, BLOCK_SIZE);

        gHASHBlock(S, forEncryption ? tmp : block);

        totalLength += BLOCK_SIZE;
    }

    private void gCTRPartial(byte[] buf, int off, int len, byte[] out, int outOff)
    {
        byte[] tmp = getNextCounterBlock();

        GCMUtil.xor(tmp, buf, off, len);
        System.arraycopy(tmp, 0, out, outOff, len);

        gHASHPartial(S, forEncryption ? tmp : buf, 0, len);

        totalLength += len;
    }

    private void gHASH(byte[] Y, byte[] b, int len)
    {
        for (int pos = 0; pos < len; pos += BLOCK_SIZE)
        {
            int num = Math.min(len - pos, BLOCK_SIZE);
            gHASHPartial(Y, b, pos, num);
        }
    }

    private void gHASHBlock(byte[] Y, byte[] b)
    {
        GCMUtil.xor(Y, b);
        multiplier.multiplyH(Y);
    }

    private void gHASHPartial(byte[] Y, byte[] b, int off, int len)
    {
        GCMUtil.xor(Y, b, off, len);
        multiplier.multiplyH(Y);
    }

    private byte[] getNextCounterBlock()
    {
        if (blocksRemaining == 0)
        {
            throw new IllegalStateException("Attempt to process too many blocks");
        }
        blocksRemaining--;

        int c = 1;
        c += counter[15] & 0xFF; counter[15] = (byte)c; c >>>= 8;
        c += counter[14] & 0xFF; counter[14] = (byte)c; c >>>= 8;
        c += counter[13] & 0xFF; counter[13] = (byte)c; c >>>= 8;
        c += counter[12] & 0xFF; counter[12] = (byte)c;

        byte[] tmp = new byte[BLOCK_SIZE];
        // TODO Sure would be nice if ciphers could operate on int[]
        cipher.processBlock(counter, 0, tmp, 0);
        return tmp;
    }

    private void checkStatus()
    {
        if (!initialised)
        {
            if (forEncryption)
            {
                throw new IllegalStateException("GCM cipher cannot be reused for encryption");
            }
            throw new IllegalStateException("GCM cipher needs to be initialised");
        }
    }
}
