package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier;
import org.bouncycastle.crypto.modes.kgcm.Tables16kKGCMMultiplier_512;
import org.bouncycastle.crypto.modes.kgcm.Tables4kKGCMMultiplier_128;
import org.bouncycastle.crypto.modes.kgcm.Tables8kKGCMMultiplier_256;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implementation of DSTU7624 GCM mode.
 * <p>
 * <b>Partial-block / interop caveat:</b> associated data and payload whose length is not a multiple
 * of the underlying block size are authenticated following the generic GCM/GMAC construction
 * (NIST SP 800-38D): the trailing partial block is zero-padded for the GF(2^n) multiplication, and
 * the true bit-length is bound by the trailing lambda field. DSTU 7624:2014 does not publish a
 * partial-block GCM/GMAC test vector, so this behaviour is verified by round-trip self-consistency
 * only and has <b>not</b> been confirmed against an independent conformant DSTU 7624 implementation.
 * See github #287.
 * </p>
 */
public class KGCMBlockCipher
    implements AEADBlockCipher
{
    private static final int MIN_MAC_BITS = 64;

    private static KGCMMultiplier createDefaultMultiplier(int blockSize)
    {
        switch (blockSize)
        {
        case 16:    return new Tables4kKGCMMultiplier_128();
        case 32:    return new Tables8kKGCMMultiplier_256();
        case 64:    return new Tables16kKGCMMultiplier_512();
        default:    throw new IllegalArgumentException("Only 128, 256, and 512 -bit block sizes supported");
        }
    }

    private BlockCipher engine;
    private BufferedBlockCipher ctrEngine;

    private int macSize;
    private boolean forEncryption;

    private byte[] initialAssociatedText;
    private byte[] macBlock;
    private byte[] nonce;
    private byte[] lastKey;

    private KGCMMultiplier multiplier;
    private long[] b;

    private final int blockSize;

    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();

    public KGCMBlockCipher(BlockCipher dstu7624Engine)
    {
        this.engine = dstu7624Engine;
        this.ctrEngine = new BufferedBlockCipher(new KCTRBlockCipher(this.engine));
        this.macSize = -1;
        this.blockSize = engine.getBlockSize();

        this.initialAssociatedText = new byte[blockSize];
        this.nonce = new byte[blockSize];
        this.multiplier = createDefaultMultiplier(blockSize);
        this.b = new long[blockSize >>> 3];

        this.macBlock = null;
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;

        KeyParameter keyParameter = null;
        byte[] newNonce;
        if (params instanceof AEADParameters)
        {
            AEADParameters aeadParameters = (AEADParameters)params;

            int macSizeInBits = aeadParameters.getMacSize();
            if (macSizeInBits < MIN_MAC_BITS || macSizeInBits > (blockSize << 3) || (macSizeInBits & 7) != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeInBits);
            }

            newNonce = aeadParameters.getNonce();
            initialAssociatedText = aeadParameters.getAssociatedText();
            macSize = macSizeInBits / 8;
            keyParameter = aeadParameters.getKey();

            if (initialAssociatedText != null)
            {
                processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
            }
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV withIV = (ParametersWithIV)params;

            newNonce = withIV.getIV();
            initialAssociatedText = null;
            macSize = blockSize; // Set default mac size

            CipherParameters innerParameters = withIV.getParameters();
            if (innerParameters != null)
            {
                if (!(innerParameters instanceof KeyParameter))
                {
                    throw new IllegalArgumentException("invalid parameters passed to KGCM");
                }

                keyParameter = (KeyParameter)innerParameters;
            }
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to KGCM");
        }

        // TODO Nonce length validation?
        if (newNonce.length < blockSize)
        {
            byte[] tmp = new byte[blockSize];
            System.arraycopy(newNonce, 0, tmp, blockSize - newNonce.length, newNonce.length);
            newNonce = tmp;
        }

        // Encrypting twice with the same key and nonce is catastrophic for any GCM-family mode
        // (it leaks the authentication key and the XOR of the plaintexts). Reject it on re-init,
        // mirroring GCMBlockCipher. reset()-based reuse is unaffected (it does not re-init).
        if (forEncryption)
        {
            // NOTE: Nonces compared _after_ zero-extension to blockSize
            if (nonce != null && Arrays.areEqual(nonce, newNonce))
            {
                if (keyParameter == null)
                {
                    throw new IllegalArgumentException("cannot reuse nonce for KGCM encryption");
                }
                if (lastKey != null && Arrays.constantTimeAreEqual(lastKey, keyParameter.getKey()))
                {
                    throw new IllegalArgumentException("cannot reuse nonce for KGCM encryption");
                }
            }
        }

        System.arraycopy(newNonce, 0, nonce, 0, blockSize);
        if (keyParameter != null)
        {
            lastKey = keyParameter.getKey();
        }

        this.macBlock = new byte[blockSize];
        ctrEngine.init(true, new ParametersWithIV(keyParameter, this.nonce));
        // TODO Surely it's redundant to init ctrEngine's inner BlockCipher??
        engine.init(true, keyParameter);
    }

    public String getAlgorithmName()
    {
        return engine.getAlgorithmName() + "/KGCM";
    }

    public BlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void processAADByte(byte in)
    {
        associatedText.write(in);
    }

    public void processAADBytes(byte[] in, int inOff, int len)
    {
        associatedText.write(in, inOff, len);
    }

    private void processAAD(byte[] authText, int authOff, int len)
    {
        int pos = authOff, end = authOff + len;
        while (end - pos >= blockSize)
        {
            xorWithInput(b, authText, pos);
            multiplier.multiplyH(b);
            pos += blockSize;
        }
        if (pos < end)
        {
            // trailing partial block: zero-pad to a full block (the message length is bound by the
            // lambda field in calculateMac, so the padding is unambiguous). See the interop caveat
            // in the class javadoc (github #287).
            xorPartialWithInput(b, authText, pos, end - pos);
            multiplier.multiplyH(b);
        }
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        data.write(in);

        return 0;
    }

    public int processBytes(byte[] in, int inOff, int inLen, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (in.length < (inOff + inLen))
        {
            throw new DataLengthException("input buffer too short");
        }

        data.write(in, inOff, inLen);

        return 0;
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        int len = data.size();
        if (!forEncryption && len < macSize)
        {
            throw new InvalidCipherTextException("data too short");
        }

        // TODO Total blocks restriction in GCM mode (extend limit naturally for larger block sizes?)

        // Set up the multiplier
        {
            byte[] temp = new byte[blockSize];
            engine.processBlock(temp, 0, temp, 0);
            long[] H = new long[blockSize >>> 3];
            Pack.littleEndianToLong(temp, 0, H);
            multiplier.init(H);
            Arrays.fill(temp, (byte)0);
            Arrays.fill(H, 0L);
        }

        int lenAAD = associatedText.size();
        if (lenAAD > 0)
        {
            processAAD(associatedText.getBuffer(), 0, lenAAD);
        }
        
        //use alternative cipher to produce output
        int resultLen;
        if (forEncryption)
        {
            if (out.length - outOff - macSize < len)
            {
                throw new OutputLengthException("Output buffer too short");
            }

            resultLen = ctrEngine.processBytes(data.getBuffer(), 0, len, out, outOff);
            resultLen += ctrEngine.doFinal(out, outOff + resultLen);

            calculateMac(out, outOff, len, lenAAD);

            if (macBlock == null)
            {
                throw new IllegalStateException("mac is not calculated");
            }

            System.arraycopy(macBlock, 0, out, outOff + resultLen, macSize);

            reset();

            return resultLen + macSize;
        }
        else
        {
            int ctLen = len - macSize;
            if (out.length - outOff < ctLen)
            {
                throw new OutputLengthException("Output buffer too short");
            }

            // KGCM authenticates the ciphertext, so verify the tag BEFORE decrypting: a forged
            // ciphertext is rejected without ever writing unverified CTR plaintext to the caller's
            // output buffer (matches CCMBlockCipher / GCMSIVBlockCipher).
            calculateMac(data.getBuffer(), 0, ctLen, lenAAD);

            if (macBlock == null)
            {
                throw new IllegalStateException("mac is not calculated");
            }

            byte[] mac = new byte[macSize];
            System.arraycopy(data.getBuffer(), len - macSize, mac, 0, macSize);

            byte[] calculatedMac = new byte[macSize];
            System.arraycopy(macBlock, 0, calculatedMac, 0, macSize);

            if (!Arrays.constantTimeAreEqual(mac, calculatedMac))
            {
                throw new InvalidCipherTextException("mac verification failed");
            }

            resultLen = ctrEngine.processBytes(data.getBuffer(), 0, ctLen, out, outOff);
            resultLen += ctrEngine.doFinal(out, outOff + resultLen);

            reset();

            return resultLen;
        }
    }

    public byte[] getMac()
    {
        byte[] mac = new byte[macSize];

        System.arraycopy(macBlock, 0, mac, 0, macSize);

        return mac;
    }

    public int getUpdateOutputSize(int len)
    {
        return 0;
    }

    public int getOutputSize(int len)
    {
        int totalData = len + data.size();

        if (forEncryption)
        {
            return totalData + macSize;
        }

        return totalData < macSize ? 0 : totalData - macSize;
    }

    public void reset()
    {
        Arrays.fill(b, 0L);

        engine.reset();

        data.reset();
        associatedText.reset();

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    private void calculateMac(byte[] input, int inOff, int len, int lenAAD)
    {
        int pos = inOff, end = inOff + len;
        while (end - pos >= blockSize)
        {
            xorWithInput(b, input, pos);
            multiplier.multiplyH(b);
            pos += blockSize;
        }
        if (pos < end)
        {
            // trailing partial block: zero-pad to a full block (length bound by lambda_c below).
            // See the interop caveat in the class javadoc (github #287).
            xorPartialWithInput(b, input, pos, end - pos);
            multiplier.multiplyH(b);
        }

        long lambda_o = (lenAAD & 0xFFFFFFFFL) << 3;
        long lambda_c = (len & 0xFFFFFFFFL) << 3;

//        byte[] temp = new byte[blockSize];
//        Pack.longToLittleEndian(lambda_o, temp, 0);
//        Pack.longToLittleEndian(lambda_c, temp, blockSize / 2);
//
//        xorWithInput(b, temp, 0);
        b[0] ^= lambda_o;
        b[blockSize >>> 4] ^= lambda_c;

        macBlock = Pack.longToLittleEndian(b);
        engine.processBlock(macBlock, 0, macBlock, 0);
    }

    private static void xorWithInput(long[] z, byte[] buf, int off)
    {
        for (int i = 0; i < z.length; ++i)
        {
            z[i] ^= Pack.littleEndianToLong(buf, off);
            off += 8;
        }
    }

    private void xorPartialWithInput(long[] z, byte[] buf, int off, int len)
    {
        // copy the trailing len (< blockSize) bytes into a zeroed full block so the read never
        // overruns the supplied buffer (which is not guaranteed zero past its valid length).
        byte[] block = new byte[blockSize];
        System.arraycopy(buf, off, block, 0, len);
        xorWithInput(z, block, 0);
    }

    private static class ExposedByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        ExposedByteArrayOutputStream()
        {
        }

        byte[] getBuffer()
        {
            return this.buf;
        }
    }
}
