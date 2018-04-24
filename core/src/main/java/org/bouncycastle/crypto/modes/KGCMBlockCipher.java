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
 * Implementation of DSTU7624 GCM mode
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
    private byte[] iv;

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
        this.iv = new byte[blockSize];
        this.multiplier = createDefaultMultiplier(blockSize);
        this.b = new long[blockSize >>> 3];

        this.macBlock = null;
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;

        KeyParameter engineParam;
        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            byte[] iv = param.getNonce();
            int diff = this.iv.length - iv.length;
            Arrays.fill(this.iv, (byte)0);
            System.arraycopy(iv, 0, this.iv, diff, iv.length);

            initialAssociatedText = param.getAssociatedText();

            int macSizeBits = param.getMacSize();
            if (macSizeBits < MIN_MAC_BITS || macSizeBits > (blockSize << 3) || (macSizeBits & 7) != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits >>> 3;
            engineParam = param.getKey();

            if (initialAssociatedText != null)
            {
                processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
            }
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;

            byte[] iv = param.getIV();
            int diff = this.iv.length - iv.length;
            Arrays.fill(this.iv, (byte)0);
            System.arraycopy(iv, 0, this.iv, diff, iv.length);

            initialAssociatedText = null;

            macSize = blockSize; // Set default mac size

            engineParam = (KeyParameter)param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameter passed");
        }

        // TODO Nonce re-use check (sample code from GCMBlockCipher)
//        if (forEncryption)
//        {
//            if (nonce != null && Arrays.areEqual(nonce, newNonce))
//            {
//                if (keyParam == null)
//                {
//                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
//                }
//                if (lastKey != null && Arrays.areEqual(lastKey, keyParam.getKey()))
//                {
//                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
//                }
//            }
//        }

        this.macBlock = new byte[blockSize];
        ctrEngine.init(true, new ParametersWithIV(engineParam, this.iv));
        engine.init(true, engineParam);
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
        while (pos < end)
        {
            xorWithInput(b, authText, pos);
            multiplier.multiplyH(b);
            pos += blockSize;
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
        }
        else
        {
            int ctLen = len - macSize; 
            if (out.length - outOff < ctLen)
            {
                throw new OutputLengthException("Output buffer too short");
            }

            calculateMac(data.getBuffer(), 0, ctLen, lenAAD);

            resultLen = ctrEngine.processBytes(data.getBuffer(), 0, ctLen, out, outOff);
            resultLen += ctrEngine.doFinal(out, outOff + resultLen);
        }

        if (macBlock == null)
        {
            throw new IllegalStateException("mac is not calculated");
        }

        if (forEncryption)
        {
            System.arraycopy(macBlock, 0, out, outOff + resultLen, macSize);

            reset();

            return resultLen + macSize;
        }
        else
        {
            byte[] mac = new byte[macSize];
            System.arraycopy(data.getBuffer(), len - macSize, mac, 0, macSize);

            byte[] calculatedMac = new byte[macSize];
            System.arraycopy(macBlock, 0, calculatedMac, 0, macSize);

            if (!Arrays.constantTimeAreEqual(mac, calculatedMac))
            {
                throw new InvalidCipherTextException("mac verification failed");
            }

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
        while (pos < end)
        {
            xorWithInput(b, input, pos);
            multiplier.multiplyH(b);
            pos += blockSize;
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

    private class ExposedByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        public ExposedByteArrayOutputStream()
        {
        }

        public byte[] getBuffer()
        {
            return this.buf;
        }
    }
}
