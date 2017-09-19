package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
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

    private BlockCipher engine;
    private BufferedBlockCipher ctrEngine;

    private int macSize;
    private boolean forEncryption;

    private byte[] initialAssociatedText;
    private byte[] macBlock;
    private byte[] iv;

    private long[] H;
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
        this.H = new long[blockSize >>> 3];
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
        byte[] temp = new byte[blockSize];
        engine.processBlock(temp, 0, temp, 0);
        Pack.littleEndianToLong(temp, 0, H);
        Arrays.fill(temp, (byte)0);

        int pos = authOff, end = authOff + len;
        while (pos < end)
        {
            xorWithInput(b, authText, pos);
            multiplyH(b);
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
        Arrays.fill(H, 0L);
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
            multiplyH(b);
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

    /*
     * Multiplication over GF(2^m) field with corresponding extension polynomials
     *
     * GF (2 ^ 128) -> x^128 + x^7 + x^2 + x
     * GF (2 ^ 256) -> x^256 + x^10 + x^5 + x^2 + 1
     * GF (2 ^ 512) -> x^512 + x^8 + x^5 + x^2 + 1
     */
    private void multiplyH(long[] z)
    {
        switch (blockSize)
        {
        case 16:
        {
            long z0 = z[0], z1 = z[1];
            long r0 = 0, r1 = 0;

            for (int i = 0; i < 2; ++i)
            {
                long bits = H[i];
                for (int j = 0; j < 64; ++j)
                {
                    long m1 = -(bits & 1L); bits >>= 1;
                    r0 ^= (z0 & m1);
                    r1 ^= (z1 & m1);

                    long m2 = z1 >> 63;
                    z1 = (z1 << 1) | (z0 >>> 63);
                    z0 = (z0 << 1) ^ (m2 & 0x87L);
                }
            }

            z[0] = r0; z[1] = r1;
            break;
        }
        case 32:
        {
            long z0 = z[0], z1 = z[1], z2= z[2], z3 = z[3];
            long r0 = 0, r1 = 0, r2 = 0, r3 = 0;

            for (int i = 0; i < 4; ++i)
            {
                long bits = H[i];
                for (int j = 0; j < 64; ++j)
                {
                    long m1 = -(bits & 1L); bits >>= 1;
                    r0 ^= (z0 & m1);
                    r1 ^= (z1 & m1);
                    r2 ^= (z2 & m1);
                    r3 ^= (z3 & m1);

                    long m2 = z3 >> 63;
                    z3 = (z3 << 1) | (z2 >>> 63);
                    z2 = (z2 << 1) | (z1 >>> 63);
                    z1 = (z1 << 1) | (z0 >>> 63);
                    z0 = (z0 << 1) ^ (m2 & 0x425L);
                }
            }

            z[0] = r0; z[1] = r1; z[2] = r2; z[3] = r3;
            break;
        }
        case 64:
        {
            long z0 = z[0], z1 = z[1], z2= z[2], z3 = z[3];
            long z4 = z[4], z5 = z[5], z6= z[6], z7 = z[7];
            long r0 = 0, r1 = 0, r2 = 0, r3 = 0;
            long r4 = 0, r5 = 0, r6 = 0, r7 = 0;

            for (int i = 0; i < 8; ++i)
            {
                long bits = H[i];
                for (int j = 0; j < 64; ++j)
                {
                    long m1 = -(bits & 1L); bits >>= 1;
                    r0 ^= (z0 & m1);
                    r1 ^= (z1 & m1);
                    r2 ^= (z2 & m1);
                    r3 ^= (z3 & m1);
                    r4 ^= (z4 & m1);
                    r5 ^= (z5 & m1);
                    r6 ^= (z6 & m1);
                    r7 ^= (z7 & m1);

                    long m2 = z7 >> 63;
                    z7 = (z7 << 1) | (z6 >>> 63);
                    z6 = (z6 << 1) | (z5 >>> 63);
                    z5 = (z5 << 1) | (z4 >>> 63);
                    z4 = (z4 << 1) | (z3 >>> 63);
                    z3 = (z3 << 1) | (z2 >>> 63);
                    z2 = (z2 << 1) | (z1 >>> 63);
                    z1 = (z1 << 1) | (z0 >>> 63);
                    z0 = (z0 << 1) ^ (m2 & 0x125L);// 293L);
                }
            }

            z[0] = r0; z[1] = r1; z[2] = r2; z[3] = r3;
            z[4] = r4; z[5] = r5; z[6] = r6; z[7] = r7;
            break;
        }
        default:
        {
            throw new IllegalStateException("Only 128, 256, and 512 -bit block sizes supported");
        }
        }
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
