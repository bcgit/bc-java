package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Implementation of DSTU7624 GCM mode
 */
public class KGCMBlockCipher
    implements AEADBlockCipher
{

    /* Constants for GF(2^m) operations */
    private static final BigInteger MASK_1_128 = new BigInteger("340282366920938463463374607431768211456", 10);
    private static final BigInteger MASK_2_128 = new BigInteger("340282366920938463463374607431768211455", 10);
    private static final BigInteger POLYRED_128 = new BigInteger("135", 10);

    private static final BigInteger MASK_1_256 = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639936", 10);
    private static final BigInteger MASK_2_256 = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10);
    private static final BigInteger POLYRED_256 = new BigInteger("1061", 10);

    private static final BigInteger MASK_1_512 = new BigInteger("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084096", 10);
    private static final BigInteger MASK_2_512 = new BigInteger("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084095", 10);
    private static final BigInteger POLYRED_512 = new BigInteger("293", 10);


    private static final int MIN_MAC_BITS = 64;
    private static final int BITS_IN_BYTE = 8;

    private BlockCipher engine;
    private BufferedBlockCipher ctrEngine;

    private int macSize;
    private boolean forEncryption;

    private byte[] initialAssociatedText;
    private byte[] macBlock;
    private byte[] iv;

    private byte[] H;
    private byte[] b;
    private byte[] temp;

    private int lambda_o;
    private int lambda_c;

    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();

    public KGCMBlockCipher(BlockCipher dstu7624Engine)
    {

        this.engine = dstu7624Engine;
        this.ctrEngine = new BufferedBlockCipher(new KCTRBlockCipher(this.engine));
        this.macSize = 0;

        this.initialAssociatedText = new byte[engine.getBlockSize()];
        this.iv = new byte[engine.getBlockSize()];
        this.H = new byte[engine.getBlockSize()];
        this.b = new byte[engine.getBlockSize()];
        this.temp = new byte[engine.getBlockSize()];

        this.lambda_c = 0;
        this.lambda_o = 0;

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
            if (macSizeBits < MIN_MAC_BITS || macSizeBits > engine.getBlockSize() * BITS_IN_BYTE || macSizeBits % BITS_IN_BYTE != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits / BITS_IN_BYTE;
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

            macSize = engine.getBlockSize(); // Set default mac size

            engineParam = (KeyParameter)param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameter passed");
        }

        this.macBlock = new byte[engine.getBlockSize()];
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
        lambda_o = len * BITS_IN_BYTE;

        engine.processBlock(H, 0, H, 0);

        int totalLength = len;
        int inOff_ = authOff;

        while (totalLength > 0)
        {
            for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
            {
                b[byteIndex] ^= authText[inOff_ + byteIndex];
            }

            multiplyOverField(engine.getBlockSize() * BITS_IN_BYTE, b, H, temp);

            temp = Arrays.reverse(temp);

            System.arraycopy(temp, 0, b, 0, engine.getBlockSize());

            totalLength -= engine.getBlockSize();

            inOff_ += engine.getBlockSize();
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

        if (associatedText.size() > 0)
        {
            processAAD(associatedText.getBuffer(), 0, associatedText.size());
        }
        
        //use alternative cipher to produce output
        int resultLen;
        if (forEncryption)
        {
            if (out.length - outOff < len + macSize)
            {
                throw new DataLengthException("Output buffer too short");
            }

            lambda_c = len * BITS_IN_BYTE;

            resultLen = ctrEngine.processBytes(data.getBuffer(), 0, len, out, outOff);
            resultLen += ctrEngine.doFinal(out, outOff + resultLen);

            calculateMac(out, outOff, len);
        }
        else
        {
            lambda_c = (len - macSize) * BITS_IN_BYTE;

            calculateMac(data.getBuffer(), 0, len - macSize);

            resultLen = ctrEngine.processBytes(data.getBuffer(), 0, len - macSize, out, outOff);
            resultLen += ctrEngine.doFinal(out, outOff + resultLen);
        }

        outOff += resultLen;
        
        if (macBlock == null)
        {
            throw new IllegalStateException("mac is not calculated");
        }

        if (forEncryption)
        {
            System.arraycopy(macBlock, 0, out, outOff, macSize);

            reset();

            return resultLen + macSize;
        }
        else
        {
            byte[] mac = new byte[macSize];
            System.arraycopy(data.getBuffer(), resultLen, mac, 0, macSize);

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
        return len;
    }

    public int getOutputSize(int len)
    {
        if (forEncryption)
        {
            return len;
        }
        else
        {
            return len + macSize;
        }
    }

    public void reset()
    {
        this.H = new byte[engine.getBlockSize()];
        this.b = new byte[engine.getBlockSize()];
        this.temp = new byte[engine.getBlockSize()];

        this.lambda_c = 0;
        this.lambda_o = 0;

        engine.reset();

        data.reset();
        associatedText.reset();

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }


    private void calculateMac(byte[] input, int inOff, int len)
    {
        macBlock = new byte[engine.getBlockSize()];

        int totalLength = len;
        int inOff_ = inOff;
        while (totalLength > 0)
        {
            for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
            {
                b[byteIndex] ^= input[byteIndex + inOff_];
            }

            multiplyOverField(engine.getBlockSize() * BITS_IN_BYTE, b, H, temp);

            temp = Arrays.reverse(temp);

            System.arraycopy(temp, 0, b, 0, engine.getBlockSize());

            totalLength -= engine.getBlockSize();
            inOff_ += engine.getBlockSize();
        }

        Arrays.fill(temp, (byte)0);

        intToBytes(lambda_o, temp, 0);
        intToBytes(lambda_c, temp, engine.getBlockSize() / 2);

        for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
        {
            b[byteIndex] ^= temp[byteIndex];
        }

        engine.processBlock(b, 0, macBlock, 0);
    }


    private void intToBytes(int num, byte[] outBytes, int outOff)
    {
        outBytes[outOff + 3] = (byte)(num >> 24);
        outBytes[outOff + 2] = (byte)(num >> 16);
        outBytes[outOff + 1] = (byte)(num >> 8);
        outBytes[outOff] = (byte)num;
    }

    /*
    * Multiplication over GF(2^m) field with corresponding extension polynomials
    *
    * GF (2 ^ 128) -> x^128 + x^7 + x^2 + x
    * GF (2 ^ 256) -> x^256 + x^10 + x^5 + x^2 + 1
    * GF (2 ^ 512) -> x^512 + x^8 + x^5 + x^2 + 1
    *
    * Thanks to João H de A Franco script.
    * https://jhafranco.com/2012/02/17/multiplication-over-the-binary-finite-field-gf2m/
    */
    private void multiplyOverField(int blockBitLength, byte[] x, byte[] y, byte[] x_mult_y)
    {
        byte[] fieldOperationBuffer1 = new byte[engine.getBlockSize()];
        byte[] fieldOperationBuffer2 = new byte[engine.getBlockSize()];

        System.arraycopy(x, 0, fieldOperationBuffer1, 0, engine.getBlockSize());
        System.arraycopy(y, 0, fieldOperationBuffer2, 0, engine.getBlockSize());

        fieldOperationBuffer1 = Arrays.reverse(fieldOperationBuffer1);
        fieldOperationBuffer2 = Arrays.reverse(fieldOperationBuffer2);


        BigInteger mask1;
        BigInteger mask2;
        BigInteger polyred;

        switch (blockBitLength)
        {
        case 128:
            mask1 = MASK_1_128;
            mask2 = MASK_2_128;
            polyred = POLYRED_128;
            break;
        case 256:
            mask1 = MASK_1_256;
            mask2 = MASK_2_256;
            polyred = POLYRED_256;
            break;
        case 512:
            mask1 = MASK_1_512;
            mask2 = MASK_2_512;
            polyred = POLYRED_512;
            break;
        default:
            mask1 = MASK_1_128;
            mask2 = MASK_2_128;
            polyred = POLYRED_128;
            break;
        }

        BigInteger p = BigInteger.ZERO;
        BigInteger p1 = new BigInteger(1, fieldOperationBuffer1);
        BigInteger p2 = new BigInteger(1, fieldOperationBuffer2);

        while (!p2.equals(BigInteger.ZERO))
        {
            if (p2.and(BigInteger.ONE).equals(BigInteger.ONE))
            {
                p = p.xor(p1);
            }

            p1 = p1.shiftLeft(1);

            if (!p1.and(mask1).equals(BigInteger.ZERO))
            {
                p1 = p1.xor(polyred);
            }
            p2 = p2.shiftRight(1);
        }

        byte[] got = BigIntegers.asUnsignedByteArray(p.and(mask2));

        Arrays.fill(x_mult_y, (byte)0);
        System.arraycopy(got, 0, x_mult_y, 0, got.length);
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
