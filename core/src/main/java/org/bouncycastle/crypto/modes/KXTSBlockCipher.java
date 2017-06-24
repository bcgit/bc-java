package org.bouncycastle.crypto.modes;

import java.math.BigInteger;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;


/**
 * Implementation of DSTU7624 XTS mode
 */
public class KXTSBlockCipher
    extends BufferedBlockCipher
{

    private static final int BITS_IN_BYTE = 8;

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

    private byte[] iv;
    private byte[] s;

    private byte[] alpha1;

    private byte[] buffer;
    private byte[] temp;

    private int counter;

    public KXTSBlockCipher(BlockCipher cipher)
    {
        this.buf = new byte[cipher.getBlockSize()];
        this.bufOff = 0;

        this.cipher = cipher;
        this.iv = new byte[cipher.getBlockSize()];
        this.s = new byte[cipher.getBlockSize()];
        this.buffer = new byte[cipher.getBlockSize()];

        this.alpha1 = new byte[cipher.getBlockSize()];
        alpha1[0] = 0x02; // Defined in standard
        this.temp = new byte[cipher.getBlockSize()];

        this.counter = 0;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters parameters)
    {
        if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            byte[] iv = ivParam.getIV();

            if (iv.length < this.iv.length)
            {
                System.arraycopy(iv, 0, this.iv, this.iv.length - iv.length, iv.length);
                for (int i = 0; i < this.iv.length - iv.length; i++)
                {
                    this.iv[i] = 0;
                }
            }
            else
            {
                System.arraycopy(iv, 0, this.iv, 0, this.iv.length);
            }

            parameters = ivParam.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameters passed");
        }


        cipher.init(true, parameters);

        cipher.processBlock(this.iv, 0, s, 0);

        cipher.init(forEncryption, parameters);
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
    {
        if (input.length - inOff < len)
        {
            throw new DataLengthException("Input buffer too short");
        }

        if (output.length - inOff < len)
        {
            throw new DataLengthException("Output buffer too short");
        }
        if (len % cipher.getBlockSize() != 0)
        {
            throw new IllegalArgumentException("Partial blocks not supported");
        }

        int totalLen = len;
        while (totalLen >= cipher.getBlockSize())
        {
            processBlock(input, inOff, output, outOff);

            totalLen -= cipher.getBlockSize();
            inOff += cipher.getBlockSize();
            outOff += cipher.getBlockSize();
        }

        return len;
    }

    private void processBlock(byte[] input, int inOff, byte[] output, int outOff)
    {
        counter++;

        powerOverField(cipher.getBlockSize() * BITS_IN_BYTE, alpha1, counter, temp);

        multiplyOverField(cipher.getBlockSize() * BITS_IN_BYTE, temp, s, buffer);

        buffer = Arrays.reverse(buffer);

        System.arraycopy(buffer, 0, temp, 0, cipher.getBlockSize());

        for (int byteIndex = 0; byteIndex < cipher.getBlockSize(); byteIndex++)
        {
            buffer[byteIndex] ^= input[inOff + byteIndex];
        }

        cipher.processBlock(buffer, 0, buffer, 0);

        for (int byteIndex = 0; byteIndex < cipher.getBlockSize(); byteIndex++)
        {
            output[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ temp[byteIndex]);
        }
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {

        reset();

        return 0;
    }

    @Override
    public void reset()
    {
        super.reset();

        Arrays.fill(buffer, (byte)0);
        Arrays.fill(temp, (byte)0);
        Arrays.fill(alpha1, (byte)0);
        alpha1[0] = 0x02; // Defined in standard

        counter = 0;
    }


    /*
    * Powering over GF(2 ^ blockBitLength) with corresponding extension polynomials
    *
    * GF (2 ^ 128) -> x^128 + x^7 + x^2 + x
    * GF (2 ^ 256) -> x^256 + x^10 + x^5 + x^2 + 1
    * GF (2 ^ 512) -> x^512 + x^8 + x^5 + x^2 + 1
    *
    * Thanks to João H de A Franco script.
    * https://jhafranco.com/2012/02/17/multiplication-over-the-binary-finite-field-gf2m/
    */
    private void powerOverField(int blockBitLength, byte[] x, int power, byte[] xPowered)
    {

        byte[] fieldOperationBuffer1 = new byte[cipher.getBlockSize()];
        byte[] fieldOperationBuffer2 = new byte[cipher.getBlockSize()];

        System.arraycopy(x, 0, fieldOperationBuffer1, 0, cipher.getBlockSize());
        System.arraycopy(x, 0, fieldOperationBuffer2, 0, cipher.getBlockSize());

        if (power == 1)
        {
            System.arraycopy(fieldOperationBuffer1, 0, xPowered, 0, cipher.getBlockSize());
            return;
        }

        for (int powerCounter = 0; powerCounter < power - 1; powerCounter++)
        {
            multiplyOverField(blockBitLength, fieldOperationBuffer1, fieldOperationBuffer2, xPowered);
            System.arraycopy(xPowered, 0, fieldOperationBuffer1, 0, cipher.getBlockSize());
        }
    }

    /* Multiplication over GF(2^m) field */
    private void multiplyOverField(int blockBitLength, byte[] x, byte[] y, byte[] x_mult_y)
    {

        byte[] fieldOperationBuffer1 = new byte[cipher.getBlockSize()];
        byte[] fieldOperationBuffer2 = new byte[cipher.getBlockSize()];

        System.arraycopy(x, 0, fieldOperationBuffer1, 0, cipher.getBlockSize());
        System.arraycopy(y, 0, fieldOperationBuffer2, 0, cipher.getBlockSize());

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


}
