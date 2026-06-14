package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implementation of GOST 3412 2015 (aka "Kuznyechik") RFC 7801, GOST 3412
 */
public class GOST3412_2015Engine
    implements BlockCipher
{

    private static final byte[] PI = new byte[]
        {
            -4, -18, -35, 17, -49, 110, 49, 22, -5, -60, -6, -38, 35, -59, 4, 77, -23, 119, -16, -37, -109, 46, -103, -70,
            23, 54, -15, -69, 20, -51, 95, -63, -7, 24, 101, 90, -30, 92, -17, 33, -127, 28, 60, 66, -117, 1, -114, 79, 5,
            -124, 2, -82, -29, 106, -113, -96, 6, 11, -19, -104, 127, -44, -45, 31, -21, 52, 44, 81, -22, -56, 72, -85, -14,
            42, 104, -94, -3, 58, -50, -52, -75, 112, 14, 86, 8, 12, 118, 18, -65, 114, 19, 71, -100, -73, 93, -121, 21,
            -95, -106, 41, 16, 123, -102, -57, -13, -111, 120, 111, -99, -98, -78, -79, 50, 117, 25, 61, -1, 53, -118, 126,
            109, 84, -58, -128, -61, -67, 13, 87, -33, -11, 36, -87, 62, -88, 67, -55, -41, 121, -42, -10, 124, 34, -71,
            3, -32, 15, -20, -34, 122, -108, -80, -68, -36, -24, 40, 80, 78, 51, 10, 74, -89, -105, 96, 115, 30, 0, 98, 68,
            26, -72, 56, -126, 100, -97, 38, 65, -83, 69, 70, -110, 39, 94, 85, 47, -116, -93, -91, 125, 105, -43, -107,
            59, 7, 88, -77, 64, -122, -84, 29, -9, 48, 55, 107, -28, -120, -39, -25, -119, -31, 27, -125, 73, 76, 63, -8,
            -2, -115, 83, -86, -112, -54, -40, -123, 97, 32, 113, 103, -92, 45, 43, 9, 91, -53, -101, 37, -48, -66, -27,
            108, 82, 89, -90, 116, -46, -26, -12, -76, -64, -47, 102, -81, -62, 57, 75, 99, -74
        };


    private static final byte[] inversePI = new byte[]{
        -91, 45, 50, -113, 14, 48, 56, -64, 84, -26, -98, 57, 85, 126, 82, -111, 100, 3, 87, 90, 28, 96, 7, 24, 33, 114,
        -88, -47, 41, -58, -92, 63, -32, 39, -115, 12, -126, -22, -82, -76, -102, 99, 73, -27, 66, -28, 21, -73, -56, 6,
        112, -99, 65, 117, 25, -55, -86, -4, 77, -65, 42, 115, -124, -43, -61, -81, 43, -122, -89, -79, -78, 91, 70, -45,
        -97, -3, -44, 15, -100, 47, -101, 67, -17, -39, 121, -74, 83, 127, -63, -16, 35, -25, 37, 94, -75, 30, -94, -33,
        -90, -2, -84, 34, -7, -30, 74, -68, 53, -54, -18, 120, 5, 107, 81, -31, 89, -93, -14, 113, 86, 17, 106, -119,
        -108, 101, -116, -69, 119, 60, 123, 40, -85, -46, 49, -34, -60, 95, -52, -49, 118, 44, -72, -40, 46, 54, -37,
        105, -77, 20, -107, -66, 98, -95, 59, 22, 102, -23, 92, 108, 109, -83, 55, 97, 75, -71, -29, -70, -15, -96, -123,
        -125, -38, 71, -59, -80, 51, -6, -106, 111, 110, -62, -10, 80, -1, 93, -87, -114, 23, 27, -105, 125, -20, 88, -9,
        31, -5, 124, 9, 13, 122, 103, 69, -121, -36, -24, 79, 29, 78, 4, -21, -8, -13, 62, 61, -67, -118, -120, -35, -51,
        11, 19, -104, 2, -109, -128, -112, -48, 36, 52, -53, -19, -12, -50, -103, 16, 68, 64, -110, 58, 1, 38, 18, 26,
        72, 104, -11, -127, -117, -57, -42, 32, 10, 8, 0, 76, -41, 116
    };


    private static final byte[] lFactors = {
        -108, 32, -123, 16, -62, -64, 1, -5, 1, -64, -62, 16, -123, 32, -108, 1
    };

    /*
     * Precomputed lookup tables for the linear transform L (and its inverse) of
     * GOST 34.12-2015. L is the LFSR R applied 16 times; since L is GF(2^8)-linear
     * over the 16-byte block, L(data) = XOR_i LT[i][data[i]], where LT[i][v] is L
     * applied to the block holding v at position i and 0 elsewhere. Each 16-byte
     * row is held as two longs (bytes 0-7 / 8-15, big-endian). The tables are
     * generated from the original R^16 / inverseR^16 over the GF(2^8) multiply
     * table, so the result is byte-identical to the per-byte LFSR implementation
     * while replacing ~256 table lookups + 16 register shifts per L with 16
     * row-XORs. This is information-equivalent to the existing S-box / GF-multiply
     * lookups (indexed by the same secret block bytes), so it does not change the
     * engine's cache constant-time posture.
     */
    private static final long[][] forwardT0 = new long[16][256];
    private static final long[][] forwardT1 = new long[16][256];
    private static final long[][] inverseT0 = new long[16][256];
    private static final long[][] inverseT1 = new long[16][256];

    /*
     * LS tables fold the S-box into the linear transform (LSX round = X then L(S(.))).
     * Since the S-box is applied before the (linear) L, L(S(x)) = XOR_i LST[i][x[i]]
     * with LST[i][v] = L(S(v) at position i) = forwardT[i][PI[v]]; likewise for the
     * equivalent inverse round invL(invS(.)) the LFSR-and-substitution fold is
     * inverseLST[i][v] = inverseT[i][inversePI[v]]. Indexed by the same secret block
     * bytes the S-box already indexes, so still information-equivalent / CT-neutral.
     */
    private static final long[][] forwardLST0 = new long[16][256];
    private static final long[][] forwardLST1 = new long[16][256];
    private static final long[][] inverseLST0 = new long[16][256];
    private static final long[][] inverseLST1 = new long[16][256];

    static
    {
        byte[][] gfMul = init_gf256_mul_table();
        for (int i = 0; i < 16; i++)
        {
            for (int v = 1; v < 256; v++)
            {
                byte[] block = new byte[16];
                block[i] = (byte)v;
                for (int r = 0; r < 16; r++)
                {
                    rSlow(block, gfMul);
                }
                forwardT0[i][v] = Pack.bigEndianToLong(block, 0);
                forwardT1[i][v] = Pack.bigEndianToLong(block, 8);

                byte[] iblock = new byte[16];
                iblock[i] = (byte)v;
                for (int r = 0; r < 16; r++)
                {
                    inverseRSlow(iblock, gfMul);
                }
                inverseT0[i][v] = Pack.bigEndianToLong(iblock, 0);
                inverseT1[i][v] = Pack.bigEndianToLong(iblock, 8);
            }
        }
        for (int i = 0; i < 16; i++)
        {
            for (int v = 0; v < 256; v++)
            {
                forwardLST0[i][v] = forwardT0[i][PI[v] & 0xFF];
                forwardLST1[i][v] = forwardT1[i][PI[v] & 0xFF];
                inverseLST0[i][v] = inverseT0[i][inversePI[v] & 0xFF];
                inverseLST1[i][v] = inverseT1[i][inversePI[v] & 0xFF];
            }
        }
    }

    protected static final int BLOCK_SIZE = 16;
    private int KEY_LENGTH = 32;
    private int SUB_LENGTH = KEY_LENGTH / 2;
    private byte[][] subKeys = null;
    private byte[][] invSubKeys = null;
    private boolean forEncryption;


    private static byte[][] init_gf256_mul_table()
    {
        byte[][] mul_table = new byte[256][];
        for (int x = 0; x < 256; x++)
        {
            mul_table[x] = new byte[256];
            for (int y = 0; y < 256; y++)
            {
                mul_table[x][y] = kuz_mul_gf256_slow((byte)x, (byte)y);
            }
        }
        return mul_table;
    }

    private static byte kuz_mul_gf256_slow(byte a, byte b)
    {
        byte p = 0;
        byte counter;
        byte hi_bit_set;
        for (counter = 0; counter < 8 && a != 0 && b != 0; counter++)
        {
            if ((b & 1) != 0)
            {
                p ^= a;
            }
            hi_bit_set = (byte)(a & 0x80);
            a <<= 1;
            if (hi_bit_set != 0)
            {
                a ^= 0xc3; /* x^8 + x^7 + x^6 + x + 1 */
            }
            b >>= 1;
        }
        return p;
    }

    public String getAlgorithmName()
    {
        return "GOST3412_2015";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {

        if (params instanceof KeyParameter)
        {
            this.forEncryption = forEncryption;
            generateSubKeys(((KeyParameter)params).getKey());
        }
        else if (params != null)
        {
            throw new IllegalArgumentException("invalid parameter passed to GOST3412_2015 init - " + params.getClass().getName());
        }
    }

    private void generateSubKeys(
        byte[] userKey)
    {

        if (userKey.length != KEY_LENGTH)
        {
            throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }

        subKeys = new byte[10][];
        for (int i = 0; i < 10; i++)
        {
            subKeys[i] = new byte[SUB_LENGTH];
        }

        byte[] x = new byte[SUB_LENGTH];
        byte[] y = new byte[SUB_LENGTH];


        for (int i = 0; i < SUB_LENGTH; i++)
        {
            subKeys[0][i] = x[i] = userKey[i];
            subKeys[1][i] = y[i] = userKey[i + SUB_LENGTH];
        }

        byte[] c = new byte[SUB_LENGTH];

        for (int k = 1; k < 5; k++)
        {

            for (int j = 1; j <= 8; j++)
            {
                C(c, 8 * (k - 1) + j);
                F(c, x, y);
            }

            System.arraycopy(x, 0, subKeys[2 * k], 0, SUB_LENGTH);
            System.arraycopy(y, 0, subKeys[2 * k + 1], 0, SUB_LENGTH);
        }

        // For the equivalent-decryption round (which applies the inverse S-box
        // before the inverse linear transform) the inner round keys are pushed
        // through inverseL once, at key-schedule time.
        invSubKeys = new byte[9][];
        for (int i = 1; i <= 8; i++)
        {
            byte[] ik = Arrays.clone(subKeys[i]);
            inverseL(ik);
            invSubKeys[i] = ik;
        }
    }


    private void C(byte[] c, int i)
    {

        Arrays.clear(c);
        c[15] = (byte)i;
        L(c);
    }


    private void F(byte[] k, byte[] a1, byte[] a0)
    {

        byte[] temp = LSX(k, a1);
        X(temp, a0);

        System.arraycopy(a1, 0, a0, 0, SUB_LENGTH);
        System.arraycopy(temp, 0, a1, 0, SUB_LENGTH);

    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

        if (subKeys == null)
        {
            throw new IllegalStateException("GOST3412_2015 engine not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        GOST3412_2015Func(in, inOff, out, outOff);

        return BLOCK_SIZE;
    }


    private void GOST3412_2015Func(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {

        byte[] block = new byte[BLOCK_SIZE];
        System.arraycopy(in, inOff, block, 0, BLOCK_SIZE);

        if (forEncryption)
        {
            for (int i = 0; i < 9; i++)
            {
                X(block, subKeys[i]);
                LS(block);
            }

            X(block, subKeys[9]);
        }
        else
        {
            // Equivalent decryption: w = invL(C ^ K9); for i=8..1: w = invLS(w) ^ invL(Ki);
            // P = invS(w) ^ K0. invLS folds inverseS into the inverse linear tables, and the
            // inner round keys are pre-transformed (invSubKeys[i] = inverseL(Ki)).
            X(block, subKeys[9]);
            inverseL(block);
            for (int i = 8; i >= 1; i--)
            {
                inverseLS(block);
                X(block, invSubKeys[i]);
            }
            inverseS(block);
            X(block, subKeys[0]);
        }


        System.arraycopy(block, 0, out, outOff, BLOCK_SIZE);
    }

    private byte[] LSX(byte[] k, byte[] a)
    {

        byte[] result = Arrays.copyOf(k, k.length);
        X(result, a);
        S(result);
        L(result);
        return result;
    }

    private void X(byte[] result, byte[] data)
    {
        for (int i = 0; i < result.length; i++)
        {
            result[i] ^= data[i];
        }
    }

    private void S(byte[] data)
    {
        for (int i = 0; i < data.length; i++)
        {
            data[i] = PI[unsignedByte(data[i])];
        }
    }

    private void inverseS(byte[] data)
    {
        for (int i = 0; i < data.length; i++)
        {
            data[i] = inversePI[unsignedByte(data[i])];
        }
    }

    private int unsignedByte(byte b)
    {
        return b & 0xFF;
    }

    private void L(byte[] data)
    {
        long r0 = 0;
        long r1 = 0;
        for (int i = 0; i < 16; i++)
        {
            int v = data[i] & 0xFF;
            r0 ^= forwardT0[i][v];
            r1 ^= forwardT1[i][v];
        }
        Pack.longToBigEndian(r0, data, 0);
        Pack.longToBigEndian(r1, data, 8);
    }

    private void inverseL(byte[] data)
    {
        long r0 = 0;
        long r1 = 0;
        for (int i = 0; i < 16; i++)
        {
            int v = data[i] & 0xFF;
            r0 ^= inverseT0[i][v];
            r1 ^= inverseT1[i][v];
        }
        Pack.longToBigEndian(r0, data, 0);
        Pack.longToBigEndian(r1, data, 8);
    }

    private void LS(byte[] data)
    {
        long r0 = 0;
        long r1 = 0;
        for (int i = 0; i < 16; i++)
        {
            int v = data[i] & 0xFF;
            r0 ^= forwardLST0[i][v];
            r1 ^= forwardLST1[i][v];
        }
        Pack.longToBigEndian(r0, data, 0);
        Pack.longToBigEndian(r1, data, 8);
    }

    private void inverseLS(byte[] data)
    {
        long r0 = 0;
        long r1 = 0;
        for (int i = 0; i < 16; i++)
        {
            int v = data[i] & 0xFF;
            r0 ^= inverseLST0[i][v];
            r1 ^= inverseLST1[i][v];
        }
        Pack.longToBigEndian(r0, data, 0);
        Pack.longToBigEndian(r1, data, 8);
    }


    /*
     * Build-time helpers (used only to populate the static L tables): the original
     * per-byte LFSR step R, its inverse, and the linear functional l over the
     * GF(2^8) multiply table. Driving R^16 / inverseR^16 over the unit vectors is
     * what makes the precomputed tables byte-identical to the old implementation.
     */
    private static byte lSlow(byte[] data, byte[][] gfMul)
    {
        byte x = data[15];
        for (int i = 14; i >= 0; i--)
        {
            x ^= gfMul[data[i] & 0xFF][lFactors[i] & 0xFF];
        }
        return x;
    }

    private static void rSlow(byte[] data, byte[][] gfMul)
    {
        byte z = lSlow(data, gfMul);
        System.arraycopy(data, 0, data, 1, 15);
        data[0] = z;
    }

    private static void inverseRSlow(byte[] data, byte[][] gfMul)
    {
        byte[] temp = new byte[16];
        System.arraycopy(data, 1, temp, 0, 15);
        temp[15] = data[0];
        byte z = lSlow(temp, gfMul);
        System.arraycopy(data, 1, data, 0, 15);
        data[15] = z;
    }

    public void reset()
    {

    }
}
