package org.bouncycastle.pqc.crypto.snova;


public class GF16Utils
{
    private static final byte[] F_STAR = {1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9};
    private static final byte[] MT4B = new byte[256];
    private static final byte[] INV4B = new byte[16];

    static byte mt(int p, int q)
    {
        return MT4B[((p) << 4) ^ (q)];
    }

    static
    {

        // Initialize multiplication table
        for (int i = 0; i < 15; i++)
        {
            for (int j = 0; j < 15; j++)
            {
                MT4B[(F_STAR[i] << 4) ^ F_STAR[j]] = F_STAR[(i + j) % 15];
            }
        }

        int g = F_STAR[1], g_inv = F_STAR[14], gn = 1, gn_inv = 1;
        // Initialize inversion table
        INV4B[0] = 0;
        INV4B[1] = 1;
        for (int i = 0; i < 14; i++)
        {
            gn = mt(gn, g);
            gn_inv = mt(gn_inv, g_inv);
            INV4B[gn] = (byte)gn_inv;
        }
    }

    /**
     * Convert one byte of data to GF16 representation (using only half of the
     * byte). Example: <bytes 12 34 56 78 9a bc> -> <bytes 02 01 04 03 05 ..... 0c
     * 0b>
     *
     * @param m       the input byte array (each byte holds two 4-bit values)
     * @param mdec    the output array that will hold the decoded nibbles (one per byte)
     * @param mdecLen the total number of nibbles to decode
     */
    public static void decode(byte[] m, byte[] mdec, int mdecLen)
    {
        int i, decIndex = 0, blocks = mdecLen >> 1;
        // Process pairs of nibbles from each byte
        for (i = 0; i < blocks; i++)
        {
            // Extract the lower nibble
            mdec[decIndex++] = (byte)(m[i] & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            mdec[decIndex++] = (byte)((m[i] >> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if ((mdecLen & 1) == 1)
        {
            mdec[decIndex] = (byte)((m[i] & 0xFF) & 0x0F);
        }
    }

    public static void decode(byte[] m, int mOff, byte[] mdec, int decIndex, int mdecLen)
    {
        // Process pairs of nibbles from each byte
        int blocks = mdecLen >> 1;
        for (int i = 0; i < blocks; i++)
        {
            // Extract the lower nibble
            mdec[decIndex++] = (byte)(m[mOff] & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            mdec[decIndex++] = (byte)((m[mOff++] >> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if ((mdecLen & 1) == 1)
        {
            mdec[decIndex] = (byte)(m[mOff] & 0x0F);
        }
    }

    /**
     * Convert two GF16 values to one byte.
     *
     * @param m    the input array of 4-bit values (stored as bytes, only lower 4 bits used)
     * @param menc the output byte array that will hold the encoded bytes
     * @param mlen the number of nibbles in the input array
     */
    public static void encode(byte[] m, byte[] menc, int outOff, int mlen)
    {
        int i, srcIndex = 0;
        // Process pairs of 4-bit values
        for (i = 0; i < mlen / 2; i++)
        {
            int lowerNibble = m[srcIndex] & 0x0F;
            int upperNibble = (m[srcIndex + 1] & 0x0F) << 4;
            menc[outOff++] = (byte)(lowerNibble | upperNibble);
            srcIndex += 2;
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((mlen & 1) == 1)
        {
            menc[outOff] = (byte)(m[srcIndex] & 0x0F);
        }
    }

    public static void encodeMergeInHalf(byte[] m, int mlen, byte[] menc)
    {
        int i, half = (mlen + 1) >>> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < mlen / 2; i++, half++)
        {
            menc[i] = (byte)(m[i] | (m[half] << 4));
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((mlen & 1) == 1)
        {
            menc[i] = m[i];
        }
    }

    /**
     * Decodes a nibble-packed byte array into an output array.
     *
     * @param input       the input byte array.
     * @param inputOffset the offset in input from which to start decoding.
     * @param output      the output byte array to hold the decoded nibbles.
     * @param mdecLen     the total number of nibbles to decode.
     */
    public static void decode(byte[] input, int inputOffset, byte[] output, int mdecLen)
    {
        int decIndex = 0, blocks = mdecLen >> 1;
        for (int i = 0; i < blocks; i++)
        {
            output[decIndex++] = (byte)(input[inputOffset] & 0x0F);
            output[decIndex++] = (byte)((input[inputOffset++] >> 4) & 0x0F);
        }
        if ((mdecLen & 1) == 1)
        {
            output[decIndex] = (byte)(input[inputOffset] & 0x0F);
        }
    }

    public static void gf16mMul(byte[] a, byte[] b, byte[] c, int rank)
    {

        for (int i = 0; i < rank; i++)
        {
            for (int j = 0; j < rank; j++)
            {
                int cIndex = i * rank + j;
                c[cIndex] = mt(getGf16m(a, i, 0, rank), getGf16m(b, 0, j, rank));
                for (int k = 1; k < rank; ++k)
                {
                    c[cIndex] ^= mt(getGf16m(a, i, k, rank), getGf16m(b, k, j, rank));
                }
            }
        }
    }

    static byte getGf16m(byte[] gf16m, int x, int y, int rank)
    {
        return gf16m[x * rank + y];
    }

    /**
     * Conversion 4 bit -> 32 bit representation
     */
    public static int gf16FromNibble(int idx)
    {
        int middle = idx | (idx << 4);
        return ((middle & 0x41) | ((middle << 2) & 0x208));
    }

    public static void gf16mAdd(byte[] a, byte[] b, byte[] c, int rank)
    {

        for (int i = 0; i < rank; ++i)
        {
            for (int j = 0; j < rank; ++j)
            {
                int index = i * rank + j;
                // GF16 addition is XOR operation (equivalent to GF(2^4) addition)
                // Mask with 0x0F to ensure we only keep 4-bit values
                c[index] = (byte)((a[index] ^ b[index]) & 0x0F);
            }
        }
    }

    public static byte mul(byte a, byte b)
    {
        return MT4B[(a & 0xF) << 4 | (b & 0xF)];
    }

    public static byte add(byte a, byte b)
    {
        return (byte)((a ^ b) & 0xF);
    }

    public static byte inv(byte a)
    {
        return INV4B[a & 0xF];
    }

    static GF16Matrix[][][] create3DArray(int d1, int d2, int d3, int rank)
    {
        GF16Matrix[][][] arr = new GF16Matrix[d1][d2][d3];
        for (int i = 0; i < d1; i++)
        {
            for (int j = 0; j < d2; j++)
            {
                for (int k = 0; k < d3; k++)
                {
                    arr[i][j][k] = new GF16Matrix(rank);
                }
            }
        }
        return arr;
    }

    static GF16Matrix[][] create2DArray(int d1, int d2, int rank)
    {
        GF16Matrix[][] arr = new GF16Matrix[d1][d2];
        for (int i = 0; i < d1; i++)
        {
            for (int j = 0; j < d2; j++)
            {
                arr[i][j] = new GF16Matrix(rank);
            }
        }
        return arr;
    }

    private static final int GF16_MASK = 0x249; // Mask for GF(2^4) reduction

    // Constant-time GF16 != 0 check
    static int ctGF16IsNotZero(byte val)
    {
        int v = val & 0xFF;
        return (v | (v >>> 1) | (v >>> 2) | (v >>> 3)) & 1;
    }

    // GF16 reduction modulo x^4 + x + 1
    private static int gf16Reduce(int idx)
    {
        int res = idx & 0x49249249;
        int upper = idx >>> 12;
        res ^= upper ^ (upper << 3);
        upper = res >>> 12;
        res ^= upper ^ (upper << 3);
        upper = res >>> 12;
        res ^= upper ^ (upper << 3);
        return res & GF16_MASK;
    }

    // Convert 32-bit reduced value to 4-bit nibble
    static byte gf16ToNibble(int val)
    {
        int res = gf16Reduce(val);
        res |= res >>> 4;
        return (byte)((res & 0x5) | ((res >>> 2) & 0xA));
    }
}