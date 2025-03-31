package org.bouncycastle.util;

public class GF16
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
     * GF(16) multiplication mod x^4 + x + 1.
     * <p>
     * This method multiplies two elements in GF(16) (represented as integers 0–15)
     * using carryless multiplication followed by reduction modulo x^4 + x + 1.
     * Please ensure a<=0x0F and b<=0x0F
     *
     * @param a an element in GF(16) (only the lower 4 bits are used)
     * @param b an element in GF(16) (only the lower 4 bits are used)
     * @return the product a * b in GF(16)
     */
    public static byte mul(byte a, byte b)
    {
        return MT4B[a << 4 | b];
    }

    /**
     * GF(16) multiplication mod x^4 + x + 1.
     * <p>
     * This method multiplies two elements in GF(16) (represented as integers 0–15)
     * using carryless multiplication followed by reduction modulo x^4 + x + 1.
     * Please ensure a<=0x0F and b<=0x0F
     *
     * @param a an element in GF(16) (only the lower 4 bits are used)
     * @param b an element in GF(16) (only the lower 4 bits are used)
     * @return the product a * b in GF(16)
     */
    public static int mul(int a, int b)
    {
        return MT4B[a << 4 | b];
    }

    public static byte inv(byte a)
    {
        return INV4B[a & 0xF];
    }

    /**
     * Decodes an encoded byte array.
     * Each byte in the input contains two nibbles (4-bit values); the lower nibble is stored first,
     * followed by the upper nibble.
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
            mdec[decIndex] = (byte)(m[i] & 0x0F);
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
     * Encodes an array of 4-bit values into a byte array.
     * Two 4-bit values are packed into one byte, with the first nibble stored in the lower 4 bits
     * and the second nibble stored in the upper 4 bits.
     *
     * @param m    the input array of 4-bit values (stored as bytes, only lower 4 bits used)
     * @param menc the output byte array that will hold the encoded bytes
     * @param mlen the number of nibbles in the input array
     */
    public static void encode(byte[] m, byte[] menc, int mlen)
    {
        int i, srcIndex = 0;
        // Process pairs of 4-bit values
        for (i = 0; i < mlen / 2; i++)
        {
            int lowerNibble = m[srcIndex] & 0x0F;
            int upperNibble = (m[srcIndex + 1] & 0x0F) << 4;
            menc[i] = (byte)(lowerNibble | upperNibble);
            srcIndex += 2;
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((mlen & 1) == 1)
        {
            menc[i] = (byte)(m[srcIndex] & 0x0F);
        }
    }

    public static byte innerProduct(byte[] a, int aOff, byte[] b, int bOff, int rank)
    {
        byte result = 0;
        for (int k = 0; k < rank; ++k, bOff += rank)
        {
            result ^= mul(a[aOff++], b[bOff]);
        }
        return result;
    }

    public static byte dotProduct(byte[] a, int aOff, byte[] b, int bOff, int rank)
    {
        byte result = 0;
        for (int k = 0; k < rank; ++k, aOff += rank, bOff += rank)
        {
            result ^= mul(a[aOff], b[bOff]);
        }
        return result;
    }
}
