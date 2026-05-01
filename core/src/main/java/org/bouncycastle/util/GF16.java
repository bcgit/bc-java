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
     * Please ensure a &lt;= 0x0F and b &lt;= 0x0F
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
     * Please ensure a &lt;= 0x0F and b &lt;= 0x0F
     *
     * @param a an element in GF(16) (only the lower 4 bits are used)
     * @param b an element in GF(16) (only the lower 4 bits are used)
     * @return the product a * b in GF(16)
     */
    public static int mul(int a, int b)
    {
        return MT4B[a << 4 | b];
    }

    /**
     * Computes the multiplicative inverse in GF(16) for a GF(16) element.
     */
    public static byte inv(byte a)
    {
        return INV4B[a & 0xF];
//        int a2 = GF16.mul(a, a);
//        int a4 = GF16.mul(a2, a2);
//        int a8 = GF16.mul(a4, a4);
//        int a6 = GF16.mul(a2, a4);
//        return (byte)GF16.mul(a8, a6);
    }

    /**
     * Decodes an encoded byte array.
     * Each byte in the input contains two nibbles (4-bit values); the lower nibble is stored first,
     * followed by the upper nibble.
     *
     * @param input     the input byte array (each byte holds two 4-bit values)
     * @param output    the output array that will hold the decoded nibbles (one per byte)
     * @param outputLen the total number of nibbles to decode
     */
    public static void decode(byte[] input, byte[] output, int outputLen)
    {
        int i, decIndex = 0, blocks = outputLen >> 1;
        // Process pairs of nibbles from each byte
        for (i = 0; i < blocks; i++)
        {
            // Extract the lower nibble
            output[decIndex++] = (byte)(input[i] & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            output[decIndex++] = (byte)((input[i] >>> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if ((outputLen & 1) == 1)
        {
            output[decIndex] = (byte)(input[i] & 0x0F);
        }
    }

    public static void decode(byte[] input, int inOff, byte[] output, int outOff, int outputLen)
    {
        // Process pairs of nibbles from each byte
        int blocks = outputLen >> 1;
        for (int i = 0; i < blocks; i++)
        {
            // Extract the lower nibble
            output[outOff++] = (byte)(input[inOff] & 0x0F);
            // Extract the upper nibble (shift right 4 bits)
            output[outOff++] = (byte)((input[inOff++] >>> 4) & 0x0F);
        }
        // If there is an extra nibble (odd number of nibbles), decode only the lower nibble
        if ((outputLen & 1) == 1)
        {
            output[outOff] = (byte)(input[inOff] & 0x0F);
        }
    }

    /**
     * Encodes an array of 4-bit values into a byte array.
     * Two 4-bit values are packed into one byte, with the first nibble stored in the lower 4 bits
     * and the second nibble stored in the upper 4 bits.
     *
     * @param input    the input array of 4-bit values (stored as bytes, only lower 4 bits used)
     * @param output   the output byte array that will hold the encoded bytes
     * @param inputLen the number of nibbles in the input array
     */
    public static void encode(byte[] input, byte[] output, int inputLen)
    {
        int i, inOff = 0, blocks = inputLen >> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < blocks; i++)
        {
            int lowerNibble = input[inOff++] & 0x0F;
            int upperNibble = (input[inOff++] & 0x0F) << 4;
            output[i] = (byte)(lowerNibble | upperNibble);
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((inputLen & 1) == 1)
        {
            output[i] = (byte)(input[inOff] & 0x0F);
        }
    }

    public static void encode(byte[] input, byte[] output, int outOff, int inputLen)
    {
        int i, inOff = 0, blocks = inputLen >> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < blocks; i++)
        {
            int lowerNibble = input[inOff++] & 0x0F;
            int upperNibble = (input[inOff++] & 0x0F) << 4;
            output[outOff++] = (byte)(lowerNibble | upperNibble);
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((inputLen & 1) == 1)
        {
            output[outOff] = (byte)(input[inOff] & 0x0F);
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
}
