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
                MT4B[(F_STAR[i]<<4) ^ F_STAR[j]] = F_STAR[(i + j) % 15];
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

    public static void convertBytesToGF16s(byte[] input, byte[] output, int gf16Count)
    {
        int pairs = gf16Count / 2;
        for (int i = 0; i < pairs; i++)
        {
            output[i * 2] = (byte)(input[i] & 0x0F);
            output[i * 2 + 1] = (byte)((input[i] >> 4) & 0x0F);
        }
        if (gf16Count % 2 == 1)
        {
            output[gf16Count - 1] = (byte)(input[pairs] & 0x0F);
        }
    }

    public static void convertGF16sToBytes(byte[] output, byte[] gf16s, int gf16Count)
    {
        int pairs = gf16Count / 2;
        for (int i = 0; i < pairs; i++)
        {
            output[i] = (byte)((gf16s[i * 2 + 1] << 4) | gf16s[i * 2]);
        }
        if (gf16Count % 2 == 1)
        {
            output[pairs] = gf16s[gf16Count - 1];
        }
    }

    static GF16Matrix[][][] create3DArray(int d1, int d2, int d3, int rank) {
        GF16Matrix[][][] arr = new GF16Matrix[d1][d2][d3];
        for (int i = 0; i < d1; i++) {
            for (int j = 0; j < d2; j++) {
                for (int k = 0; k < d3; k++) {
                    arr[i][j][k] = new GF16Matrix(rank);
                }
            }
        }
        return arr;
    }

    static GF16Matrix[][] create2DArray(int d1, int d2, int rank) {
        GF16Matrix[][] arr = new GF16Matrix[d1][d2];
        for (int i = 0; i < d1; i++) {
            for (int j = 0; j < d2; j++) {
                arr[i][j] = new GF16Matrix(rank);
            }
        }
        return arr;
    }

}