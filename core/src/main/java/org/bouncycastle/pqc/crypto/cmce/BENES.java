package org.bouncycastle.pqc.crypto.cmce;

abstract class BENES
{
    protected final int SYS_N;
    protected final int SYS_T;
    protected final int GFBITS;

    public BENES(int n, int t, int m)
    {
        SYS_N = n;
        SYS_T = t;
        GFBITS = m;
    }

    /* input: in, a 64x64 matrix over GF(2) */
    /* output: out, transpose of in */
    static void transpose_64x64(long[] out, long[] in)
    {
        int i, j, s, d;

        long x, y;
        long[][] masks = {
                {0x5555555555555555L, 0xAAAAAAAAAAAAAAAAL},
                {0x3333333333333333L, 0xCCCCCCCCCCCCCCCCL},
                {0x0F0F0F0F0F0F0F0FL, 0xF0F0F0F0F0F0F0F0L},
                {0x00FF00FF00FF00FFL, 0xFF00FF00FF00FF00L},
                {0x0000FFFF0000FFFFL, 0xFFFF0000FFFF0000L},
                {0x00000000FFFFFFFFL, 0xFFFFFFFF00000000L}
        };

        for (i = 0; i < 64; i++)
            out[i] = in[i];

        for (d = 5; d >= 0; d--)
        {
            s = 1 << d;
            for (i = 0; i < 64; i += s*2)
            {
                for (j = i; j < i+s; j++)
                {
                    x = (out[j] & masks[d][0]) | ((out[j+s] & masks[d][0]) << s);
                    y = ((out[j] & masks[d][1]) >>> s) | (out[j+s] & masks[d][1]);

                    out[j+0] = x;
                    out[j+s] = y;
                }
            }
        }

    }

    static void transpose_64x64(long[] out, long[] in, int offset)
    {
        int i, j, s, d;

        long x, y;
        long[][] masks = {
                {0x5555555555555555L, 0xAAAAAAAAAAAAAAAAL},
                {0x3333333333333333L, 0xCCCCCCCCCCCCCCCCL},
                {0x0F0F0F0F0F0F0F0FL, 0xF0F0F0F0F0F0F0F0L},
                {0x00FF00FF00FF00FFL, 0xFF00FF00FF00FF00L},
                {0x0000FFFF0000FFFFL, 0xFFFF0000FFFF0000L},
                {0x00000000FFFFFFFFL, 0xFFFFFFFF00000000L}
        };

        for (i = 0; i < 64; i++)
            out[i + offset] = in[i + offset];

        for (d = 5; d >= 0; d--)
        {
            s = 1 << d;
            for (i = 0; i < 64; i += s*2)
            {
                for (j = i; j < i+s; j++)
                {
                    x = (out[j+offset] & masks[d][0]) | ((out[j+s + offset] & masks[d][0]) << s);
                    y = ((out[j+offset] & masks[d][1]) >>> s) | (out[j+s + offset] & masks[d][1]);

                    out[j+0 + offset] = x;
                    out[j+s + offset] = y;
                }
            }
        }

    }


    abstract protected void support_gen(short[] s, byte[] c);



}
