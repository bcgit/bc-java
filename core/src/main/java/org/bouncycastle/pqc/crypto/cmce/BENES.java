package org.bouncycastle.pqc.crypto.cmce;

abstract class BENES
{
    private static final long[] TRANSPOSE_MASKS = { 0x5555555555555555L, 0x3333333333333333L,
        0x0F0F0F0F0F0F0F0FL, 0x00FF00FF00FF00FFL, 0x0000FFFF0000FFFFL, 0x00000000FFFFFFFFL };

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
        transpose_64x64(out, in, 0);
    }

    static void transpose_64x64(long[] out, long[] in, int offset)
    {
        System.arraycopy(in, offset, out, offset, 64);

        int d = 5;
        do
        {
            long m = TRANSPOSE_MASKS[d];
            int s = 1 << d;
            for (int i = offset; i < offset + 64; i += s * 2)
            {
                for (int j = i; j < i + s; j += 4)
                {
//                    Bits.bitPermuteStep2(ref out[j + s + 0], ref out[j + 0], m, s);
//                    Bits.bitPermuteStep2(ref out[j + s + 1], ref out[j + 1], m, s);
//                    Bits.bitPermuteStep2(ref out[j + s + 2], ref out[j + 2], m, s);
//                    Bits.bitPermuteStep2(ref out[j + s + 3], ref out[j + 3], m, s);
                    long lo0 = out[j + 0];
                    long lo1 = out[j + 1];
                    long lo2 = out[j + 2];
                    long lo3 = out[j + 3];
                    long hi0 = out[j + s + 0];
                    long hi1 = out[j + s + 1];
                    long hi2 = out[j + s + 2];
                    long hi3 = out[j + s + 3];
                    long t0 = ((lo0 >>> s) ^ hi0) & m;
                    long t1 = ((lo1 >>> s) ^ hi1) & m;
                    long t2 = ((lo2 >>> s) ^ hi2) & m;
                    long t3 = ((lo3 >>> s) ^ hi3) & m;
                    out[j + 0] = lo0 ^ t0 << s;
                    out[j + 1] = lo1 ^ t1 << s;
                    out[j + 2] = lo2 ^ t2 << s;
                    out[j + 3] = lo3 ^ t3 << s;
                    out[j + s + 0] = hi0 ^ t0;
                    out[j + s + 1] = hi1 ^ t1;
                    out[j + s + 2] = hi2 ^ t2;
                    out[j + s + 3] = hi3 ^ t3;
                }
            }
        }
        while (--d >= 2);

        do
        {
            long m = TRANSPOSE_MASKS[d];
            int s = 1 << d;
            for (int i = offset; i < offset + 64; i += s * 2)
            {
                for (int j = i; j < i + s; ++j)
                {
//                    Bits.bitPermuteStep2(ref out[j + s], ref out[j], m, s);
                    long lo = out[j + 0];
                    long hi = out[j + s];
                    long t = ((lo >>> s) ^ hi) & m;
                    out[j + 0] = lo ^ t << s;
                    out[j + s] = hi ^ t;
                }
            }
        }
        while (--d >= 0);
    }

    abstract protected void support_gen(short[] s, byte[] c);
}
