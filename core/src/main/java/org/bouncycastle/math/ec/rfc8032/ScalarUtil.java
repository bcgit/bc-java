package org.bouncycastle.math.ec.rfc8032;

import org.bouncycastle.util.Integers;

abstract class ScalarUtil
{
    private static final long M = 0xFFFFFFFFL;

    static void addShifted_NP(int last, int s, int[] Nu, int[] Nv, int[] _p)
    {
        int sWords = s >>> 5, sBits = s & 31;

        long cc__p = 0L;
        long cc_Nu = 0L;

        if (sBits == 0)
        {
            for (int i = sWords; i <= last; ++i)
            {
                cc_Nu += Nu[i] & M;
                cc_Nu += _p[i - sWords] & M;

                cc__p += _p[i] & M;
                cc__p += Nv[i - sWords] & M;
                _p[i]  = (int)cc__p; cc__p >>>= 32;

                cc_Nu += _p[i - sWords] & M;
                Nu[i]  = (int)cc_Nu; cc_Nu >>>= 32;
            }
        }
        else
        {
            int prev_p = 0;
            int prev_q = 0;
            int prev_v = 0;

            for (int i = sWords; i <= last; ++i)
            {
                int next_p = _p[i - sWords];
                int p_s = (next_p << sBits) | (prev_p >>> -sBits);
                prev_p = next_p;

                cc_Nu += Nu[i] & M;
                cc_Nu += p_s & M;

                int next_v = Nv[i - sWords];
                int v_s = (next_v << sBits) | (prev_v >>> -sBits);
                prev_v = next_v;

                cc__p += _p[i] & M;
                cc__p += v_s & M;
                _p[i]  = (int)cc__p; cc__p >>>= 32;

                int next_q = _p[i - sWords];
                int q_s = (next_q << sBits) | (prev_q >>> -sBits);
                prev_q = next_q;

                cc_Nu += q_s & M;
                Nu[i]  = (int)cc_Nu; cc_Nu >>>= 32;
            }
        }
    }

    static void addShifted_UV(int last, int s, int[] u0, int[] u1, int[] v0, int[] v1)
    {
        int sWords = s >>> 5, sBits = s & 31;

        long cc_u0 = 0L;
        long cc_u1 = 0L;

        if (sBits == 0)
        {
            for (int i = sWords; i <= last; ++i)
            {
                cc_u0 += u0[i] & M;
                cc_u1 += u1[i] & M;
                cc_u0 += v0[i - sWords] & M;
                cc_u1 += v1[i - sWords] & M;
                u0[i]  = (int)cc_u0; cc_u0 >>>= 32;
                u1[i]  = (int)cc_u1; cc_u1 >>>= 32;
            }
        }
        else
        {
            int prev_v0 = 0;
            int prev_v1 = 0;

            for (int i = sWords; i <= last; ++i)
            {
                int next_v0 = v0[i - sWords];
                int next_v1 = v1[i - sWords];
                int v0_s = (next_v0 << sBits) | (prev_v0 >>> -sBits);
                int v1_s = (next_v1 << sBits) | (prev_v1 >>> -sBits);
                prev_v0 = next_v0;
                prev_v1 = next_v1;

                cc_u0 += u0[i] & M;
                cc_u1 += u1[i] & M;
                cc_u0 += v0_s & M;
                cc_u1 += v1_s & M;
                u0[i]  = (int)cc_u0; cc_u0 >>>= 32;
                u1[i]  = (int)cc_u1; cc_u1 >>>= 32;
            }
        }
    }

    static int getBitLength(int last, int[] x)
    {
        int i = last;
        int sign = x[i] >> 31;
        while (i > 0 && x[i] == sign)
        {
            --i;
        }
        return i * 32 + 32 - Integers.numberOfLeadingZeros(x[i] ^ sign);
    }

    static int getBitLengthPositive(int last, int[] x)
    {
        int i = last;
        while (i > 0 && x[i] == 0)
        {
            --i;
        }
        return i * 32 + 32 - Integers.numberOfLeadingZeros(x[i]);
    }

    static boolean lessThan(int last, int[] x, int[] y)
    {
        int i = last;
        do
        {
            int x_i = x[i] + Integer.MIN_VALUE;
            int y_i = y[i] + Integer.MIN_VALUE;
            if (x_i < y_i)
                return true;
            if (x_i > y_i)
                return false;
        }
        while (--i >= 0);
        return false;
    }

    static void subShifted_NP(int last, int s, int[] Nu, int[] Nv, int[] _p)
    {
        int sWords = s >>> 5, sBits = s & 31;

        long cc__p = 0L;
        long cc_Nu = 0L;

        if (sBits == 0)
        {
            for (int i = sWords; i <= last; ++i)
            {
                cc_Nu += Nu[i] & M;
                cc_Nu -= _p[i - sWords] & M;

                cc__p += _p[i] & M;
                cc__p -= Nv[i - sWords] & M;
                _p[i]  = (int)cc__p; cc__p >>= 32;

                cc_Nu -= _p[i - sWords] & M;
                Nu[i]  = (int)cc_Nu; cc_Nu >>= 32;
            }
        }
        else
        {
            int prev_p = 0;
            int prev_q = 0;
            int prev_v = 0;

            for (int i = sWords; i <= last; ++i)
            {
                int next_p = _p[i - sWords];
                int p_s = (next_p << sBits) | (prev_p >>> -sBits);
                prev_p = next_p;

                cc_Nu += Nu[i] & M;
                cc_Nu -= p_s & M;

                int next_v = Nv[i - sWords];
                int v_s = (next_v << sBits) | (prev_v >>> -sBits);
                prev_v = next_v;

                cc__p += _p[i] & M;
                cc__p -= v_s & M;
                _p[i]  = (int)cc__p; cc__p >>= 32;

                int next_q = _p[i - sWords];
                int q_s = (next_q << sBits) | (prev_q >>> -sBits);
                prev_q = next_q;

                cc_Nu -= q_s & M;
                Nu[i]  = (int)cc_Nu; cc_Nu >>= 32;
            }
        }
    }

    static void subShifted_UV(int last, int s, int[] u0, int[] u1, int[] v0, int[] v1)
    {
        int sWords = s >>> 5, sBits = s & 31;

        long cc_u0 = 0L;
        long cc_u1 = 0L;

        if (sBits == 0)
        {
            for (int i = sWords; i <= last; ++i)
            {
                cc_u0 += u0[i] & M;
                cc_u1 += u1[i] & M;
                cc_u0 -= v0[i - sWords] & M;
                cc_u1 -= v1[i - sWords] & M;
                u0[i]  = (int)cc_u0; cc_u0 >>= 32;
                u1[i]  = (int)cc_u1; cc_u1 >>= 32;
            }
        }
        else
        {
            int prev_v0 = 0;
            int prev_v1 = 0;

            for (int i = sWords; i <= last; ++i)
            {
                int next_v0 = v0[i - sWords];
                int next_v1 = v1[i - sWords];
                int v0_s = (next_v0 << sBits) | (prev_v0 >>> -sBits);
                int v1_s = (next_v1 << sBits) | (prev_v1 >>> -sBits);
                prev_v0 = next_v0;
                prev_v1 = next_v1;

                cc_u0 += u0[i] & M;
                cc_u1 += u1[i] & M;
                cc_u0 -= v0_s & M;
                cc_u1 -= v1_s & M;
                u0[i]  = (int)cc_u0; cc_u0 >>= 32;
                u1[i]  = (int)cc_u1; cc_u1 >>= 32;
            }
        }
    }
}
