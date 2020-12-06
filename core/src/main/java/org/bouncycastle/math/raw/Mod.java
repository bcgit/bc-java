package org.bouncycastle.math.raw;

import java.util.Random;

import org.bouncycastle.util.Integers;

/*
 * Modular inversion as implemented in this class is based on the paper "Fast constant-time gcd
 * computation and modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
 */

public abstract class Mod
{
    private static final int M30 = 0x3FFFFFFF;
    private static final long M32L = 0xFFFFFFFFL;

    /** @deprecated Will be removed. */
    public static void add(int[] p, int[] x, int[] y, int[] z)
    {
        int len = p.length;
        int c = Nat.add(len, x, y, z);
        if (c != 0)
        {
            Nat.subFrom(len, p, z);
        }
    }

    public static void checkedModOddInverse(int[] m, int[] x, int[] z)
    {
        if (0 == modOddInverse(m, x, z))
        {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static void checkedModOddInverseVar(int[] m, int[] x, int[] z)
    {
        if (!modOddInverseVar(m, x, z))
        {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static int inverse32(int d)
    {
//        assert (d & 1) == 1;
//        int x = d + (((d + 1) & 4) << 1);   // d.x == 1 mod 2**4
        int x = d;                          // d.x == 1 mod 2**3
        x *= 2 - d * x;                     // d.x == 1 mod 2**6
        x *= 2 - d * x;                     // d.x == 1 mod 2**12
        x *= 2 - d * x;                     // d.x == 1 mod 2**24
        x *= 2 - d * x;                     // d.x == 1 mod 2**48
//        assert d * x == 1;
        return  x;
    }

    /** @deprecated Use {@link #checkedModOddInverseVar(int[], int[], int[])} instead. */
    public static void invert(int[] m, int[] x, int[] z)
    {
        checkedModOddInverseVar(m,  x,  z);
    }

    public static int modOddInverse(int[] m, int[] x, int[] z)
    {
        int len32 = m.length;
//        assert len32 > 0;
//        assert (m[0] & 1) != 0;
//        assert m[len32 - 1] != 0;

        int bits = (len32 << 5) - Integers.numberOfLeadingZeros(m[len32 - 1]);
        int len30 = (bits + 29) / 30;

        int[] t = new int[4];
        int[] D = new int[len30];
        int[] E = new int[len30];
        int[] F = new int[len30];
        int[] G = new int[len30];
        int[] M = new int[len30];

        E[0] = 1;
        encode30(bits, x, 0, G, 0);
        encode30(bits, m, 0, M, 0);
        System.arraycopy(M, 0, F, 0, len30);

        int eta = -1;
        int m0Inv32 = inverse32(M[0]);
        int maxDivsteps = getMaximumDivsteps(bits);

        for (int divSteps = 0; divSteps < maxDivsteps; divSteps += 30)
        {
            eta = divsteps30(eta, F[0], G[0], t);
            updateDE30(len30, D, E, t, m0Inv32, M);
            updateFG30(len30, F, G, t);
        }

        int signF = F[len30 - 1] >> 31;
        cnegate30(len30, signF, F);

        /*
         * D is in the range (-2.M, M). First, conditionally add M if D is negative, to bring it
         * into the range (-M, M). Then normalize by conditionally negating (according to signF)
         * and/or then adding M, to bring it into the range [0, M).
         */
        cnormalize30(len30, signF, D, M);

        decode30(bits, D, 0, z, 0);
//        assert 0 != Nat.lessThan(len32, z, m);

        return Nat.equalTo(len30, F, 1) & Nat.equalToZero(len30, G);
    }

    public static boolean modOddInverseVar(int[] m, int[] x, int[] z)
    {
        int len32 = m.length;
//        assert len32 > 0;
//        assert (m[0] & 1) != 0;
//        assert m[len32 - 1] != 0;

        int bits = (len32 << 5) - Integers.numberOfLeadingZeros(m[len32 - 1]);
        int len30 = (bits + 29) / 30;

        int[] t = new int[4];
        int[] D = new int[len30];
        int[] E = new int[len30];
        int[] F = new int[len30];
        int[] G = new int[len30];
        int[] M = new int[len30];

        E[0] = 1;
        encode30(bits, x, 0, G, 0);
        encode30(bits, m, 0, M, 0);
        System.arraycopy(M, 0, F, 0, len30);

        int clzG = Integers.numberOfLeadingZeros(G[len30 - 1] | 1) - (len30 * 30 + 2 - bits);
        int eta = -1 - clzG;
        int lenDE = len30, lenFG = len30;
        int m0Inv32 = inverse32(M[0]);
        int maxDivsteps = getMaximumDivsteps(bits);

        int divsteps = 0;
        while (!Nat.isZero(lenFG, G))
        {
            if (divsteps >= maxDivsteps)
            {
                return false;
            }

            divsteps += 30;

            eta = divsteps30Var(eta, F[0], G[0], t);
            updateDE30(lenDE, D, E, t, m0Inv32, M);
            updateFG30(lenFG, F, G, t);

            int fn = F[lenFG - 1];
            int gn = G[lenFG - 1];

            int cond = (lenFG - 2) >> 31;
            cond |= fn ^ (fn >> 31);
            cond |= gn ^ (gn >> 31);

            if (cond == 0)
            {
                F[lenFG - 2] |= fn << 30;
                G[lenFG - 2] |= gn << 30;
                --lenFG;
            }
        }

        int signF = F[lenFG - 1] >> 31;

        /*
         * D is in the range (-2.M, M). First, conditionally add M if D is negative, to bring it
         * into the range (-M, M). Then normalize by conditionally negating (according to signF)
         * and/or then adding M, to bring it into the range [0, M).
         */
        int signD = D[lenDE - 1] >> 31;
        if (signD < 0)
        {
            signD = add30(lenDE, D, M);
        }
        if (signF < 0)
        {
            signD = negate30(lenDE, D);
            signF = negate30(lenFG, F);
        }
//        assert 0 == signF;

        if (!Nat.isOne(lenFG, F))
        {
            return false;
        }

        if (signD < 0)
        {
            signD = add30(lenDE, D, M);
        }
//        assert 0 == signD;

        decode30(bits, D, 0, z, 0);
//        assert !Nat.gte(len32, z, m);

        return true;
    }

    public static int[] random(int[] p)
    {
        int len = p.length;
        Random rand = new Random();
        int[] s = Nat.create(len);

        int m = p[len - 1];
        m |= m >>> 1;
        m |= m >>> 2;
        m |= m >>> 4;
        m |= m >>> 8;
        m |= m >>> 16;

        do
        {
            for (int i = 0; i != len; i++)
            {
                s[i] = rand.nextInt();
            }
            s[len - 1] &= m;
        }
        while (Nat.gte(len, s, p));

        return s;
    }

    /** @deprecated Will be removed. */
    public static void subtract(int[] p, int[] x, int[] y, int[] z)
    {
        int len = p.length;
        int c = Nat.sub(len, x, y, z);
        if (c != 0)
        {
            Nat.addTo(len, p, z);
        }
    }

    private static int add30(int len30, int[] D, int[] M)
    {
//        assert len30 > 0;
//        assert D.length >= len30;
//        assert M.length >= len30;

        int c = 0, last = len30 - 1;
        for (int i = 0; i < last; ++i)
        {
            c += D[i] + M[i];
            D[i] = c & M30; c >>= 30;
        }
        c += D[last] + M[last];
        D[last] = c; c >>= 30;
        return c;
    }

    private static void cnegate30(int len30, int cond, int[] D)
    {
//        assert len30 > 0;
//        assert D.length >= len30;

        int c = 0, last = len30 - 1;
        for (int i = 0; i < last; ++i)
        {
            c += (D[i] ^ cond) - cond;
            D[i] = c & M30; c >>= 30;
        }
        c += (D[last] ^ cond) - cond;
        D[last] = c;
    }

    private static void cnormalize30(int len30, int condNegate, int[] D, int[] M)
    {
//        assert len30 > 0;
//        assert D.length >= len30;
//        assert M.length >= len30;

        int last = len30 - 1;

        {
            int c = 0, condAdd = D[last] >> 31;
            for (int i = 0; i < last; ++i)
            {
                int di = D[i] + (M[i] & condAdd);
                di = (di ^ condNegate) - condNegate;
                c += di; D[i] = c & M30; c >>= 30;
            }
            {
                int di = D[last] + (M[last] & condAdd);
                di = (di ^ condNegate) - condNegate;
                c += di; D[last] = c;
            }
        }

        {
            int c = 0, condAdd = D[last] >> 31;
            for (int i = 0; i < last; ++i)
            {
                int di = D[i] + (M[i] & condAdd);
                c += di; D[i] = c & M30; c >>= 30;
            }
            {
                int di = D[last] + (M[last] & condAdd);
                c += di; D[last] = c;
            }
//            assert c >> 30 == 0;
        }
    }

    private static void decode30(int bits, int[] x, int xOff, int[] z, int zOff)
    {
//        assert bits > 0;
//        assert x != z;

        int avail = 0;
        long data = 0L;

        while (bits > 0)
        {
            while (avail < Math.min(32, bits))
            {
                data |= (long)x[xOff++] << avail;
                avail += 30;
            }

            z[zOff++] = (int)data; data >>>= 32;
            avail -= 32;
            bits -= 32;
        }
    }

    private static int divsteps30(int eta, int f0, int g0, int[] t)
    {
        int u = 1, v = 0, q = 0, r = 1;
        int f = f0, g = g0;

        for (int i = 0; i < 30; ++i)
        {
//            assert (f & 1) == 1;
//            assert (u * f0 + v * g0) == f << i;
//            assert (q * f0 + r * g0) == g << i;

            int c1 = eta >> 31;
            int c2 = -(g & 1);

            int x = (f ^ c1) - c1;
            int y = (u ^ c1) - c1;
            int z = (v ^ c1) - c1;

            g += x & c2;
            q += y & c2;
            r += z & c2;

            c1 &= c2;
            eta = (eta ^ c1) - (c1 + 1);

            f += g & c1;
            u += q & c1;
            v += r & c1;

            g >>= 1;
            u <<= 1;
            v <<= 1;
        }

        t[0] = u;
        t[1] = v;
        t[2] = q;
        t[3] = r;

        return eta;
    }

    private static int divsteps30Var(int eta, int f0, int g0, int[] t)
    {
        int u = 1, v = 0, q = 0, r = 1;
        int f = f0, g = g0, m, w, x, y, z;
        int i = 30, limit, zeros;

        for (;;)
        {
            // Use a sentinel bit to count zeros only up to i.
            zeros = Integers.numberOfTrailingZeros(g | (-1 << i));

            g >>= zeros;
            u <<= zeros;
            v <<= zeros;
            eta -= zeros;
            i -= zeros;

            if (i <= 0)
            {
                break;
            }

//            assert (f & 1) == 1;
//            assert (g & 1) == 1;
//            assert (u * f0 + v * g0) == f << (30 - i);
//            assert (q * f0 + r * g0) == g << (30 - i);

            if (eta < 0)
            {
                eta = -eta;
                x = f; f = g; g = -x;
                y = u; u = q; q = -y;
                z = v; v = r; r = -z;

                // Handle up to 6 divsteps at once, subject to eta and i.
                limit = (eta + 1) > i ? i : (eta + 1);
                m = (-1 >>> (32 - limit)) & 63;

                w = (f * g * (f * f - 2)) & m;
            }
            else
            {
                // Handle up to 4 divsteps at once, subject to eta and i.
                limit = (eta + 1) > i ? i : (eta + 1);
                m = (-1 >>> (32 - limit)) & 15;

                w = f + (((f + 1) & 4) << 1);
                w = (-w * g) & m;
            }

            g += f * w;
            q += u * w;
            r += v * w;

//            assert (g & m) == 0;
        }

        t[0] = u;
        t[1] = v;
        t[2] = q;
        t[3] = r;

        return eta;
    }

    private static void encode30(int bits, int[] x, int xOff, int[] z, int zOff)
    {
//        assert bits > 0;
//        assert x != z;

        int avail = 0;
        long data = 0L;

        while (bits > 0)
        {
            if (avail < Math.min(30, bits))
            {
                data |= (x[xOff++] & M32L) << avail;
                avail += 32;
            }

            z[zOff++] = (int)data & M30; data >>>= 30;
            avail -= 30;
            bits -= 30;
        }
    }

    private static int getMaximumDivsteps(int bits)
    {
        return (49 * bits + (bits < 46 ? 80 : 47)) / 17;
    }

    private static int negate30(int len30, int[] D)
    {
//        assert len30 > 0;
//        assert D.length >= len30;

        int c = 0, last = len30 - 1;
        for (int i = 0; i < last; ++i)
        {
            c -= D[i];
            D[i] = c & M30; c >>= 30;
        }
        c -= D[last];
        D[last] = c; c >>= 30;
        return c;
    }

    private static void updateDE30(int len30, int[] D, int[] E, int[] t, int m0Inv32, int[] M)
    {
//        assert len30 > 0;
//        assert D.length >= len30;
//        assert E.length >= len30;
//        assert M.length >= len30;
//        assert m0Inv32 * M[0] == 1;

        final int u = t[0], v = t[1], q = t[2], r = t[3];
        int di, ei, i, md, me, mi, sd, se;
        long cd, ce;

        /*
         * We accept D (E) in the range (-2.M, M) and conceptually add the modulus to the input
         * value if it is initially negative. Instead of adding it explicitly, we add u and/or v (q
         * and/or r) to md (me).
         */
        sd = D[len30 - 1] >> 31;
        se = E[len30 - 1] >> 31;

        md = (u & sd) + (v & se);
        me = (q & sd) + (r & se);

        mi = M[0];
        di = D[0];
        ei = E[0];

        cd = (long)u * di + (long)v * ei;
        ce = (long)q * di + (long)r * ei;

        /*
         * Subtract from md/me an extra term in the range [0, 2^30) such that the low 30 bits of the
         * intermediate D/E values will be 0, allowing clean division by 2^30. The final D/E are
         * thus in the range (-2.M, M), consistent with the input constraint.
         */
        md -= (m0Inv32 * (int)cd + md) & M30;
        me -= (m0Inv32 * (int)ce + me) & M30;

        cd += (long)mi * md;
        ce += (long)mi * me;

//        assert ((int)cd & M30) == 0;
//        assert ((int)ce & M30) == 0;

        cd >>= 30;
        ce >>= 30;

        for (i = 1; i < len30; ++i)
        {
            mi = M[i];
            di = D[i];
            ei = E[i];

            cd += (long)u * di + (long)v * ei + (long)mi * md;
            ce += (long)q * di + (long)r * ei + (long)mi * me;

            D[i - 1] = (int)cd & M30; cd >>= 30;
            E[i - 1] = (int)ce & M30; ce >>= 30;
        }

        D[len30 - 1] = (int)cd;
        E[len30 - 1] = (int)ce;
    }

    private static void updateFG30(int len30, int[] F, int[] G, int[] t)
    {
//        assert len30 > 0;
//        assert F.length >= len30;
//        assert G.length >= len30;

        final int u = t[0], v = t[1], q = t[2], r = t[3];
        int fi, gi, i;
        long cf, cg;

        fi = F[0];
        gi = G[0];

        cf = (long)u * fi + (long)v * gi;
        cg = (long)q * fi + (long)r * gi;

//        assert ((int)cf & M30) == 0;
//        assert ((int)cg & M30) == 0;

        cf >>= 30;
        cg >>= 30;

        for (i = 1; i < len30; ++i)
        {
            fi = F[i];
            gi = G[i];

            cf += (long)u * fi + (long)v * gi;
            cg += (long)q * fi + (long)r * gi;

            F[i - 1] = (int)cf & M30; cf >>= 30;
            G[i - 1] = (int)cg & M30; cg >>= 30;
        }

        F[len30 - 1] = (int)cf;
        G[len30 - 1] = (int)cg;
    }
}
