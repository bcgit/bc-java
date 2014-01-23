package org.bouncycastle.math.ec;

import org.bouncycastle.util.Arrays;

abstract class Mod
{
    public static void invert(int[] p, int[] x, int[] z)
    {
        int len = p.length;
        if (Nat.isOne(len, x))
        {
            System.arraycopy(x, 0, z, 0, len);
            return;
        }

        int[] u = Arrays.clone(x);
        int[] a = Nat.create(len);
        a[0] = 1;

        if ((u[0] & 1) == 0)
        {
            inversionStep(p, u, a);
        }
        if (Nat.isOne(len, u))
        {
            System.arraycopy(a, 0, z, 0, len);
            return;
        }

        int[] v = Arrays.clone(p);
        int[] b = Nat.create(len);

        for (;;)
        {
            if (Nat.gte(len, u, v))
            {
                subtract(p, a, b, a);
                Nat.sub(len, u, v, u);
                if ((u[0] & 1) == 0)
                {
                    inversionStep(p, u, a);
                }
                if (Nat.isOne(len, u))
                {
                    System.arraycopy(a, 0, z, 0, len);
                    return;
                }
            }
            else
            {
                subtract(p, b, a, b);
                Nat.sub(len, v, u, v);
                if ((v[0] & 1) == 0)
                {
                    inversionStep(p, v, b);
                }
                if (Nat.isOne(len, v))
                {
                    System.arraycopy(b, 0, z, 0, len);
                    return;
                }
            }
        }
    }

    public static void subtract(int[] p, int[] x, int[] y, int[] z)
    {
        int len = p.length;
        int c = Nat.sub(len, x, y, z);
        if (c != 0)
        {
            Nat.add(len, z, p, z);
        }
    }

    private static void inversionStep(int[] p, int[] u, int[] x)
    {
        int len = p.length;
        int count = 0;
        while (u[0] == 0)
        {
            Nat.shiftDownWord(u, len, 0);
            count += 32;
        }

        int zeroes = getTrailingZeroes(u[0]);
        if (zeroes > 0)
        {
            Nat.shiftDownBits(u, len, zeroes, 0);
            count += zeroes;
        }

        for (int i = 0; i < count; ++i)
        {
            int c = (x[0] & 1) == 0 ? 0 : Nat.add(len, x, p, x);
            Nat.shiftDownBit(x, len, c);
        }
    }

    private static int getTrailingZeroes(int x)
    {
//        assert x != 0;

        int count = 0;
        while ((x & 1) == 0)
        {
            x >>>= 1;
            ++count;
        }
        return count;
    }
}
