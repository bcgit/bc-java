package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

public class SecP256R1Field
{
    // 2^256 - 2^224 + 2^192 + 2^96 - 1
    private static final int[] P = new int[] { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0xFFFFFFFF };
    private static final int P7 = 0xFFFFFFFF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat256.add(x, y, z);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat256.sub(z, P, z);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        System.arraycopy(x, 0, z, 0, 8);
        int c = Nat256.inc(z, 0);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat256.sub(z, P, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat256.fromBigInteger(x);
        if (z[7] == P7 && Nat256.gte(z, P))
        {
            Nat256.sub(z, P, z);
        }
        return z;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat256.createExt();
        Nat256.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat256.isZero(x))
        {
            Nat256.zero(z);
        }
        else
        {
            Nat256.sub(P, x, z);
        }
    }

    private static void reduce(int[] tt, int[] z)
    {
        int c = 0;

        System.arraycopy(tt, 0, z, 0, 8); //s1

        int[] s2 = new int[] { 0, 0, 0, tt[11], tt[12], tt[13], tt[14], tt[15] };
        c += Nat256.addBothTo(s2, s2, z);
        int[] s3 = new int[] { 0, 0, 0, tt[12], tt[13], tt[14], tt[15], 0 };
        c += Nat256.addBothTo(s3, s3, z);
        int[] s4 = new int[] { tt[8], tt[9], tt[10], 0, 0, 0, tt[14], tt[15] };
        int[] s5 = new int[] { tt[9], tt[10], tt[11], tt[13], tt[14], tt[15], tt[13], tt[8] };
        c += Nat256.addBothTo(s4, s5, z);

        int[] s6 = new int[] { tt[11], tt[12], tt[13], 0, 0, 0, tt[8], tt[10] };
        int[] s7 = new int[] { tt[12], tt[13], tt[14], tt[15], 0, 0, tt[9], tt[11] };
        c += Nat256.subBothFrom(s6, s7, z);
        int[] s8 = new int[] { tt[13], tt[14], tt[15], tt[8], tt[9], tt[10], 0, tt[12] };
        int[] s9 = new int[] { tt[14], tt[15], 0, tt[9], tt[10], tt[11], 0, tt[13] };
        c += Nat256.subBothFrom(s8, s9, z);

        if (c > 0)
        {
            do
            {
                c += Nat256.sub(z, P, z);
            }
            while (c != 0);
        }
        else if (c < 0)
        {
            do
            {
                c += Nat256.add(z, P, z);
            }
            while (c != 0);
        }

        assert c == 0;

        if (z[7] == P7 && Nat256.gte(z, P))
        {
            Nat256.sub(z, P, z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat256.createExt();
        // NOTE: The simpler 'mul' performs better than 'square'
        // Nat256.square(x, tt);
        Nat256.mul(x, x, tt);
        reduce(tt, z);
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat256.sub(x, y, z);
        if (c != 0)
        {
            Nat256.add(z, P, z);
        }
    }
}
