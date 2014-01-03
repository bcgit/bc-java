package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

public class SecP256K1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    private static final int[] P = new int[] { 0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF };
    private static final int P7 = 0xFFFFFFFF;
    private static final long PInv = 0x00000001000003D1L;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat256.add(x, y, z);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat256.addDWord(PInv, z, 0);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        System.arraycopy(x, 0, z, 0, 8);
        int c = Nat256.inc(z, 0);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat256.addDWord(PInv, z, 0);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat256.fromBigInteger(x);
        if (z[7] == P7 && Nat256.gte(z, P))
        {
            Nat256.addDWord(PInv, z, 0);
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
        long extra = -(tt[8] & M);
        extra += Nat256.mulWordAddExt((int)PInv, tt, 8, tt, 0) & M;
        extra += (Nat256.addExt(tt, 8, tt, 1) & M) << 32;
        extra += (tt[8] & M);

        long c = Nat256.mulWordDwordAdd((int)PInv, extra, tt, 0) & M;
        c += Nat256.addDWord(extra, tt, 1);

        assert c == 0L || c == 1L;

        if (c != 0 || (tt[7] == P7 && Nat256.gte(tt, P)))
        {
            Nat256.addDWord(PInv, tt, 0);
        }

        System.arraycopy(tt, 0, z, 0, 8);
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
            Nat256.subDWord(PInv, z);
        }
    }
}
