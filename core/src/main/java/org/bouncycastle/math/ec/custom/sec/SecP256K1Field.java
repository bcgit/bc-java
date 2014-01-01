package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.crypto.util.Pack;

public class SecP256K1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    private static final int[] P = new int[] { 0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF };
    private static final long PInv = 0x00000001000003D1L;

    public static int[] create()
    {
        return new int[8];
    }

    public static int[] createDouble()
    {
        return new int[16];
    }

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat256.add(x, y, z);
        if (c != 0 || (z[7] == -1 && Nat256.gte(z, P)))
        {
            Nat256.addDWord(PInv, z, 0);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        System.arraycopy(x, 0, z, 0, 8);
        int c = Nat256.inc(z, 0);
        if (c != 0 || (z[7] == -1 && Nat256.gte(z, P)))
        {
            Nat256.addDWord(PInv, z, 0);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        if (x.signum() < 0 || x.bitLength() > 256)
        {
            throw new IllegalArgumentException();
        }

        int[] z = create();
        int i = 0;
        while (x.bitLength() > 0)
        {
            z[i++] = x.intValue();
            x = x.shiftRight(32);
        }
        if (z[7] == -1 && Nat256.gte(z, P))
        {
            Nat256.addDWord(PInv, z, 0);
        }
        return z;
    }

    public static boolean isOne(int[] x)
    {
        return Nat256.isOne(x);
    }

    public static boolean isZero(int[] x)
    {
        return Nat256.isZero(x);
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = createDouble();
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

        if (c != 0 || (tt[7] == -1 && Nat256.gte(tt, P)))
        {
            Nat256.addDWord(PInv, z, 0);
        }

        System.arraycopy(tt, 0, z, 0, 8);
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = createDouble();
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

    public static boolean testBit(int[] x, int bit)
    {
        if (bit < 0 || bit > 255)
        {
            return false;
        }
        int w = bit >>> 5;
        int b = bit & 31;
        return (x[w] & (1 << b)) != 0;
    }

    public static BigInteger toBigInteger(int[] x)
    {
        byte[] bs = new byte[32];
        for (int i = 0; i < 8; ++i)
        {
            Pack.intToBigEndian(x[i], bs, (7 - i) << 2);
        }
        return new BigInteger(1, bs);
    }
}
