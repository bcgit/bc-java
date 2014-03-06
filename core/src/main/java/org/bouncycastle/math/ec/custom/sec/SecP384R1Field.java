package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.Nat;

public class SecP384R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^384 - 2^128 - 2^96 + 2^32 - 1
    static final int[] P = new int[]{ 0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, 0xFFFFFFFE,
        0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0x00000001, 0x00000000,
        0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0x00000001,
        0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFE, 0xFFFFFFFF,
        0x00000001, 0x00000002 };
    private static final int P11 = 0xFFFFFFFF;
    private static final int PExt23 = 0xFFFFFFFF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat.add(12, x, y, z);
        if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.add(24, xx, yy, zz);
        if (c != 0 || (zz[23] == PExt23 && Nat.gte(24, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(24, zz, PExtInv.length);
            }
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(12, x, z);
        if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat.fromBigInteger(384, x);
        if (z[11] == P11 && Nat.gte(12, z, P))
        {
            Nat.subFrom(12, P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(12, x, 0, z);
        }
        else
        {
            int c = Nat.add(12, x, P, z);
            Nat.shiftDownBit(12, z, c);
        }
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat.create(24);
        Nat384.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat.isZero(12, x))
        {
            Nat.zero(12, z);
        }
        else
        {
            Nat.sub(12, P, x, z);
        }
    }

    public static void reduce(int[] xx, int[] z)
    {
        long xx12 = xx[12] & M, xx13 = xx[13] & M, xx14 = xx[14] & M, xx15 = xx[15] & M;
        long xx16 = xx[16] & M, xx17 = xx[17] & M, xx18 = xx[18] & M, xx19 = xx[19] & M;
        long xx20 = xx[20] & M, xx21 = xx[21] & M, xx22 = xx[22] & M, xx23 = xx[23] & M;

        final long n = 1;

        xx12 -= n;

        long cc = 0;
        cc += (xx[0] & M) + xx12 + xx20 + xx21 - xx23;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (xx[1] & M) + xx13 + xx22 + xx23 - xx12 - xx20;
        z[1] = (int)cc;
        cc >>= 32;
        cc += (xx[2] & M) + xx14 + xx23 - xx13 - xx21;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (xx[3] & M) + xx12 + xx15 + xx20 + xx21 - xx14 - xx22 - xx23;
        z[3] = (int)cc;
        cc >>= 32;
        cc += (xx[4] & M) + xx12 + xx13 + xx16 + xx20 + ((xx21 - xx23) << 1) + xx22 - xx15;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (xx[5] & M) + xx13 + xx14 + xx17 + xx21 + (xx22 << 1) + xx23 - xx16;
        z[5] = (int)cc;
        cc >>= 32;
        cc += (xx[6] & M) + xx14 + xx15 + xx18 + xx22 + (xx23 << 1) - xx17;
        z[6] = (int)cc;
        cc >>= 32;
        cc += (xx[7] & M) + xx15 + xx16 + xx19 + xx23 - xx18;
        z[7] = (int)cc;
        cc >>= 32;
        cc += (xx[8] & M) + xx16 + xx17 + xx20 - xx19;
        z[8] = (int)cc;
        cc >>= 32;
        cc += (xx[9] & M) + xx17 + xx18 + xx21 - xx20;
        z[9] = (int)cc;
        cc >>= 32;
        cc += (xx[10] & M) + xx18 + xx19 + xx22 - xx21;
        z[10] = (int)cc;
        cc >>= 32;
        cc += (xx[11] & M) + xx19 + xx20 + xx23 - xx22;
        z[11] = (int)cc;
        cc >>= 32;
        cc += n;

//        assert cc >= 0;

        reduce32((int)cc, z);
    }

    public static void reduce32(int x, int[] z)
    {
        long cc = 0;
        
        if (x != 0)
        {
            long xx12 = x & M;
    
            cc += (z[0] & M) + xx12;
            z[0] = (int)cc;
            cc >>= 32;
            cc += (z[1] & M) - xx12;
            z[1] = (int)cc;
            cc >>= 32;
            if (cc != 0)
            {
                cc += (z[2] & M);
                z[2] = (int)cc;
                cc >>= 32;
            }
            cc += (z[3] & M) + xx12;
            z[3] = (int)cc;
            cc >>= 32;
            cc += (z[4] & M) + xx12;
            z[4] = (int)cc;
            cc >>= 32;

//            assert cc == 0 || cc == 1;
        }

        if ((cc != 0 && Nat.incAt(12, z, 5) != 0)
            || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat.create(24);
        Nat384.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat.create(24);
        Nat384.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat384.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat.sub(12, x, y, z);
        if (c != 0)
        {
            subPInvFrom(z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(24, xx, yy, zz);
        if (c != 0)
        {
            if (Nat.subFrom(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.decAt(24, zz, PExtInv.length);
            }
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(12, x, 0, z);
        if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    private static void addPInvTo(int[] z)
    {
        long c = (z[0] & M) + 1;
        z[0] = (int)c;
        c >>= 32;
        c += (z[1] & M) - 1;
        z[1] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[2] & M);
            z[2] = (int)c;
            c >>= 32;
        }
        c += (z[3] & M) + 1;
        z[3] = (int)c;
        c >>= 32;
        c += (z[4] & M) + 1;
        z[4] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.incAt(12, z, 5);
        }
    }

    private static void subPInvFrom(int[] z)
    {
        long c = (z[0] & M) - 1;
        z[0] = (int)c;
        c >>= 32;
        c += (z[1] & M) + 1;
        z[1] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[2] & M);
            z[2] = (int)c;
            c >>= 32;
        }
        c += (z[3] & M) - 1;
        z[3] = (int)c;
        c >>= 32;
        c += (z[4] & M) - 1;
        z[4] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.decAt(12, z, 5);
        }
    }
}
