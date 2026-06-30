package org.bouncycastle.pqc.crypto.uov;

import org.bouncycastle.math.raw.GF16;
import org.bouncycastle.math.raw.GF256AES;
import org.bouncycastle.util.Pack;

/**
 * GF(2^8) and GF(2^4) vector primitives for UOV.
 * <p>
 * The scalar GF(2^8) multiply/inverse live in the shared
 * {@link org.bouncycastle.math.raw.GF256AES} (same 0x11b AES field), and the scalar
 * GF(2^4) multiply/inverse plus the word-parallel multiply-accumulate step in
 * {@link org.bouncycastle.math.raw.GF16} (same x^4 + x + 1 field, shared with MAYO).
 * The vector multiply-accumulate kernels below drive
 * {@link org.bouncycastle.math.raw.GF256AES#mulFx8(int, long)} and
 * {@link org.bouncycastle.math.raw.GF16#mulAddStep16(long, long, long, long, long)}.
 * <p>
 * GF(2^8) reduction polynomial: x^8 + x^4 + x^3 + x + 1 (0x11b) — the AES field.
 * GF(2^4) reduction polynomial: x^4 + x + 1 (0x13). Matches the reference
 * pqov implementation in src/gf16.h.
 */
final class GF
{
    private GF()
    {
    }

    static int isNonzero256(int a)
    {
        return (-(a & 0xff)) >>> 31;
    }

    static int isNonzero16(int a)
    {
        return (-(a & 0xf)) >>> 31;
    }

    static int getEle16(byte[] vec, int i)
    {
        int b = vec[i >>> 1] & 0xff;
        return ((i & 1) != 0) ? (b >>> 4) : (b & 0xf);
    }

    static void setEle16(byte[] vec, int i, int v)
    {
        int idx = i >>> 1;
        int old = vec[idx] & 0xff;
        if ((i & 1) != 0)
        {
            old = (old & 0x0f) | ((v & 0xf) << 4);
        }
        else
        {
            old = (old & 0xf0) | (v & 0xf);
        }
        vec[idx] = (byte)old;
    }

    static void vecAdd(byte[] accuB, int aOff, byte[] a, int bOff, int len)
    {
        for (int i = 0; i < len; i++)
        {
            accuB[aOff + i] ^= a[bOff + i];
        }
    }

    static void vecConditionalAdd(byte[] accuB, int bOff, int condition, byte[] a, int aOff, int len)
    {
        int mask = -(condition & 1);
        for (int i = 0; i < len; i++)
        {
            accuB[bOff + i] ^= (byte)(a[aOff + i] & mask);
        }
    }

    static void vecMulScalar256(byte[] a, int aOff, int scalar, int len)
    {
        // Word-parallel: eight GF(256) lanes per long via the shared
        // constant-time GF256AES.mulFx8, with a scalar tail for the final sub-8
        // columns. Byte-identical to the per-element form a[i] = a[i] * scalar;
        // loop bounds depend only on the public length len and the multiply is
        // table-free, so constant time is preserved.
        int i = 0;
        for (; i + 8 <= len; i += 8)
        {
            long v = Pack.littleEndianToLong(a, aOff + i);
            Pack.longToLittleEndian(GF256AES.mulFx8(scalar, v), a, aOff + i);
        }
        for (; i < len; i++)
        {
            a[aOff + i] = (byte)GF256AES.mul(a[aOff + i] & 0xff, scalar);
        }
    }

    static void vecMadd256(byte[] accuC, int cOff, byte[] a, int aOff, int scalar, int len)
    {
        // No `if (scalar == 0) return` shortcut: scalar is derived from secret
        // material (vinegar / oil) during sign(), so branching on its zero-ness
        // would leak one bit of timing info per call. Word-parallel over eight
        // lanes per long via the shared constant-time GF256AES.mulFx8 (table-free,
        // handles a zero scalar correctly), with a scalar tail. Byte-identical
        // to the per-element accuC[i] ^= a[i] * scalar form.
        int i = 0;
        for (; i + 8 <= len; i += 8)
        {
            long av = Pack.littleEndianToLong(a, aOff + i);
            long cv = Pack.littleEndianToLong(accuC, cOff + i);
            Pack.longToLittleEndian(cv ^ GF256AES.mulFx8(scalar, av), accuC, cOff + i);
        }
        for (; i < len; i++)
        {
            accuC[cOff + i] ^= (byte)GF256AES.mul(a[aOff + i] & 0xff, scalar);
        }
    }

    static void vecMulScalar16(byte[] a, int aOff, int scalar, int len)
    {
        for (int i = 0; i < len; i++)
        {
            int b = a[aOff + i] & 0xff;
            int lo = GF16.mul(b & 0xf, scalar);
            int hi = GF16.mul((b >>> 4) & 0xf, scalar);
            a[aOff + i] = (byte)((hi << 4) | lo);
        }
    }

    static void vecMadd16(byte[] accuC, int cOff, byte[] a, int aOff, int scalar, int len)
    {
        // No zero-scalar shortcut, see vecMadd256. Word-parallel over sixteen
        // GF(16) nibbles per long via the shared constant-time GF16.mulAddStep16
        // (mask-select on the scalar's 4 bits + SWAR *x, table-free), with a
        // per-element tail. Byte-identical to the per-nibble GF16.mul form; the
        // nibble kernel is shared with MAYO's GF16Utils.
        int s = scalar & 0xf;
        long m0 = -(long)(s & 1);
        long m1 = -(long)((s >>> 1) & 1);
        long m2 = -(long)((s >>> 2) & 1);
        long m3 = -(long)((s >>> 3) & 1);
        int i = 0;
        for (; i + 8 <= len; i += 8)
        {
            long r = GF16.mulAddStep16(Pack.littleEndianToLong(a, aOff + i), m0, m1, m2, m3);
            Pack.longToLittleEndian(Pack.littleEndianToLong(accuC, cOff + i) ^ r, accuC, cOff + i);
        }
        for (; i < len; i++)
        {
            int b = a[aOff + i] & 0xff;
            int lo = GF16.mul(b & 0xf, s);
            int hi = GF16.mul((b >>> 4) & 0xf, s);
            accuC[cOff + i] ^= (byte)((hi << 4) | lo);
        }
    }
}
