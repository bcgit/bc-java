package org.bouncycastle.pqc.crypto.uov;

/**
 * GF(2^8) and GF(2^4) primitives for UOV.
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

    static int mul256(int a, int b)
    {
        a &= 0xff;
        b &= 0xff;
        int r = a * (b & 1);
        for (int i = 1; i < 8; i++)
        {
            a = ((a << 1) ^ (((a >> 7) & 1) * 0x1b)) & 0xff;
            r ^= a * ((b >> i) & 1);
        }
        return r & 0xff;
    }

    static int inv256(int a)
    {
        // No `if (a == 0) return 0` early-out: during Gaussian elimination a is
        // the (secret-derived) pivot element, so branching on its zero-ness
        // leaks per-column whether that pivot was singular. The Fermat chain
        // below already maps 0 -> 0 (every term stays 0), so the early-out is
        // redundant. Matches the reference branchless gf256_inv (src/gf16.h).
        a &= 0xff;
        int a2 = squ256(a);
        int a4 = squ256(a2);
        int a8 = squ256(a4);
        int a4_2 = mul256(a4, a2);
        int a8_4_2 = mul256(a4_2, a8);
        int a64 = squ256(a8_4_2);
        a64 = squ256(a64);
        a64 = squ256(a64);
        int a64_2 = mul256(a64, a8_4_2);
        int a128 = squ256(a64_2);
        return mul256(a2, a128);
    }

    private static int squ256(int a)
    {
        return mul256(a, a);
    }

    static int isNonzero256(int a)
    {
        return (-(a & 0xff)) >>> 31;
    }

    static int mul16(int a, int b)
    {
        a &= 0xf;
        b &= 0xf;
        int r = (a & 1) * b
              ^ (a & 2) * b
              ^ (a & 4) * b
              ^ (a & 8) * b;
        int r4 = (r ^ (((r >> 4) & 5) * 3)) & 0xff;
        r4 ^= (((r >> 5) & 1) * 6);
        return r4 & 0xf;
    }

    static int inv16(int a)
    {
        int a2 = mul16(a, a);
        int a4 = mul16(a2, a2);
        int a8 = mul16(a4, a4);
        int a6 = mul16(a4, a2);
        return mul16(a8, a6);
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
        for (int i = 0; i < len; i++)
        {
            a[aOff + i] = (byte)mul256(a[aOff + i] & 0xff, scalar);
        }
    }

    static void vecMadd256(byte[] accuC, int cOff, byte[] a, int aOff, int scalar, int len)
    {
        // No `if (scalar == 0) return` shortcut: scalar is derived from
        // secret material (vinegar / oil) during sign(), so branching on its
        // zero-ness would leak one bit of timing info per call. The inner
        // mul256 handles 0 correctly (returns 0).
        for (int i = 0; i < len; i++)
        {
            accuC[cOff + i] ^= (byte)mul256(a[aOff + i] & 0xff, scalar);
        }
    }

    static void vecMulScalar16(byte[] a, int aOff, int scalar, int len)
    {
        for (int i = 0; i < len; i++)
        {
            int b = a[aOff + i] & 0xff;
            int lo = mul16(b & 0xf, scalar);
            int hi = mul16((b >>> 4) & 0xf, scalar);
            a[aOff + i] = (byte)((hi << 4) | lo);
        }
    }

    static void vecMadd16(byte[] accuC, int cOff, byte[] a, int aOff, int scalar, int len)
    {
        // No zero-scalar shortcut see vecMadd256.
        for (int i = 0; i < len; i++)
        {
            int b = a[aOff + i] & 0xff;
            int lo = mul16(b & 0xf, scalar);
            int hi = mul16((b >>> 4) & 0xf, scalar);
            accuC[cOff + i] ^= (byte)((hi << 4) | lo);
        }
    }
}
