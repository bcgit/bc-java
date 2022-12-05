package org.bouncycastle.pqc.crypto.gemss;

public class GeMSSUtils
{
    static long NORBITS_UINT(long n)
    {
        n |= n << 32;
        n >>>= 32;
        --n;
        return n >>> 63;
//        n |= n >>> 32;
//        n |= n >>> 16;
//        n |= n >>> 8;
//        n |= n >>> 4;
//        n |= n >>> 2;
//        n |= n >>> 1;
//        n = ~n;
//        return n & 1L;
    }

    static long XORBITS_UINT(long n)
    {
        //TODO: need to test which one is faster.
//        n ^= n >>> 32;
//        n ^= n >>> 16;
//        n ^= n >>> 8;
//        n ^= n >>> 4;
//        n ^= n >>> 2;
//        n ^= n >>> 1;
//        return n & 1L;
        n ^= n << 1;
        n ^= n << 2;
        return ((n & (0x8888888888888888L)) * (0x1111111111111111L)) >>> 63;
    }

    static long ORBITS_UINT(long n)
    {
        n |= n << 32;
        n >>>= 32;
        n += 0xFFFFFFFFL;
        return n >>> 32;
//        n |= n >>> 32;
//        n |= n >>> 16;
//        n |= n >>> 8;
//        n |= n >>> 4;
//        n |= n >>> 2;
//        n |= n >>> 1;
//        return n & 1L;
    }

    /* Compare two UINT in constant-time */
    static long CMP_LT_UINT(long a, long b)
    {
        return ((((a >>> 63) ^ (b >>> 63)) & (((a >>> 63) - (b >>> 63)) >>> 63))
            ^ (((a >>> 63) ^ (b >>> 63) ^ 1L) & (((a & (0x7FFFFFFFFFFFFFFFL))
            - (b & (0x7FFFFFFFFFFFFFFFL))) >>> 63)));
    }

    static long maskUINT(int k)
    {
        return k != 0 ? (1L << k) - 1L : -1L;
    }

    static int Highest_One(int x)
    {
        x |= x >>> 1;
        x |= x >>> 2;
        x |= x >>> 4;
        x |= x >>> 8;
        x |= x >>> 16;
        return x ^ (x >>> 1);
    }
}
