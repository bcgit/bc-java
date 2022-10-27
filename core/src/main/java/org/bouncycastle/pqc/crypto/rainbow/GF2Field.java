package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.util.Pack;

/**
 * This class provides the basic operations like addition, multiplication and
 * finding the multiplicative inverse of an element in GF2^8.
 * <p>
 * GF2^8 is implemented using the tower representation:
 * gf4     := gf2[x]/x^2+x+1
 * gf16    := gf4[y]/y^2+y+x
 * gf256   := gf16[X]/X^2+X+xy
 */
class GF2Field
{
    static final byte[][] gfMulTable = new byte[256][256];
    static final byte[] gfInvTable = new byte[256];

    static
    {
        {
            long p = 0x0101010101010101L;
            for (int i = 1; i <= 255; i++)
            {
                long q = 0x0706050403020100L;
                for (int j = 0; j < 256; j += 8)
                {
                    long r = gf256Mul_64(p, q);
                    Pack.longToLittleEndian(r, gfMulTable[i], j);
                    q += 0x0808080808080808L;
                }

                p += 0x0101010101010101L;
            }
        }

        {
            long p = 0x0706050403020100L;
            for (int i = 0; i < 256; i += 8)
            {
                long r = gf256Inv_64(p);
                Pack.longToLittleEndian(r, gfInvTable, i);
                p += 0x0808080808080808L;
            }
        }
    }

    public static final int MASK = 0xff;

    private static short gf4Mul2(short a)
    {
        int r = a << 1;
        r ^= (a >>> 1) * 7;
        return (short)(r & MASK);
    }

    private static short gf4Mul3(short a)
    {
        int msk = (a - 2) >>> 1;
        int r = (msk & (a * 3)) | ((~msk) & (a - 1));
        return (short)(r & MASK);
    }

    private static short gf4Mul(short a, short b)
    {
        int r = a * (b & 1);
        r ^= (gf4Mul2(a) * (b >>> 1));
        return (short)(r & MASK);
    }

    private static short gf4Squ(short a)
    {
        int r = a ^ (a >>> 1);
        return (short)(r & MASK);
    }

    private static short gf16Mul(short a, short b)
    {
        short a0 = (short)((a & 3) & MASK);
        short a1 = (short)((a >>> 2) & MASK);
        short b0 = (short)((b & 3) & MASK);
        short b1 = (short)((b >>> 2) & MASK);
        short a0b0 = gf4Mul(a0, b0);
        short a1b1 = gf4Mul(a1, b1);
        short a0b1_a1b0 = (short)(gf4Mul((short)(a0 ^ a1), (short)(b0 ^ b1)) ^ a0b0);
        short a1b1_x2 = gf4Mul2(a1b1);
        return (short)(((a0b1_a1b0 << 2) ^ a0b0 ^ a1b1_x2) & MASK);
    }

    private static short gf16Squ(short a)
    {
        short a0 = (short)((a & 3) & MASK);
        short a1 = (short)((a >>> 2) & MASK);
        a1 = gf4Squ(a1);
        short a1squ_x2 = gf4Mul2(a1);
        return (short)(((a1 << 2) ^ a1squ_x2 ^ gf4Squ(a0)) & MASK);
    }

    private static short gf16Mul8(short a)
    {
        short a0 = (short)((a & 3) & MASK);
        short a1 = (short)((a >>> 2) & MASK);
        int r = gf4Mul2((short)(a0 ^ a1)) << 2;
        r |= gf4Mul3(a1);
        return (short)(r & MASK);
    }

    private static short gf256Mul(short a, short b)
    {
        short a0 = (short)((a & 15) & MASK);
        short a1 = (short)((a >>> 4) & MASK);
        short b0 = (short)((b & 15) & MASK);
        short b1 = (short)((b >>> 4) & MASK);
        short a0b0 = gf16Mul(a0, b0);
        short a1b1 = gf16Mul(a1, b1);
        short a0b1_a1b0 = (short)(gf16Mul((short)(a0 ^ a1), (short)(b0 ^ b1)) ^ a0b0);
        short a1b1_x2 = gf16Mul8(a1b1);
        return (short)(((a0b1_a1b0 << 4) ^ a0b0 ^ a1b1_x2) & MASK);
    }

    private static short gf256Squ(short a)
    {
        short a0 = (short)((a & 15) & MASK);
        short a1 = (short)((a >>> 4) & MASK);
        a1 = gf16Squ(a1);
        short a1squ_x8 = gf16Mul8(a1);
        return (short)(((a1 << 4) ^ a1squ_x8 ^ gf16Squ(a0)) & MASK);
    }

    private static short gf256Inv(short a)
    {
        // 128+64+32+16+8+4+2 = 254
        short a2 = gf256Squ(a);
        short a4 = gf256Squ(a2);
        short a8 = gf256Squ(a4);
        short a4_2 = gf256Mul(a4, a2);
        short a8_4_2 = gf256Mul(a4_2, a8);
        short a64_ = gf256Squ(a8_4_2);
        a64_ = gf256Squ(a64_);
        a64_ = gf256Squ(a64_);
        short a64_2 = gf256Mul(a64_, a8_4_2);
        short a128_ = gf256Squ(a64_2);
        return gf256Mul(a2, a128_);
    }

    /**
     * This function calculates the sum of two elements as an operation in GF2^8
     *
     * @param a the first element that is to be added
     * @param b the second element that should be added
     * @return the sum of the two elements a and b in GF2^8
     */
    public static short addElem(short a, short b)
    {
        return (short)(a ^ b);
    }

    public static long addElem_64(long a, long b)
    {
        return a ^ b;
    }

    /**
     * This function computes the multiplicative inverse of a given element in
     * GF2^8 The 0 has no multiplicative inverse and in this case 0 is returned.
     *
     * @param a the element which multiplicative inverse is to be computed
     * @return the multiplicative inverse of the given element, in case it
     * exists or 0, otherwise
     */
    public static short invElem(short a)
    {
//        return gf256Inv(a);
        return (short)(gfInvTable[a] & 0xff);
    }

    public static long invElem_64(long a)
    {
        return gf256Inv_64(a);
    }

    /**
     * This function multiplies two elements in GF2^8. If one of the two
     * elements is 0, 0 is returned.
     *
     * @param a the first element to be multiplied.
     * @param b the second element to be multiplied.
     * @return the product of the two input elements in GF2^8.
     */
    public static short multElem(short a, short b)
    {
//        return gf256Mul(a, b);
        return (short)(gfMulTable[a][b] & 0xff);
    }

    public static long multElem_64(long a, long b)
    {
        return gf256Mul_64(a, b);
    }



    // 64-bit parallel methods
    
    private static long gf4Mul2_64(long p)
    {
        long p0 = p & 0x5555555555555555L;
        long p1 = p & 0xAAAAAAAAAAAAAAAAL;
        return p1 ^ (p0 << 1) ^ (p1 >>> 1);
    }

//    private static long gf4Mul3_64(long p)
//    {
//        long p0 = p & 0x5555555555555555L;
//        long p1 = p & 0xAAAAAAAAAAAAAAAAL;
//        return p0 ^ (p0 << 1) ^ (p1 >>> 1);
//    }

    private static long gf4Mul_64(long p, long q)
    {
        long r1 = (((p << 1) & q) ^ ((q << 1) & p)) & 0xAAAAAAAAAAAAAAAAL;
        long r02 = p & q;

        return r02 ^ r1 ^ ((r02 & 0xAAAAAAAAAAAAAAAAL) >>> 1);
    }

    private static long gf4Squ_64(long p)
    {
        long p1 = p & 0xAAAAAAAAAAAAAAAAL;
        return p ^ (p1 >>> 1);
    }

    private static long gf16Mul_64(long p, long q)
    {
        long t = gf4Mul_64(p, q);
        
        long a0b0 = t & 0x3333333333333333L;
        long a1b1 = t & 0xCCCCCCCCCCCCCCCCL;

        long pk = (((p << 2) ^ p) & 0xCCCCCCCCCCCCCCCCL) ^ (a1b1 >>> 2); 
        long qk = (((q << 2) ^ q) & 0xCCCCCCCCCCCCCCCCL) ^ 0x2222222222222222L; 

        long v = gf4Mul_64(pk, qk);
        return v ^ (a0b0 << 2) ^ a0b0;
    }

    private static long gf16Squ_64(long p)
    {
        long t = gf4Squ_64(p);
        long u = gf4Mul2_64(t & 0xCCCCCCCCCCCCCCCCL);
        return t ^ (u >>> 2);
    }

    private static long gf16Mul8_64(long p)
    {
        long p0 = p & 0x3333333333333333L;
        long p1 = p & 0xCCCCCCCCCCCCCCCCL;

        long pk = (p0 << 2) ^ p1 ^ (p1 >>> 2);
        long t = gf4Mul2_64(pk);
        return t ^ (p1 >>> 2);
    }

    private static long gf256Mul_64(long p, long q)
    {
        long t = gf16Mul_64(p, q);
        
        long a0b0 = t & 0x0F0F0F0F0F0F0F0FL;
        long a1b1 = t & 0xF0F0F0F0F0F0F0F0L;

        long pk = (((p << 4) ^ p) & 0xF0F0F0F0F0F0F0F0L) ^ (a1b1 >>> 4); 
        long qk = (((q << 4) ^ q) & 0xF0F0F0F0F0F0F0F0L) ^ 0x0808080808080808L; 

        long v = gf16Mul_64(pk, qk);
        return v ^ (a0b0 << 4) ^ a0b0;
    }

    private static long gf256Squ_64(long p)
    {
        long t = gf16Squ_64(p);
        long a1Sq = t & 0xF0F0F0F0F0F0F0F0L;
        long a1squ_x8 = gf16Mul8_64(a1Sq);

        return t ^ (a1squ_x8 >>> 4);
    }

    private static long gf256Inv_64(long p)
    {
        long p2 = gf256Squ_64(p);
        long p4 = gf256Squ_64(p2);
        long p8 = gf256Squ_64(p4);
        long p4_2 = gf256Mul_64(p4, p2);
        long p8_4_2 = gf256Mul_64(p4_2, p8);
        long p64_ = gf256Squ_64(p8_4_2);
        p64_ = gf256Squ_64(p64_);
        p64_ = gf256Squ_64(p64_);
        long p64_2 = gf256Mul_64(p64_, p8_4_2);
        long p128_ = gf256Squ_64(p64_2);
        return gf256Mul_64(p2, p128_);
    }
}
