package org.bouncycastle.pqc.crypto.rainbow;

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
        short a0b1_a1b0 = (short)(gf4Mul((short)(a0 ^ a1), (short)(b0 ^ b1)) ^ a0b0 ^ a1b1);
        short a1b1_x2 = gf4Mul2(a1b1);
        return (short)((((a0b1_a1b0 ^ a1b1) << 2) ^ a0b0 ^ a1b1_x2) & MASK);
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
        short a0b1_a1b0 = (short)(gf16Mul((short)(a0 ^ a1), (short)(b0 ^ b1)) ^ a0b0 ^ a1b1);
        short a1b1_x2 = gf16Mul8(a1b1);
        return (short)((((a0b1_a1b0 ^ a1b1) << 4) ^ a0b0 ^ a1b1_x2) & MASK);
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
        if (a == 0)
        {
            return 0;
        }
        return gf256Inv(a);
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
        if (a == 0 || b == 0)
        {
            return 0;
        }
        else
        {
            return gf256Mul(a, b);
        }
    }

}
