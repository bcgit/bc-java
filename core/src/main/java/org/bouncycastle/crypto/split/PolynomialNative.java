package org.bouncycastle.crypto.split;

public class PolynomialNative
    extends Polynomial
{
    private final int IRREDUCIBLE;

    public PolynomialNative(int algorithm, int l, int m, int n)
    {
        super(l, m, n);
        switch (algorithm)
        {
        case AES:
            IRREDUCIBLE = 0x11B;
            break;
        case RSA:
            IRREDUCIBLE = 0x11D;
            break;
        default:
            throw new IllegalArgumentException("The algorithm is not correct");
        }
        init();
    }

    protected int gfMul(int x, int y)
    {
        //pmult
        int result = 0;
        while (y > 0)
        {
            if ((y & 1) != 0)
            {  // If the lowest bit of y is 1
                result ^= x;     // XOR x into the result
            }
            x <<= 1;             // Shift x left (multiply by 2 in GF)
            if ((x & 0x100) != 0)
            {  // If x is larger than 8 bits, reduce
                x ^= IRREDUCIBLE;  // XOR with the irreducible polynomial
            }
            y >>= 1;             // Shift y right
        }
        //mod
        while (result >= (1 << 8))
        {
            if ((result & (1 << 8)) != 0)
            {
                result ^= IRREDUCIBLE;
            }
            result <<= 1;
        }
        return result & 0xFF;
    }

    protected byte gfDiv(int x, int y)
    {
        return (byte)gfMul(x, gfPow((byte)y, (byte)254) & 0xff);
    }
}
