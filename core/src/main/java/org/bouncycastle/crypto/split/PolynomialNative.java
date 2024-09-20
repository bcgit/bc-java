package org.bouncycastle.crypto.split;

public class PolynomialNative
    extends Polynomial
{
    private final int IRREDUCIBLE;

    public PolynomialNative(int algorithm)
    {
        switch (algorithm){
        case AES:
            IRREDUCIBLE = 0x11B;
            break;
        case RSA:
            IRREDUCIBLE = 0x11D;
            break;
        default:
            throw new IllegalArgumentException("The algorithm is not correct");
        }
    }

    public int gfMul(int x, int y)
    {
        int result = pmult(x, y);
        return mod(result, IRREDUCIBLE);
    }

    private int pmult(int x, int y)
    {
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
        return result;
    }

    private static int mod(int value, int irreducible)
    {
        while (value >= (1 << 8))
        {
            if ((value & (1 << 8)) != 0)
            {
                value ^= irreducible;
            }
            value <<= 1;
        }
        return value & 0xFF;
    }

    public int gfPow(int n, int k)
    {
        int result = 1;
        int[] base = new int[]{n};
        while (k > 0)
        {
            if ((k & 1) != 0)
            {
                result = gfMul(result, base[0]);
            }
            base[0] = gfMul(base[0], base[0]);
            k >>= 1;
        }
        return result;
    }

    public int gfInv(int x)
    {
        return gfPow(x, 254); // Inverse is x^(2^8-2)
    }

    public int gfDiv(int x, int y)
    {
        return gfMul(x, gfInv(y));
    }
}
