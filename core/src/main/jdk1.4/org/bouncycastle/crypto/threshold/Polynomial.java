package org.bouncycastle.crypto.threshold;

/**
 * GF(256) arithmetic for Shamir secret splitting, over the AES (0x11b) or RSA (0x11d) reduction
 * polynomial.
 * <p>
 * Every operand reaching gfMul is secret: the secret being split, the random polynomial
 * coefficients, the share bytes, and the Lagrange products derived from them. Both operations are
 * therefore computed rather than looked up, and neither branches on an operand - a table indexed by
 * an operand leaks it through cache-timing, and a loop whose trip count is an operand's bit length
 * leaks it through timing.
 * <p>
 * NOTE: this overlay exists only because ShamirSecretSplitter.Algorithm is a hand-rolled typesafe
 * enum here rather than a Java 5 enum, so the algorithm is selected by switching on its ordinal
 * rather than on the constant itself. Keep everything else identical to the base implementation.
 */
final class Polynomial
{
    private final int irreducible;

    Polynomial(ShamirSecretSplitter.Algorithm algorithm)
    {
        switch (algorithm.ord)
        {
        case ShamirSecretSplitter._AES:
            irreducible = 0x11B;
            break;
        case ShamirSecretSplitter._RSA:
            irreducible = 0x11D;
            break;
        default:
            throw new IllegalArgumentException("The algorithm is not correct");
        }
    }

    byte gfMul(int x, int y)
    {
        int result = 0;

        // Russian-peasant multiply over a fixed eight iterations. The mask -(y & 1) is 0 or -1, so
        // the accumulate is unconditional, and the reduction XORs the irreducible polynomial under a
        // mask taken from x's top bit rather than testing it.
        for (int i = 0; i < 8; i++)
        {
            result ^= x & -(y & 1);
            y >>>= 1;

            int carry = (x >>> 7) & 1;
            x = ((x << 1) ^ (irreducible & -carry)) & 0xFF;
        }

        return (byte)result;
    }

    /**
     * The exponent is always public - the fixed 254 of an inversion (n^254 is n's multiplicative inverse,
     * by Fermat, and maps 0 to 0, so a zero needs no branch of its own), or a share/coefficient index - so
     * branching on its bits is safe. The base may be secret, and reaches only gfMul.
     */
    byte gfPow(int n, byte k)
    {
        int result = 1;
        for (int i = 0; i < 8; i++)
        {
            if ((k & (1 << i)) != 0)
            {
                result = gfMul(result & 0xff, n & 0xff);
            }
            n = gfMul(n & 0xff, n & 0xff);
        }
        return (byte)result;
    }

    byte[] gfVecMul(byte[] xs, byte[][] yss)
    {
        byte[] result = new byte[yss[0].length];
        int sum;
        for (int j = 0; j < yss[0].length; j++)
        {
            sum = 0;
            for (int k = 0; k < xs.length; k++)
            {
                sum ^= gfMul(xs[k] & 0xff, yss[k][j] & 0xff);
            }
            result[j] = (byte)sum;
        }
        return result;
    }
}
