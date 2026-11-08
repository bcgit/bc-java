package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.Fp2Element;

/**
 * Checks both G2 scalar multiplications, which run in Jacobian coordinates,
 * against a plain affine double-and-add built from the public {@code add} and
 * {@code doublePoint}. Covers points in and outside the prime-order subgroup,
 * negative scalars, and the scalars that drive the mixed addition into its
 * special cases: {@code r} (the accumulator reaches {@code -P}, so the final
 * addition gives infinity) and {@code r + 2} (it reaches {@code P}, so the final
 * addition is a doubling).
 */
public class BLS12_381G2ScalarMulTest
    extends TestCase
{
    private static final BigInteger R = BLS12_381G1.ORDER;
    private static final SecureRandom RNG = new SecureRandom(new byte[]{ 11 });

    private static BLS12_381G2Point affineMultiply(BLS12_381G2Point p, BigInteger k)
    {
        if (k.signum() < 0)
        {
            return affineMultiply(p.negate(), k.negate());
        }
        BLS12_381G2Point result = BLS12_381G2Point.INFINITY;
        BLS12_381G2Point addend = p;
        for (int i = 0; i < k.bitLength(); ++i)
        {
            if (k.testBit(i))
            {
                result = result.add(addend);
            }
            addend = addend.doublePoint();
        }
        return result;
    }

    /** A random point of E'(Fp^2): outside G2 except with probability 1/h. */
    private static BLS12_381G2Point nonSubgroupPoint()
    {
        for (;;)
        {
            Fp2Element x = Fp2Element.of(new BigInteger(380, RNG), new BigInteger(380, RNG));
            Fp2Element y = x.square().mul(x).add(BLS12_381G2Point.B).sqrtOrNull();
            if (y != null)
            {
                return BLS12_381G2Point.of(x, y);
            }
        }
    }

    private static void check(BLS12_381G2Point p, BigInteger k, boolean constantTime)
    {
        BLS12_381G2Point expected = affineMultiply(p, k);
        assertEquals("multiply by " + k, expected, p.multiply(k));
        if (constantTime)
        {
            assertEquals("constantTimeMultiply by " + k, expected, p.constantTimeMultiply(k));
        }
    }

    public void testSpecialScalars()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        BigInteger[] scalars = { BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), BigInteger.valueOf(3),
            R.subtract(BigInteger.ONE), R, R.add(BigInteger.ONE), R.add(BigInteger.valueOf(2)),
            BigInteger.ONE.shiftLeft(255), BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE),
            BigInteger.valueOf(-1), R.negate().add(BigInteger.valueOf(5)) };
        for (int i = 0; i < scalars.length; ++i)
        {
            check(g, scalars[i], true);
        }
        assertTrue(g.multiply(R).isInfinity());
        assertTrue(g.constantTimeMultiply(R).isInfinity());
        assertEquals(g.doublePoint(), g.multiply(R.add(BigInteger.valueOf(2))));
    }

    public void testRandomScalarsInSubgroup()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator().multiply(new BigInteger(255, RNG));
        for (int i = 0; i < 6; ++i)
        {
            check(g, new BigInteger(256, RNG), true);
        }
    }

    /**
     * On G2, {@code constantTimeMultiply} splits the scalar into four base-|x|
     * digits and adds subset sums of P, -psi(P), psi^2(P), -psi^3(P) from a
     * table. These scalars give digits that are zero in some columns (so the
     * table entry is skipped), single-digit scalars that leave the
     * accumulator at infinity for up to three quarters of the loop, digits at
     * their maximum |x| - 1, equal digits (only entries 0 and 15), every one
     * of the 16 entries, and scalars that only reduce mod r into range.
     */
    public void testGlsDigitPatterns()
    {
        BigInteger absX = new BigInteger("d201000000010000", 16);
        BigInteger max = absX.subtract(BigInteger.ONE);
        BLS12_381G2Point g = BLS12_381G2.getGenerator().multiply(new BigInteger(255, RNG));
        BigInteger[][] digitSets = {
            { BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO },
            { BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO },
            { BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO },
            { BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE },
            { max, max, max, BigInteger.ZERO },
            { max, BigInteger.ZERO, max, BigInteger.ONE },
            { BigInteger.valueOf(0x5a5a), BigInteger.valueOf(0x5a5a), BigInteger.valueOf(0x5a5a),
                BigInteger.valueOf(0x5a5a) },
            // Column j of these digits is the 4-bit number j mod 16: every table entry.
            { BigInteger.valueOf(0xaaaaL), BigInteger.valueOf(0xccccL), BigInteger.valueOf(0xf0f0L),
                BigInteger.valueOf(0xff00L) },
            { new BigInteger(64, RNG).mod(absX), new BigInteger(64, RNG).mod(absX), new BigInteger(64, RNG).mod(absX),
                new BigInteger(60, RNG) },
        };
        for (int i = 0; i < digitSets.length; ++i)
        {
            BigInteger k = BigInteger.ZERO;
            for (int j = 3; j >= 0; --j)
            {
                k = k.multiply(absX).add(digitSets[i][j]);
            }
            assertTrue(k.compareTo(R) < 0);
            check(g, k, true);
        }
        BigInteger[] reduced = { R.add(BigInteger.valueOf(7)), R.shiftLeft(3).add(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(300).subtract(BigInteger.ONE), absX.pow(4), absX.pow(4).subtract(BigInteger.ONE),
            R.negate().subtract(BigInteger.valueOf(9)) };
        for (int i = 0; i < reduced.length; ++i)
        {
            assertEquals("constantTimeMultiply by " + reduced[i], affineMultiply(g, reduced[i].mod(R)),
                g.constantTimeMultiply(reduced[i]));
        }
    }

    public void testPointsOutsideSubgroup()
    {
        for (int i = 0; i < 3; ++i)
        {
            BLS12_381G2Point p = nonSubgroupPoint();
            check(p, new BigInteger(256, RNG), true);
            check(p, R, true);
            // Cofactor clearing, the hash-to-curve use of multiply.
            check(p, BLS12_381G2.H_EFF, false);
        }
    }

    public void testInfinity()
    {
        assertTrue(BLS12_381G2Point.INFINITY.multiply(BigInteger.TEN).isInfinity());
        assertTrue(BLS12_381G2Point.INFINITY.constantTimeMultiply(BigInteger.TEN).isInfinity());
    }
}
