package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Tests for the constant-time scalar-multiplication paths used by BLS
 * sign / skToPk on secret scalars.
 * <p>
 * The strongest correctness check is "{@code constantTimeMultiply}
 * produces the same result as the variable-time {@code multiply} for
 * every test scalar" — algebraic equivalence rules out any chance that
 * the timing-protection rewrite changed the output. Combined with the
 * Eth2 byte-level KAT tests (which exercise the constant-time path
 * end-to-end), this gives strong evidence the constant-time variants
 * are correct as well as timing-protected.
 * <p>
 * A coarse timing-stability check is included as a smoke test, with the
 * caveat that pure-Java timing measurement is noisy and a crude inter-run
 * variance check is the best we can do without a JMH harness.
 */
public class BLS12_381ConstantTimeMulTest
    extends TestCase
{
    private static final SecureRandom RNG = new SecureRandom(new byte[]{37});

    public void testG2EquivalenceOnSmallScalars()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        for (int k = 1; k <= 8; ++k)
        {
            BigInteger scalar = BigInteger.valueOf(k);
            assertEquals("constant-time and variable-time must agree (k=" + k + ")",
                g.multiply(scalar), g.constantTimeMultiply(scalar));
        }
    }

    public void testG2EquivalenceOnRandomScalars()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        for (int trial = 0; trial < 4; ++trial)
        {
            BigInteger scalar = new BigInteger(255, RNG).mod(BLS12_381G1.ORDER);
            if (scalar.signum() == 0)
            {
                continue;
            }
            assertEquals("constant-time and variable-time must agree on random scalar #" + trial,
                g.multiply(scalar), g.constantTimeMultiply(scalar));
        }
    }

    public void testG2EquivalenceOnLowAndHighHammingWeight()
    {
        // Pathological cases the variable-time mult would treat very
        // differently: scalar with Hamming weight 1 vs. Hamming weight ~255.
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        BigInteger lowHw = BigInteger.ONE.shiftLeft(123);
        BigInteger highHw = BLS12_381G1.ORDER.subtract(BigInteger.ONE);

        assertEquals(g.multiply(lowHw), g.constantTimeMultiply(lowHw));
        assertEquals(g.multiply(highHw), g.constantTimeMultiply(highHw));
    }

    public void testG2InfinityScalar()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        assertEquals("0 * G2 == infinity",
            BLS12_381G2Point.INFINITY, g.constantTimeMultiply(BigInteger.ZERO));
    }

    public void testG2NegativeScalar()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        BigInteger scalar = BigInteger.valueOf(7);
        assertEquals("(-7) * G == 7 * (-G)",
            g.multiply(scalar.negate()),
            g.constantTimeMultiply(scalar.negate()));
    }

    public void testG2InfinityPoint()
    {
        assertEquals("any scalar * infinity == infinity",
            BLS12_381G2Point.INFINITY,
            BLS12_381G2Point.INFINITY.constantTimeMultiply(BigInteger.valueOf(42)));
    }

    public void testG1EquivalenceOnSmallScalars()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        for (int k = 1; k <= 8; ++k)
        {
            BigInteger scalar = BigInteger.valueOf(k);
            assertEquals("G1 constant-time vs variable-time, k=" + k,
                g.multiply(scalar).normalize(),
                BLS12_381G1.constantTimeMultiply(g, scalar));
        }
    }

    public void testG1EquivalenceOnRandomScalars()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        for (int trial = 0; trial < 3; ++trial)
        {
            BigInteger scalar = new BigInteger(255, RNG).mod(BLS12_381G1.ORDER);
            if (scalar.signum() == 0)
            {
                continue;
            }
            assertEquals("G1 constant-time vs variable-time, random #" + trial,
                g.multiply(scalar).normalize(),
                BLS12_381G1.constantTimeMultiply(g, scalar));
        }
    }

    public void testG1InfinityPoint()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint result = BLS12_381G1.constantTimeMultiply(curve.getInfinity(), BigInteger.valueOf(99));
        assertTrue("any scalar * infinity == infinity", result.isInfinity());
    }

    /**
     * Coarse timing-stability smoke test — for any two scalars of the
     * same bit length the constant-time multiply should take comparable
     * time. Specifically, low-Hamming-weight (worst case for vanilla
     * double-and-add) and high-Hamming-weight should be within a small
     * factor of each other. We don't assert tight bounds because Java
     * timing is noisy (JIT, GC, cache); we just assert they're not
     * &gt; 5x apart, which would indicate a very obvious bit-pattern leak.
     */
    public void testG2ConstantTimeSmokeCheck()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        // Warm up JIT.
        for (int i = 0; i < 3; ++i)
        {
            g.constantTimeMultiply(BigInteger.valueOf(i + 2));
        }

        BigInteger lowHw = BigInteger.ONE.shiftLeft(200);   // single bit at position 200
        BigInteger highHw = BLS12_381G1.ORDER.subtract(BigInteger.ONE);

        long lowStart = System.nanoTime();
        g.constantTimeMultiply(lowHw);
        long lowElapsed = System.nanoTime() - lowStart;

        long highStart = System.nanoTime();
        g.constantTimeMultiply(highHw);
        long highElapsed = System.nanoTime() - highStart;

        long ratio = Math.max(lowElapsed, highElapsed) / Math.max(1, Math.min(lowElapsed, highElapsed));
        assertTrue("constant-time multiply timing must not vary > 5x with Hamming weight (got "
                + lowElapsed + " vs " + highElapsed + " ns, ratio=" + ratio + ")",
            ratio < 5);
    }
}
