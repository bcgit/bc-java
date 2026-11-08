package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381SubgroupCheck;
import org.bouncycastle.crypto.bls.Fp2Element;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Tests for the Bowe-style fast subgroup-membership checks. The headline
 * test in each direction is "the new fast check agrees with the slow
 * {@code [r] P == 0} test on every input we throw at it" — that's what
 * proves the optimisation is correct.
 */
public class BLS12_381SubgroupCheckTest
    extends TestCase
{
    private static final SecureRandom RNG = new SecureRandom(new byte[]{17});

    public void testG1GeneratorIsInSubgroup()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        assertTrue(BLS12_381SubgroupCheck.isInG1Subgroup(g));
    }

    public void testG1ScalarMultiplesAreInSubgroup()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        for (int k = 1; k <= 6; ++k)
        {
            assertTrue("k=" + k + " * G1 must be in G1",
                BLS12_381SubgroupCheck.isInG1Subgroup(g.multiply(BigInteger.valueOf(k))));
        }
    }

    public void testG1InfinityIsInSubgroup()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        assertTrue(BLS12_381SubgroupCheck.isInG1Subgroup(curve.getInfinity()));
    }

    public void testG1FastCheckAgreesWithSlow()
    {
        // Fast check (sigma(P) == [-x^2] P) must agree with [r] P == 0
        // on the canonical generator and small multiples thereof.
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        for (int k = 0; k < 5; ++k)
        {
            ECPoint p = g.multiply(BigInteger.valueOf(k + 1));
            boolean fast = BLS12_381SubgroupCheck.isInG1Subgroup(p);
            boolean slow = p.multiply(BLS12_381G1.ORDER).isInfinity();
            assertEquals("k=" + k + ": fast and slow checks must agree", slow, fast);
        }
    }

    /**
     * The fast G1 check against {@code [r] P == 0} on points outside the
     * subgroup: random curve points, their components of small order
     * dividing the cofactor h = 3 * 11^2 * 10177^2 * 859267^2 * 52437899^2
     * (orders 3 and 11 make the double-and-add by |x| meet its doubling and
     * inverse cases), and the same points with the cofactor cleared.
     */
    public void testG1FastCheckAgreesWithSlowOffSubgroup()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        BigInteger p = Fp2Element.P;
        BigInteger r = BLS12_381G1.ORDER;
        BigInteger h = curve.getCofactor();
        BigInteger four = BigInteger.valueOf(4);
        int found = 0, rejected = 0;
        while (found < 6)
        {
            BigInteger x = new BigInteger(p.bitLength(), RNG).mod(p);
            BigInteger rhs = x.multiply(x).multiply(x).add(four).mod(p);
            BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
            if (!y.multiply(y).mod(p).equals(rhs))
            {
                continue;
            }
            ++found;
            ECPoint pt = curve.createPoint(x, y);
            ECPoint small = ECAlgorithms.referenceMultiply(pt, r);
            ECPoint order3 = ECAlgorithms.referenceMultiply(small, h.divide(BigInteger.valueOf(3)));
            ECPoint inG1 = ECAlgorithms.referenceMultiply(pt, h);
            ECPoint[] points = { pt, pt.negate(), small, order3,
                ECAlgorithms.referenceMultiply(small, h.divide(BigInteger.valueOf(11))),
                ECAlgorithms.referenceMultiply(small, h.divide(BigInteger.valueOf(121))), inG1, inG1.add(order3) };
            for (int i = 0; i < points.length; ++i)
            {
                ECPoint q = points[i].normalize();
                boolean slow = ECAlgorithms.referenceMultiply(q, r).isInfinity();
                assertEquals("point " + found + "/" + i + ": fast and slow checks must agree", slow,
                    BLS12_381SubgroupCheck.isInG1Subgroup(q));
                if (!slow)
                {
                    ++rejected;
                }
            }
        }
        // pt, -pt and [r]pt are always outside G1. The order-3 multiple vanishes
        // when [r]pt has no 3-part (about a third of points), and the h/11
        // multiple always vanishes, because the 11-torsion of E(Fp) is
        // Z/11 x Z/11, so only these three per point are guaranteed.
        assertTrue(rejected >= 6 * 3);
    }

    public void testG2GeneratorIsInSubgroup()
    {
        assertTrue(BLS12_381SubgroupCheck.isInG2Subgroup(BLS12_381G2.getGenerator()));
    }

    public void testG2ScalarMultiplesAreInSubgroup()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        for (int k = 1; k <= 4; ++k)
        {
            assertTrue("k=" + k + " * G2 must be in G2",
                BLS12_381SubgroupCheck.isInG2Subgroup(g.multiply(BigInteger.valueOf(k))));
        }
    }

    public void testG2InfinityIsInSubgroup()
    {
        assertTrue(BLS12_381SubgroupCheck.isInG2Subgroup(BLS12_381G2Point.INFINITY));
    }

    public void testG2FastCheckAgreesWithSlow()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        for (int k = 0; k < 4; ++k)
        {
            BLS12_381G2Point p = g.multiply(BigInteger.valueOf(k + 1));
            boolean fast = BLS12_381SubgroupCheck.isInG2Subgroup(p);
            boolean slow = p.multiply(BLS12_381G1.ORDER).isInfinity();
            assertEquals("k=" + k + ": fast and slow G2 checks must agree", slow, fast);
        }
    }

    public void testG2RejectsOffSubgroupPoint()
    {
        // Find a point on E'(Fp^2) that is NOT in the prime-order subgroup G2.
        // Strategy: pick random x ∈ Fp^2 with y^2 = x^3 + 4(1+I) solvable,
        // recover y. Statistically the resulting point is in G2 only with
        // probability 1/cofactor (≈ 2^-381), so we'll typically find an
        // off-subgroup point on the first few attempts.
        for (int attempt = 0; attempt < 16; ++attempt)
        {
            BigInteger c0 = new BigInteger(Fp2Element.P.bitLength(), RNG).mod(Fp2Element.P);
            BigInteger c1 = new BigInteger(Fp2Element.P.bitLength(), RNG).mod(Fp2Element.P);
            Fp2Element x = Fp2Element.of(c0, c1);
            Fp2Element rhs = x.square().mul(x).add(BLS12_381G2Point.B);
            Fp2Element y = rhs.sqrtOrNull();
            if (y == null)
            {
                continue;
            }
            BLS12_381G2Point candidate = BLS12_381G2Point.of(x, y);
            // Most random curve points are not in G2 (cofactor is huge).
            // Verify: slow check returns false, fast check must too.
            boolean slow = candidate.multiply(BLS12_381G1.ORDER).isInfinity();
            if (slow)
            {
                // Extremely unlikely; skip and try another.
                continue;
            }
            boolean fast = BLS12_381SubgroupCheck.isInG2Subgroup(candidate);
            assertFalse("off-subgroup G2 point must be rejected by fast check", fast);
            return;
        }
        fail("could not construct an off-subgroup G2 point in 16 attempts");
    }

    public void testSigmaG1IsOnCurve()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        ECPoint sigmaG = BLS12_381SubgroupCheck.sigmaG1(g);
        assertTrue("sigma(G1) must remain on the curve", sigmaG.isValid());
    }

    public void testPsiG2IsOnCurve()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        BLS12_381G2Point psiG = BLS12_381SubgroupCheck.psiG2(g);
        // Verify y^2 == x^3 + 4(1+I) in Fp^2.
        Fp2Element lhs = psiG.y().square();
        Fp2Element rhs = psiG.x().square().mul(psiG.x()).add(BLS12_381G2Point.B);
        assertEquals("psi(G2) must remain on the curve", lhs, rhs);
    }
}
