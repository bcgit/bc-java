package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381Pairing;
import org.bouncycastle.crypto.bls.Fp12Element;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Bilinearity-based correctness tests for the BLS12-381 optimal ate pairing.
 * <p>
 * Without external KAT vectors at hand, these tests validate the pairing
 * via its defining algebraic properties:
 * <ul>
 *   <li>Identity: {@code e(O, Q) == 1} and {@code e(P, O) == 1}.</li>
 *   <li>Non-degeneracy: {@code e(G1, G2) != 1}.</li>
 *   <li>Subgroup membership: {@code e(P, Q)^r == 1} (output is in GT, the
 *       order-r subgroup of Fp^12).</li>
 *   <li>Bilinearity in G1: {@code e(a*P, Q) == e(P, Q)^a}.</li>
 *   <li>Bilinearity in G2: {@code e(P, b*Q) == e(P, Q)^b}.</li>
 *   <li>Full bilinearity: {@code e(a*P, b*Q) == e(P, Q)^(a*b)}.</li>
 *   <li>Symmetry of the bilinear pairing in this swap pattern:
 *       {@code e(a*P, Q) == e(P, a*Q)}.</li>
 * </ul>
 * Together these uniquely identify a non-degenerate bilinear pairing on
 * G1 x G2 -> GT up to a constant factor; correctness of the constant factor
 * (which depends on the twist convention) requires comparing against an
 * external reference and is left to a follow-on slice that adds KAT
 * vectors.
 */
public class BLS12_381PairingTest
    extends TestCase
{
    private static ECPoint g1Generator()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        return BLS12_381G1.getGenerator(curve);
    }

    public void testIdentityG1()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint o = curve.getInfinity();
        Fp12Element e = BLS12_381Pairing.pair(o, BLS12_381G2.getGenerator());
        assertEquals(Fp12Element.ONE, e);
    }

    public void testIdentityG2()
    {
        Fp12Element e = BLS12_381Pairing.pair(g1Generator(), BLS12_381G2Point.INFINITY);
        assertEquals(Fp12Element.ONE, e);
    }

    public void testNonDegeneracy()
    {
        Fp12Element e = BLS12_381Pairing.pair(g1Generator(), BLS12_381G2.getGenerator());
        assertFalse("e(G1, G2) must not be 1 (pairing is non-degenerate)", Fp12Element.ONE.equals(e));
    }

    public void testGtSubgroupMembership()
    {
        // e(G1, G2)^r == 1 — output of the pairing lives in the order-r
        // subgroup GT of Fp^12. This is the strongest single-pairing test
        // of the final exponentiation.
        Fp12Element e = BLS12_381Pairing.pair(g1Generator(), BLS12_381G2.getGenerator());
        Fp12Element ePowR = e.modPow(BLS12_381G1.ORDER);
        assertEquals("e(G1, G2)^r must be 1 (pairing output is in GT)",
            Fp12Element.ONE, ePowR);
    }

    /**
     * Confirms the Hayashida-Hayasaka-Teruya {@code /3} hard-part chain
     * produces the canonical {@code f^((p^4 - p^2 + 1) / r)} (no cube
     * factor), by direct comparison against a naive
     * {@link Fp12Element#modPow} on the full hard exponent. Catches any
     * algebra error in the chain that would otherwise hide behind
     * bilinearity (which holds even when the pairing differs from
     * canonical by a fixed power coprime to r).
     */
    public void testHardPartMatchesNaiveModPow()
    {
        // Apply the easy part first so the input lives in the cyclotomic
        // subgroup, then compare chain vs. modPow on the hard exponent.
        // Use a fixed pseudorandom Fp12 element so the test is reproducible.
        java.security.SecureRandom rng = new java.security.SecureRandom(new byte[]{77});
        java.math.BigInteger p = org.bouncycastle.crypto.bls.Fp2Element.P;
        org.bouncycastle.crypto.bls.Fp2Element a0 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a1 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a2 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp6Element c0 = org.bouncycastle.crypto.bls.Fp6Element.of(a0, a1, a2);
        org.bouncycastle.crypto.bls.Fp2Element a3 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a4 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a5 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp6Element c1 = org.bouncycastle.crypto.bls.Fp6Element.of(a3, a4, a5);
        Fp12Element raw = Fp12Element.of(c0, c1);

        // Apply easy part: raw^(p^6 - 1)(p^2 + 1).
        Fp12Element f1 = raw.conjugate().mul(raw.inverse());
        Fp12Element easy = f1.frobeniusSquared().mul(f1);

        Fp12Element chain = BLS12_381Pairing.hardPart(easy);
        Fp12Element direct = easy.modPow(BLS12_381Pairing.HARD_EXPONENT);
        assertEquals("hardPart chain must produce canonical f^hard_exp", direct, chain);
    }

    public void testBilinearityInG1()
    {
        BigInteger a = BigInteger.valueOf(7);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p.multiply(a), q);
        Fp12Element rhs = BLS12_381Pairing.pair(p, q).modPow(a);
        assertEquals("e(a*P, Q) must equal e(P, Q)^a", rhs, lhs);
    }

    public void testBilinearityInG2()
    {
        BigInteger b = BigInteger.valueOf(11);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p, q.multiply(b));
        Fp12Element rhs = BLS12_381Pairing.pair(p, q).modPow(b);
        assertEquals("e(P, b*Q) must equal e(P, Q)^b", rhs, lhs);
    }

    public void testFullBilinearity()
    {
        BigInteger a = BigInteger.valueOf(5);
        BigInteger b = BigInteger.valueOf(13);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p.multiply(a), q.multiply(b));
        Fp12Element rhs = BLS12_381Pairing.pair(p, q).modPow(a.multiply(b));
        assertEquals("e(a*P, b*Q) must equal e(P, Q)^(a*b)", rhs, lhs);
    }

    public void testScalarSwap()
    {
        // e(a*P, Q) == e(P, a*Q) — both equal e(P, Q)^a.
        BigInteger a = BigInteger.valueOf(17);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p.multiply(a), q);
        Fp12Element rhs = BLS12_381Pairing.pair(p, q.multiply(a));
        assertEquals("e(a*P, Q) must equal e(P, a*Q)", rhs, lhs);
    }

    // ---------------------------------------------------------------------
    // multiPair edge cases (review gap G11).
    //
    // The verify paths transitively exercise multiPair with one or two
    // (g1, g2) pairs, but the documented edge cases (length mismatch,
    // all inputs infinity, mixed infinity) aren't tested directly.
    // Each affects whether aggregate-verify produces correct results
    // for malformed or degenerate input lists.
    // ---------------------------------------------------------------------

    public void testMultiPairRejectsLengthMismatch()
    {
        ECPoint g1 = g1Generator();
        BLS12_381G2Point g2 = BLS12_381G2.getGenerator();
        try
        {
            BLS12_381Pairing.multiPair(
                new ECPoint[]{g1, g1},
                new BLS12_381G2Point[]{g2});
            fail("g1/g2 length mismatch must throw");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testMultiPairAllInfinityReturnsOne()
    {
        // Per BLS12_381Pairing.multiPair javadoc: pairs whose G1 or G2
        // component is the point at infinity are skipped, and an
        // all-infinity input list returns the GT identity.
        ECCurve curve = BLS12_381G1.createCurve();
        Fp12Element result = BLS12_381Pairing.multiPair(
            new ECPoint[]{curve.getInfinity(), curve.getInfinity()},
            new BLS12_381G2Point[]{BLS12_381G2Point.INFINITY, BLS12_381G2Point.INFINITY});
        assertEquals("all-infinity multiPair must return GT identity",
            Fp12Element.ONE, result);
    }

    public void testMultiPairMixedInfinitySkips()
    {
        // (g1, g2) + (infinity, q) + (p, infinity) should equal e(g1, g2)
        // alone, because the two infinity pairs are skipped.
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g1 = g1Generator();
        BLS12_381G2Point g2 = BLS12_381G2.getGenerator();

        Fp12Element pure = BLS12_381Pairing.pair(g1, g2);
        Fp12Element padded = BLS12_381Pairing.multiPair(
            new ECPoint[]{g1, curve.getInfinity(), g1.multiply(BigInteger.valueOf(3))},
            new BLS12_381G2Point[]{g2, g2, BLS12_381G2Point.INFINITY});
        assertEquals("interleaved-infinity multiPair must equal the non-infinity-only product",
            pure, padded);
    }
}
