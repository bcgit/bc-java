package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.Fp12Element;
import org.bouncycastle.crypto.bls.Fp2Element;
import org.bouncycastle.crypto.bls.Fp6Element;

/**
 * Self-validating field-axiom tests for the BLS12-381 pairing field tower.
 * <p>
 * These tests do not depend on external KAT vectors; they exercise the field
 * laws directly. A correct Fp^6 / Fp^12 implementation must satisfy:
 * <ul>
 *   <li>Ring axioms: associativity, commutativity, distributivity.</li>
 *   <li>Inverse correctness: {@code a * a^-1 == 1}.</li>
 *   <li>Squaring identity: {@code (a + b)^2 == a^2 + 2*a*b + b^2}.</li>
 *   <li>Fermat's little theorem in the relevant field: {@code a^(q-1) == 1}
 *       for nonzero {@code a}, where {@code q == p^6} or {@code p^12}.</li>
 *   <li>Subfield embedding: lifting Fp^2 → Fp^6 → Fp^12 preserves
 *       arithmetic.</li>
 *   <li>Conjugation in Fp^12: {@code conjugate^2 == identity}, and
 *       {@code (a*b).conjugate == a.conjugate * b.conjugate}.</li>
 * </ul>
 * Random elements are drawn from a fixed seed so failures are reproducible.
 */
public class Fp6Fp12Test
    extends TestCase
{
    private static final BigInteger P = Fp2Element.P;
    private static final SecureRandom RNG = new SecureRandom(new byte[]{42});

    private static Fp2Element randomFp2()
    {
        return Fp2Element.of(new BigInteger(P.bitLength(), RNG), new BigInteger(P.bitLength(), RNG));
    }

    private static Fp6Element randomFp6()
    {
        return Fp6Element.of(randomFp2(), randomFp2(), randomFp2());
    }

    private static Fp12Element randomFp12()
    {
        return Fp12Element.of(randomFp6(), randomFp6());
    }

    public void testFp6Add()
    {
        Fp6Element a = randomFp6();
        Fp6Element b = randomFp6();
        // commutativity
        assertEquals(a.add(b), b.add(a));
        // associativity
        Fp6Element c = randomFp6();
        assertEquals(a.add(b).add(c), a.add(b.add(c)));
        // identity
        assertEquals(a, a.add(Fp6Element.ZERO));
        // additive inverse
        assertEquals(Fp6Element.ZERO, a.add(a.neg()));
    }

    public void testFp6MulCommutative()
    {
        Fp6Element a = randomFp6();
        Fp6Element b = randomFp6();
        assertEquals(a.mul(b), b.mul(a));
    }

    public void testFp6MulAssociative()
    {
        Fp6Element a = randomFp6();
        Fp6Element b = randomFp6();
        Fp6Element c = randomFp6();
        assertEquals(a.mul(b).mul(c), a.mul(b.mul(c)));
    }

    public void testFp6Distributive()
    {
        Fp6Element a = randomFp6();
        Fp6Element b = randomFp6();
        Fp6Element c = randomFp6();
        assertEquals(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
    }

    public void testFp6SquareMatchesMul()
    {
        Fp6Element a = randomFp6();
        assertEquals(a.mul(a), a.square());
    }

    public void testFp6SquareOfSum()
    {
        Fp6Element a = randomFp6();
        Fp6Element b = randomFp6();
        Fp6Element ab = a.mul(b);
        Fp6Element expected = a.square().add(ab).add(ab).add(b.square());
        assertEquals(expected, a.add(b).square());
    }

    public void testFp6Inverse()
    {
        Fp6Element a = randomFp6();
        assertEquals(Fp6Element.ONE, a.mul(a.inverse()));
    }

    public void testFp6FermatSubgroupOrder()
    {
        // q^6 = p^6. Pick small subgroup order: a^(p^6 - 1) == 1 for nonzero a.
        Fp6Element a = randomFp6();
        BigInteger qMinus1 = P.pow(6).subtract(BigInteger.ONE);
        assertEquals(Fp6Element.ONE, a.modPow(qMinus1));
    }

    public void testFp6MulByV()
    {
        // a.mulByV() should equal a * (0 + 1*v + 0*v^2)
        Fp6Element a = randomFp6();
        Fp6Element v = Fp6Element.of(Fp2Element.ZERO, Fp2Element.ONE, Fp2Element.ZERO);
        assertEquals(a.mul(v), a.mulByV());
    }

    public void testFp6FromFp2Embedding()
    {
        // A pure Fp2 element a, lifted to Fp6, must commute with everything Fp6.
        Fp2Element a = randomFp2();
        Fp6Element a6 = Fp6Element.fromFp2(a);
        Fp6Element b = randomFp6();
        // Addition lifts: (a + b in Fp6) == fromFp2(a) + b
        assertEquals(b.mulFp2(a), a6.mul(b));
    }

    public void testFp12MulCommutative()
    {
        Fp12Element a = randomFp12();
        Fp12Element b = randomFp12();
        assertEquals(a.mul(b), b.mul(a));
    }

    public void testFp12MulAssociative()
    {
        Fp12Element a = randomFp12();
        Fp12Element b = randomFp12();
        Fp12Element c = randomFp12();
        assertEquals(a.mul(b).mul(c), a.mul(b.mul(c)));
    }

    public void testFp12Distributive()
    {
        Fp12Element a = randomFp12();
        Fp12Element b = randomFp12();
        Fp12Element c = randomFp12();
        assertEquals(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
    }

    public void testFp12SquareMatchesMul()
    {
        Fp12Element a = randomFp12();
        assertEquals(a.mul(a), a.square());
    }

    public void testFp12SquareOfSum()
    {
        Fp12Element a = randomFp12();
        Fp12Element b = randomFp12();
        Fp12Element ab = a.mul(b);
        Fp12Element expected = a.square().add(ab).add(ab).add(b.square());
        assertEquals(expected, a.add(b).square());
    }

    public void testFp12Inverse()
    {
        Fp12Element a = randomFp12();
        assertEquals(Fp12Element.ONE, a.mul(a.inverse()));
    }

    public void testFp12Conjugate()
    {
        Fp12Element a = randomFp12();
        // conjugate^2 == identity
        assertEquals(a, a.conjugate().conjugate());
        // conjugate is an Fp^12 -> Fp^12 ring homomorphism (anti- but this
        // particular involution is a homomorphism for the chosen basis)
        Fp12Element b = randomFp12();
        assertEquals(a.mul(b).conjugate(), a.conjugate().mul(b.conjugate()));
    }

    public void testFp12ConjugateEqualsP6Frobenius()
    {
        // For BLS12-381, conjugating (c0 + c1*w) -> (c0 - c1*w) is exactly
        // raising to the p^6 power, because Frobenius on Fp^12 cycles through
        // the basis and p^6 maps w -> -w (w^p^6 = w * (w^2)^((p^6-1)/2) = w * v^((p^6-1)/2)).
        Fp12Element a = randomFp12();
        BigInteger p6 = P.pow(6);
        assertEquals(a.modPow(p6), a.conjugate());
    }

    public void testFp12FermatSubgroupOrder()
    {
        // a^(p^12 - 1) == 1 for nonzero a in Fp^12.
        Fp12Element a = randomFp12();
        BigInteger qMinus1 = P.pow(12).subtract(BigInteger.ONE);
        assertEquals(Fp12Element.ONE, a.modPow(qMinus1));
    }

    public void testFp6FrobeniusMatchesModPow()
    {
        Fp6Element a = randomFp6();
        assertEquals(a.modPow(P), a.frobenius());
    }

    public void testFp12FrobeniusMatchesModPow()
    {
        Fp12Element a = randomFp12();
        assertEquals(a.modPow(P), a.frobenius());
    }

    public void testFp6FrobeniusSquaredMatchesModPow()
    {
        // frobeniusSquared() is an optimisation: it should equal modPow(p^2).
        Fp6Element a = randomFp6();
        BigInteger pSq = P.pow(2);
        assertEquals(a.modPow(pSq), a.frobeniusSquared());
    }

    public void testFp12FrobeniusSquaredMatchesModPow()
    {
        Fp12Element a = randomFp12();
        BigInteger pSq = P.pow(2);
        assertEquals(a.modPow(pSq), a.frobeniusSquared());
    }

    public void testFp12FromFp6Embedding()
    {
        Fp6Element a = randomFp6();
        Fp6Element b = randomFp6();
        Fp12Element a12 = Fp12Element.fromFp6(a);
        Fp12Element b12 = Fp12Element.fromFp6(b);
        // Embedding is a ring homomorphism.
        assertEquals(Fp12Element.fromFp6(a.mul(b)), a12.mul(b12));
        assertEquals(Fp12Element.fromFp6(a.add(b)), a12.add(b12));
    }

    /**
     * Fp^2 multiplication against the four-product schoolbook formula, including
     * components at the top of the range, where Karatsuba's sums are largest.
     */
    public void testFp2MulMatchesSchoolbook()
    {
        BigInteger[] edge = { BigInteger.ZERO, BigInteger.ONE, P.subtract(BigInteger.ONE),
            P.subtract(BigInteger.valueOf(2)), P.shiftRight(1) };
        for (int i = 0; i < 200; ++i)
        {
            BigInteger a = i < 25 ? edge[i % 5] : new BigInteger(P.bitLength(), RNG).mod(P);
            BigInteger b = i < 25 ? edge[(i / 5) % 5] : new BigInteger(P.bitLength(), RNG).mod(P);
            BigInteger c = i < 25 ? edge[(i + 2) % 5] : new BigInteger(P.bitLength(), RNG).mod(P);
            BigInteger d = i < 25 ? edge[(i / 5 + 3) % 5] : new BigInteger(P.bitLength(), RNG).mod(P);

            Fp2Element r = Fp2Element.of(a, b).mul(Fp2Element.of(c, d));
            assertEquals(a.multiply(c).subtract(b.multiply(d)).mod(P), r.c0());
            assertEquals(a.multiply(d).add(b.multiply(c)).mod(P), r.c1());
        }
    }

    /**
     * The other Fp^2 operations against plain {@code BigInteger.mod} arithmetic,
     * with the same edge components: the reductions are Barrett and conditional
     * add/subtract, whose boundaries sit at 0, p - 1 and products near 2p^2.
     */
    public void testFp2OpsMatchReference()
    {
        BigInteger[] edge = { BigInteger.ZERO, BigInteger.ONE, P.subtract(BigInteger.ONE),
            P.subtract(BigInteger.valueOf(2)), P.shiftRight(1), P.shiftRight(1).add(BigInteger.ONE) };
        for (int i = 0; i < 300; ++i)
        {
            BigInteger a = i < 36 ? edge[i % 6] : new BigInteger(P.bitLength(), RNG).mod(P);
            BigInteger b = i < 36 ? edge[i / 6] : new BigInteger(P.bitLength(), RNG).mod(P);
            BigInteger c = i < 36 ? edge[(i + 1) % 6] : new BigInteger(P.bitLength(), RNG).mod(P);
            BigInteger d = i < 36 ? edge[(i / 6 + 2) % 6] : new BigInteger(P.bitLength(), RNG).mod(P);
            Fp2Element x = Fp2Element.of(a, b), y = Fp2Element.of(c, d);

            assertFp2(a.add(c), b.add(d), x.add(y));
            assertFp2(a.subtract(c), b.subtract(d), x.sub(y));
            assertFp2(a.negate(), b.negate(), x.neg());
            assertFp2(a, b.negate(), x.frobenius());
            assertFp2(a.multiply(a).subtract(b.multiply(b)), a.multiply(b).shiftLeft(1), x.square());
            assertFp2(a.multiply(c), b.multiply(c), x.mulFp(c));
            if (!x.isZero())
            {
                assertEquals(Fp2Element.ONE, x.mul(x.inverse()));
            }
        }
    }

    /**
     * Products whose real part {@code ac - bd} is a large negative number that a
     * Barrett estimate would overshoot unless it is first shifted into range
     * (found by search; about 0.5% of negative values behave this way).
     */
    public void testFp2MulNegativeRealPart()
    {
        String[][] bd = {
            { "1034b24754d7e95bcdc64abf059d4fb5e6d6692c7eddb801227b9144f035e9008e95662c19635ff5159c89bb7ac30d45",
              "1586e31ba768ea288bf2215bdf272b542d1f5560d6335b88f6cc135a7ca53a0fb8e1cc86f1d8644b20c29ee7ffe56e91" },
            { "e30fd7adc5a76fbc00ec8ee9670858f1acccfb1303466b305983da077e4239a1dd341a6cf061749444d56b804270533",
              "ea8e355a1f1010caaa5610c9a3b8107475c43e9b30cac7adc61c0822dd58e270b2d8f0e969a8cf05df04f9981b8f055" } };
        for (int i = 0; i < bd.length; ++i)
        {
            BigInteger b = new BigInteger(bd[i][0], 16), d = new BigInteger(bd[i][1], 16);
            Fp2Element r = Fp2Element.of(BigInteger.ZERO, b).mul(Fp2Element.of(BigInteger.ONE, d));
            assertFp2(b.multiply(d).negate(), b, r);
        }
    }

    private static void assertFp2(BigInteger c0, BigInteger c1, Fp2Element actual)
    {
        assertEquals(c0.mod(P), actual.c0());
        assertEquals(c1.mod(P), actual.c1());
    }

    /**
     * Fp^6 multiplication against the nine-product schoolbook formula with the
     * products by xi = 1 + I done as full Fp^2 multiplications.
     */
    public void testFp6MulMatchesSchoolbook()
    {
        Fp2Element xi = Fp2Element.of(1, 1);
        Fp2Element top = Fp2Element.of(P.subtract(BigInteger.ONE), P.subtract(BigInteger.ONE));
        for (int i = 0; i < 100; ++i)
        {
            Fp6Element a = i == 0 ? Fp6Element.of(top, top, top) : randomFp6();
            Fp6Element b = i == 0 ? Fp6Element.of(top, top, top) : randomFp6();

            Fp2Element r0 = a.c0().mul(b.c0()).add(a.c1().mul(b.c2()).add(a.c2().mul(b.c1())).mul(xi));
            Fp2Element r1 = a.c0().mul(b.c1()).add(a.c1().mul(b.c0())).add(a.c2().mul(b.c2()).mul(xi));
            Fp2Element r2 = a.c0().mul(b.c2()).add(a.c1().mul(b.c1())).add(a.c2().mul(b.c0()));

            assertEquals(Fp6Element.of(r0, r1, r2), a.mul(b));
            assertEquals(a.mul(a), a.square());
            assertEquals(Fp6Element.of(a.c2().mul(xi), a.c0(), a.c1()), a.mulByV());
        }
    }
}
