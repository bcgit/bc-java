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
}
