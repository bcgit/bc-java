package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381Fp;
import org.bouncycastle.crypto.bls.BLS12_381G1;

/**
 * Field-axiom tests for the limb-based BLS12-381 Fp implementation, plus
 * direct correspondence checks against {@link BigInteger} arithmetic mod p.
 * <p>
 * The high-confidence test is {@link #testCorrespondsToBigInteger}: random
 * inputs are processed both through {@link BLS12_381Fp} and through plain
 * {@code BigInteger} mod-p arithmetic, and the results must agree
 * bit-for-bit. This catches Montgomery-form errors, limb-ordering errors,
 * carry-propagation errors — anything that would cause the two
 * implementations to diverge.
 */
public class BLS12_381FpTest
    extends TestCase
{
    private static final BigInteger P = BLS12_381G1.Q;
    private static final SecureRandom RNG = new SecureRandom(new byte[]{31});

    private static BigInteger randomBigInt()
    {
        return new BigInteger(P.bitLength(), RNG).mod(P);
    }

    private static BLS12_381Fp lift(BigInteger v)
    {
        return BLS12_381Fp.fromBigInteger(v);
    }

    public void testRoundTrip()
    {
        for (int i = 0; i < 8; ++i)
        {
            BigInteger v = randomBigInt();
            assertEquals(v, lift(v).toBigInteger());
        }
    }

    public void testZeroRoundTrip()
    {
        assertEquals(BigInteger.ZERO, BLS12_381Fp.ZERO.toBigInteger());
    }

    public void testOneRoundTrip()
    {
        assertEquals(BigInteger.ONE, BLS12_381Fp.ONE.toBigInteger());
    }

    public void testAddCommutative()
    {
        BLS12_381Fp a = lift(randomBigInt());
        BLS12_381Fp b = lift(randomBigInt());
        assertEquals(a.add(b), b.add(a));
    }

    public void testAddIdentity()
    {
        BLS12_381Fp a = lift(randomBigInt());
        assertEquals(a, a.add(BLS12_381Fp.ZERO));
    }

    public void testAddInverse()
    {
        BLS12_381Fp a = lift(randomBigInt());
        assertEquals(BLS12_381Fp.ZERO, a.add(a.neg()));
    }

    public void testMulCommutative()
    {
        BLS12_381Fp a = lift(randomBigInt());
        BLS12_381Fp b = lift(randomBigInt());
        assertEquals(a.mul(b), b.mul(a));
    }

    public void testMulAssociative()
    {
        BLS12_381Fp a = lift(randomBigInt());
        BLS12_381Fp b = lift(randomBigInt());
        BLS12_381Fp c = lift(randomBigInt());
        assertEquals(a.mul(b).mul(c), a.mul(b.mul(c)));
    }

    public void testMulDistributive()
    {
        BLS12_381Fp a = lift(randomBigInt());
        BLS12_381Fp b = lift(randomBigInt());
        BLS12_381Fp c = lift(randomBigInt());
        assertEquals(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
    }

    public void testMulIdentity()
    {
        BLS12_381Fp a = lift(randomBigInt());
        assertEquals(a, a.mul(BLS12_381Fp.ONE));
    }

    public void testSquareMatchesMul()
    {
        BLS12_381Fp a = lift(randomBigInt());
        assertEquals(a.mul(a), a.square());
    }

    public void testInverse()
    {
        BLS12_381Fp a = lift(randomBigInt());
        assertEquals(BLS12_381Fp.ONE, a.mul(a.inverse()));
    }

    public void testFermat()
    {
        // a^(p-1) == 1 for nonzero a.
        BLS12_381Fp a = lift(randomBigInt());
        assertEquals(BLS12_381Fp.ONE, a.modPow(P.subtract(BigInteger.ONE)));
    }

    /**
     * Cross-check against {@link BigInteger} mod-p arithmetic on random
     * inputs. This is the highest-confidence single test of the
     * implementation: it catches Montgomery-form errors, limb-ordering
     * errors, carry-propagation errors, and any algebraic mistake in
     * {@code add}, {@code sub}, {@code mul}, {@code square}, or {@code inverse}.
     */
    public void testCorrespondsToBigInteger()
    {
        for (int i = 0; i < 16; ++i)
        {
            BigInteger aBig = randomBigInt();
            BigInteger bBig = randomBigInt();
            BLS12_381Fp a = lift(aBig);
            BLS12_381Fp b = lift(bBig);

            assertEquals("add", aBig.add(bBig).mod(P), a.add(b).toBigInteger());
            assertEquals("sub", aBig.subtract(bBig).mod(P), a.sub(b).toBigInteger());
            assertEquals("mul", aBig.multiply(bBig).mod(P), a.mul(b).toBigInteger());
            assertEquals("square", aBig.multiply(aBig).mod(P), a.square().toBigInteger());
            assertEquals("neg", aBig.negate().mod(P), a.neg().toBigInteger());
            if (aBig.signum() != 0)
            {
                assertEquals("inv", aBig.modInverse(P), a.inverse().toBigInteger());
            }
        }
    }
}
