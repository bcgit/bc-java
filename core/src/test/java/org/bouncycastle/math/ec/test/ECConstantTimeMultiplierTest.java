package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstantTimeMultiplier;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/**
 * Differential tests for {@link ECConstantTimeMultiplier}.
 * <p>
 * The multiplier exists to remove a timing side channel, not to compute anything new, so its
 * output must agree exactly with the existing multipliers for every scalar. That is what is
 * checked here, against {@link ECAlgorithms#referenceMultiply} (plain double-and-add) and against
 * whatever multiplier the curve is configured with, across every named curve - which covers the
 * Fp custom curves, the generic Fp curves, the binary (F2m) curves, and the GLV curve secp256k1
 * whose endomorphism this multiplier deliberately bypasses.
 * <p>
 * The scalars are not only random: the recoding forces the scalar odd, splits it into fixed-width
 * signed odd digits and relies on no digit being zero and on the accumulator never colliding with
 * a table entry, so the boundary values below (1, 2, order-1, powers of two, values either side of
 * a window boundary) are the cases most likely to break those assumptions.
 */
public class ECConstantTimeMultiplierTest
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int RANDOM_TESTS_PER_CURVE = 5;

    public void testAgainstReferenceOnAllNamedCurves()
    {
        Set names = new HashSet(enumToList(ECNamedCurveTable.getNames()));
        names.addAll(enumToList(CustomNamedCurves.getNames()));

        int curves = 0;
        for (Iterator it = names.iterator(); it.hasNext(); )
        {
            String name = (String)it.next();

            X9ECParameters x9 = CustomNamedCurves.getByName(name);
            if (x9 == null)
            {
                x9 = ECNamedCurveTable.getByName(name);
            }
            if (x9 == null || x9.getCurve().getOrder() == null)
            {
                continue;
            }

            ++curves;
            checkCurve(name, x9);
        }

        assertTrue("no curves were exercised", curves > 20);
    }

    private void checkCurve(String name, X9ECParameters x9)
    {
        ECConstantTimeMultiplier M = new ECConstantTimeMultiplier();
        BigInteger order = x9.getCurve().getOrder();
        ECPoint g = x9.getG().normalize();

        // a variable point, as a key agreement would see: someone else's public key
        ECPoint peer = g.multiply(new BigInteger(order.bitLength(), RANDOM).mod(order).max(BigInteger.valueOf(2)))
            .normalize();

        List scalars = new ArrayList();
        scalars.add(BigInteger.valueOf(1));
        scalars.add(BigInteger.valueOf(2));
        scalars.add(BigInteger.valueOf(3));
        scalars.add(order.subtract(BigInteger.valueOf(1)));
        scalars.add(order.subtract(BigInteger.valueOf(2)));
        scalars.add(order.shiftRight(1));

        // long runs of zeros and ones, and the window boundaries
        int bits = order.bitLength();
        scalars.add(BigInteger.ONE.shiftLeft(bits - 1));
        scalars.add(BigInteger.ONE.shiftLeft(bits - 1).subtract(BigInteger.ONE));
        for (int w = 3; w <= 7; ++w)
        {
            BigInteger pow = BigInteger.ONE.shiftLeft(w);
            scalars.add(pow);
            scalars.add(pow.subtract(BigInteger.ONE));
            scalars.add(pow.add(BigInteger.ONE));
        }

        for (int i = 0; i < RANDOM_TESTS_PER_CURVE; ++i)
        {
            scalars.add(new BigInteger(order.bitLength(), RANDOM).mod(order).max(BigInteger.ONE));
        }

        for (Iterator it = scalars.iterator(); it.hasNext(); )
        {
            BigInteger k = (BigInteger)it.next();
            if (k.signum() <= 0 || k.compareTo(order) >= 0)
            {
                continue;
            }

            // against plain double-and-add, and against the curve's own configured multiplier
            ECPoint expected = ECAlgorithms.referenceMultiply(peer, k).normalize();
            ECPoint actual = M.multiply(peer, k).normalize();
            ECPoint viaDefault = peer.multiply(k).normalize();

            assertEquals(name + " reference vs constant-time, k=" + k.toString(16), expected, actual);
            assertEquals(name + " default vs constant-time, k=" + k.toString(16), viaDefault, actual);

            // and through the public entry point
            assertEquals(name + " multiplySecret, k=" + k.toString(16),
                expected, ECAlgorithms.multiplySecret(peer, k).normalize());
        }
    }

    /**
     * The base point is a legitimate input too, even though the fixed-base comb would normally be
     * used for it - a caller cannot be assumed to know which point it holds.
     */
    public void testBasePoint()
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("secp256r1");
        ECPoint g = x9.getG().normalize();
        BigInteger order = x9.getCurve().getOrder();

        for (int i = 0; i < 20; ++i)
        {
            BigInteger k = new BigInteger(order.bitLength(), RANDOM).mod(order).max(BigInteger.ONE);
            assertEquals(ECAlgorithms.referenceMultiply(g, k).normalize(),
                ECAlgorithms.multiplySecret(g, k).normalize());
        }
    }

    public void testSignAndInfinityHandling()
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("secp256r1");
        ECPoint g = x9.getG().normalize();
        ECConstantTimeMultiplier M = new ECConstantTimeMultiplier();

        // the AbstractECMultiplier contract: zero scalar and infinite point both give infinity,
        // and a negative scalar negates the result
        assertTrue(M.multiply(g, BigInteger.ZERO).isInfinity());
        assertTrue(M.multiply(g.getCurve().getInfinity(), BigInteger.valueOf(7)).isInfinity());

        BigInteger k = BigInteger.valueOf(1234567);
        assertEquals(M.multiply(g, k).negate().normalize(), M.multiply(g, k.negate()).normalize());
    }

    /**
     * The subgroup precondition, pinned: the odd-forcing step computes (k + n)P in place of an
     * even kP, which is the same point exactly when the order of P divides n. For a point
     * outside the order-n subgroup the result therefore differs from plain multiplication by nP
     * on even scalars - deliberate, documented behaviour, asserted here so a change to the
     * recoding shows up. sect163k1 (cofactor 2) supplies both an order-2 point - (0, 1), since
     * y^2 + xy = x^3 + x^2 + 1 forces y = 1 at x = 0 - and a full-order point, G + (0, 1).
     */
    public void testOutOfSubgroupPointSemantics()
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("sect163k1");
        ECCurve curve = x9.getCurve();
        BigInteger n = curve.getOrder();

        ECPoint T = curve.createPoint(BigIntegers.ZERO, BigIntegers.ONE);
        assertTrue("(0, 1) should have order 2", T.twice().isInfinity() && !T.isInfinity());

        ECPoint[] points = new ECPoint[]{ T, x9.getG().add(T).normalize() };

        List scalars = new ArrayList();
        scalars.add(BigIntegers.TWO);
        scalars.add(BigInteger.valueOf(4));
        scalars.add(n.subtract(BigIntegers.ONE));
        scalars.add(BigInteger.valueOf(5));
        for (int i = 0; i < RANDOM_TESTS_PER_CURVE; ++i)
        {
            scalars.add(new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigIntegers.ONE));
        }

        for (int i = 0; i != points.length; ++i)
        {
            ECPoint p = points[i];
            for (Iterator it = scalars.iterator(); it.hasNext(); )
            {
                BigInteger k = (BigInteger)it.next();

                // what the multiplier is documented to compute: kP for odd k, (k + n)P for even
                BigInteger kOdd = k.testBit(0) ? k : k.add(n);
                ECPoint expected = ECAlgorithms.referenceMultiply(p, kOdd).normalize();

                assertEquals("point " + i + ", k=" + k.toString(16),
                    expected, ECAlgorithms.multiplySecret(p, k).normalize());
            }
        }
    }

    public void testRejectsEvenOrder()
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("secp256r1");
        ECPoint g = x9.getG().normalize();

        try
        {
            // an even order would break the odd-forcing silently, so it must be refused loudly
            ECAlgorithms.multiplySecret(g, BigInteger.valueOf(7), x9.getN().add(BigIntegers.ONE));
            fail("expected rejection of an even group order");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    public void testRejectsScalarLargerThanOrder()
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("secp256r1");
        ECPoint g = x9.getG().normalize();

        try
        {
            ECAlgorithms.multiplySecret(g, x9.getCurve().getOrder().shiftLeft(1));
            fail("expected rejection of a scalar wider than the order");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    private static List enumToList(Enumeration en)
    {
        List rv = new ArrayList();
        while (en.hasMoreElements())
        {
            rv.add(en.nextElement());
        }
        return rv;
    }
}
