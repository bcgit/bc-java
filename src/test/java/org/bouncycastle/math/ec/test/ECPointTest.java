package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Test class for {@link org.bouncycastle.math.ec.ECPoint ECPoint}. All
 * literature values are taken from "Guide to elliptic curve cryptography",
 * Darrel Hankerson, Alfred J. Menezes, Scott Vanstone, 2004, Springer-Verlag
 * New York, Inc.
 */
public class ECPointTest extends TestCase
{
    /**
     * Random source used to generate random points
     */
    private SecureRandom secRand = new SecureRandom();

    private ECPointTest.Fp fp = null;

    private ECPointTest.F2m f2m = null;

    /**
     * Nested class containing sample literature values for <code>Fp</code>.
     */
    public static class Fp
    {
        private final BigInteger q = new BigInteger("29");

        private final BigInteger a = new BigInteger("4");

        private final BigInteger b = new BigInteger("20");

        private final ECCurve.Fp curve = new ECCurve.Fp(q, a, b);

        private final ECPoint.Fp infinity = (ECPoint.Fp) curve.getInfinity();

        private final int[] pointSource = { 5, 22, 16, 27, 13, 6, 14, 6 };

        private ECPoint.Fp[] p = new ECPoint.Fp[pointSource.length / 2];

        /**
         * Creates the points on the curve with literature values.
         */
        private void createPoints()
        {
            for (int i = 0; i < pointSource.length / 2; i++)
            {
                ECFieldElement.Fp x = new ECFieldElement.Fp(q, new BigInteger(
                        Integer.toString(pointSource[2 * i])));
                ECFieldElement.Fp y = new ECFieldElement.Fp(q, new BigInteger(
                        Integer.toString(pointSource[2 * i + 1])));
                p[i] = new ECPoint.Fp(curve, x, y);
            }
        }
    }

    /**
     * Nested class containing sample literature values for <code>F2m</code>.
     */
    public static class F2m
    {
        // Irreducible polynomial for TPB z^4 + z + 1
        private final int m = 4;

        private final int k1 = 1;

        // a = z^3
        private final ECFieldElement.F2m aTpb = new ECFieldElement.F2m(m, k1,
                new BigInteger("1000", 2));

        // b = z^3 + 1
        private final ECFieldElement.F2m bTpb = new ECFieldElement.F2m(m, k1,
                new BigInteger("1001", 2));

        private final ECCurve.F2m curve = new ECCurve.F2m(m, k1, aTpb
                .toBigInteger(), bTpb.toBigInteger());

        private final ECPoint.F2m infinity = (ECPoint.F2m) curve.getInfinity();

        private final String[] pointSource = { "0010", "1111", "1100", "1100",
                "0001", "0001", "1011", "0010" };

        private ECPoint.F2m[] p = new ECPoint.F2m[pointSource.length / 2];

        /**
         * Creates the points on the curve with literature values.
         */
        private void createPoints()
        {
            for (int i = 0; i < pointSource.length / 2; i++)
            {
                ECFieldElement.F2m x = new ECFieldElement.F2m(m, k1,
                        new BigInteger(pointSource[2 * i], 2));
                ECFieldElement.F2m y = new ECFieldElement.F2m(m, k1,
                        new BigInteger(pointSource[2 * i + 1], 2));
                p[i] = new ECPoint.F2m(curve, x, y);
            }
        }
    }

    public void setUp()
    {
        fp = new ECPointTest.Fp();
        fp.createPoints();

        f2m = new ECPointTest.F2m();
        f2m.createPoints();
    }

    /**
     * Tests, if inconsistent points can be created, i.e. points with exactly
     * one null coordinate (not permitted).
     */
    public void testPointCreationConsistency()
    {
        try
        {
            ECPoint.Fp bad = new ECPoint.Fp(fp.curve, new ECFieldElement.Fp(
                    fp.q, new BigInteger("12")), null);
            fail();
        }
        catch (IllegalArgumentException expected)
        {
        }

        try
        {
            ECPoint.Fp bad = new ECPoint.Fp(fp.curve, null,
                    new ECFieldElement.Fp(fp.q, new BigInteger("12")));
            fail();
        }
        catch (IllegalArgumentException expected)
        {
        }

        try
        {
            ECPoint.F2m bad = new ECPoint.F2m(f2m.curve, new ECFieldElement.F2m(
                    f2m.m, f2m.k1, new BigInteger("1011")), null);
            fail();
        }
        catch (IllegalArgumentException expected)
        {
        }

        try
        {
            ECPoint.F2m bad = new ECPoint.F2m(f2m.curve, null,
                    new ECFieldElement.F2m(f2m.m, f2m.k1,
                            new BigInteger("1011")));
            fail();
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    /**
     * Tests <code>ECPoint.add()</code> against literature values.
     * 
     * @param p
     *            The array of literature values.
     * @param infinity
     *            The point at infinity on the respective curve.
     */
    private void implTestAdd(ECPoint[] p, ECPoint infinity)
    {
        assertEquals("p0 plus p1 does not equal p2", p[2], p[0].add(p[1]));
        assertEquals("p1 plus p0 does not equal p2", p[2], p[1].add(p[0]));
        for (int i = 0; i < p.length; i++)
        {
            assertEquals("Adding infinity failed", p[i], p[i].add(infinity));
            assertEquals("Adding to infinity failed", p[i], infinity.add(p[i]));
        }
    }

    /**
     * Calls <code>implTestAdd()</code> for <code>Fp</code> and
     * <code>F2m</code>.
     */
    public void testAdd()
    {
        implTestAdd(fp.p, fp.infinity);
        implTestAdd(f2m.p, f2m.infinity);
    }

    /**
     * Tests <code>ECPoint.twice()</code> against literature values.
     * 
     * @param p
     *            The array of literature values.
     */
    private void implTestTwice(ECPoint[] p)
    {
        assertEquals("Twice incorrect", p[3], p[0].twice());
        assertEquals("Add same point incorrect", p[3], p[0].add(p[0]));
    }

    /**
     * Calls <code>implTestTwice()</code> for <code>Fp</code> and
     * <code>F2m</code>.
     */
    public void testTwice()
    {
        implTestTwice(fp.p);
        implTestTwice(f2m.p);
    }

    /**
     * Goes through all points on an elliptic curve and checks, if adding a
     * point <code>k</code>-times is the same as multiplying the point by
     * <code>k</code>, for all <code>k</code>. Should be called for points
     * on very small elliptic curves only.
     * 
     * @param p
     *            The base point on the elliptic curve.
     * @param infinity
     *            The point at infinity on the elliptic curve.
     */
    private void implTestAllPoints(ECPoint p, ECPoint infinity)
    {
        ECPoint adder = infinity;
        ECPoint multiplier = infinity;
        int i = 1;
        do
        {
            adder = adder.add(p);
            multiplier = p.multiply(new BigInteger(Integer.toString(i)));
            assertEquals("Results of add() and multiply() are inconsistent "
                    + i, adder, multiplier);
            i++;
        }
        while (!(adder.equals(infinity)));
    }

    /**
     * Calls <code>implTestAllPoints()</code> for the small literature curves,
     * both for <code>Fp</code> and <code>F2m</code>.
     */
    public void testAllPoints()
    {
        for (int i = 0; i < fp.p.length; i++)
        {
            implTestAllPoints(fp.p[0], fp.infinity);
        }

        for (int i = 0; i < f2m.p.length; i++)
        {
            implTestAllPoints(f2m.p[0], f2m.infinity);
        }
    }

    /**
     * Simple shift-and-add multiplication. Serves as reference implementation
     * to verify (possibly faster) implementations in
     * {@link org.bouncycastle.math.ec.ECPoint ECPoint}.
     * 
     * @param p
     *            The point to multiply.
     * @param k
     *            The multiplier.
     * @return The result of the point multiplication <code>kP</code>.
     */
    private ECPoint multiply(ECPoint p, BigInteger k)
    {
        ECPoint q = p.getCurve().getInfinity();
        int t = k.bitLength();
        for (int i = 0; i < t; i++)
        {
            if (k.testBit(i))
            {
                q = q.add(p);
            }
            p = p.twice();
        }
        return q;
    }

    /**
     * Checks, if the point multiplication algorithm of the given point yields
     * the same result as point multiplication done by the reference
     * implementation given in <code>multiply()</code>. This method chooses a
     * random number by which the given point <code>p</code> is multiplied.
     * 
     * @param p
     *            The point to be multiplied.
     * @param numBits
     *            The bitlength of the random number by which <code>p</code>
     *            is multiplied.
     */
    private void implTestMultiply(ECPoint p, int numBits)
    {
        BigInteger k = new BigInteger(numBits, secRand);
        ECPoint ref = multiply(p, k);
        ECPoint q = p.multiply(k);
        assertEquals("ECPoint.multiply is incorrect", ref, q);
    }

    /**
     * Checks, if the point multiplication algorithm of the given point yields
     * the same result as point multiplication done by the reference
     * implementation given in <code>multiply()</code>. This method tests
     * multiplication of <code>p</code> by every number of bitlength
     * <code>numBits</code> or less.
     * 
     * @param p
     *            The point to be multiplied.
     * @param numBits
     *            Try every multiplier up to this bitlength
     */
    private void implTestMultiplyAll(ECPoint p, int numBits)
    {
        BigInteger bound = BigInteger.valueOf(2).pow(numBits);
        BigInteger k = BigInteger.ZERO;

        do
        {
            ECPoint ref = multiply(p, k);
            ECPoint q = p.multiply(k);
            assertEquals("ECPoint.multiply is incorrect", ref, q);
            k = k.add(BigInteger.ONE);
        }
        while (k.compareTo(bound) < 0);
    }

    /**
     * Tests <code>ECPoint.add()</code> and <code>ECPoint.subtract()</code>
     * for the given point and the given point at infinity.
     * 
     * @param p
     *            The point on which the tests are performed.
     * @param infinity
     *            The point at infinity on the same curve as <code>p</code>.
     */
    private void implTestAddSubtract(ECPoint p, ECPoint infinity)
    {
        assertEquals("Twice and Add inconsistent", p.twice(), p.add(p));
        assertEquals("Twice p - p is not p", p, p.twice().subtract(p));
        assertEquals("p - p is not infinity", infinity, p.subtract(p));
        assertEquals("p plus infinity is not p", p, p.add(infinity));
        assertEquals("infinity plus p is not p", p, infinity.add(p));
        assertEquals("infinity plus infinity is not infinity ", infinity,
                infinity.add(infinity));
    }

    /**
     * Calls <code>implTestAddSubtract()</code> for literature values, both
     * for <code>Fp</code> and <code>F2m</code>.
     */
    public void testAddSubtractMultiplySimple()
    {
        for (int iFp = 0; iFp < fp.pointSource.length / 2; iFp++)
        {
            implTestAddSubtract(fp.p[iFp], fp.infinity);

            // Could be any numBits, 6 is chosen at will
            implTestMultiplyAll(fp.p[iFp], 6);
            implTestMultiplyAll(fp.infinity, 6);
        }

        for (int iF2m = 0; iF2m < f2m.pointSource.length / 2; iF2m++)
        {
            implTestAddSubtract(f2m.p[iF2m], f2m.infinity);

            // Could be any numBits, 6 is chosen at will
            implTestMultiplyAll(f2m.p[iF2m], 6);
            implTestMultiplyAll(f2m.infinity, 6);
        }
    }

    /**
     * Test encoding with and without point compression.
     * 
     * @param p
     *            The point to be encoded and decoded.
     */
    private void implTestEncoding(ECPoint p)
    {
        // Not Point Compression
        ECPoint unCompP;

        // Point compression
        ECPoint compP;

        if (p instanceof ECPoint.Fp)
        {
            unCompP = new ECPoint.Fp(p.getCurve(), p.getX(), p.getY(), false);
            compP = new ECPoint.Fp(p.getCurve(), p.getX(), p.getY(), true);
        }
        else
        {
            unCompP = new ECPoint.F2m(p.getCurve(), p.getX(), p.getY(), false);
            compP = new ECPoint.F2m(p.getCurve(), p.getX(), p.getY(), true);
        }

        byte[] unCompBarr = unCompP.getEncoded();
        ECPoint decUnComp = p.getCurve().decodePoint(unCompBarr);
        assertEquals("Error decoding uncompressed point", p, decUnComp);

        byte[] compBarr = compP.getEncoded();
        ECPoint decComp = p.getCurve().decodePoint(compBarr);
        assertEquals("Error decoding compressed point", p, decComp);
    }

    /**
     * Calls <code>implTestAddSubtract()</code>,
     * <code>implTestMultiply</code> and <code>implTestEncoding</code> for
     * the standard elliptic curves as given in <code>SECNamedCurves</code>.
     */
    public void testAddSubtractMultiplyTwiceEncoding()
    {
        Enumeration curveEnum = SECNamedCurves.getNames();
        while (curveEnum.hasMoreElements())
        {
            String name = (String) curveEnum.nextElement();
            X9ECParameters x9ECParameters = SECNamedCurves.getByName(name);

            BigInteger n = x9ECParameters.getN();

            // The generator is multiplied by random b to get random q
            BigInteger b = new BigInteger(n.bitLength(), secRand);
            ECPoint g = x9ECParameters.getG();
            ECPoint q = g.multiply(b);

            // Get point at infinity on the curve
            ECPoint infinity = x9ECParameters.getCurve().getInfinity();

            implTestAddSubtract(q, infinity);
            implTestMultiply(q, n.bitLength());
            implTestMultiply(infinity, n.bitLength());
            implTestEncoding(q);
        }
    }

    public static Test suite()
    {
        return new TestSuite(ECPointTest.class);
    }
}
