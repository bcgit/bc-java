package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

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

        private final BigInteger n = new BigInteger("38");

        private final BigInteger h = new BigInteger("1");

        private final ECCurve curve = new ECCurve.Fp(q, a, b, n, h);

        private final ECPoint infinity = curve.getInfinity();

        private final int[] pointSource = { 5, 22, 16, 27, 13, 6, 14, 6 };

        private ECPoint[] p = new ECPoint[pointSource.length / 2];

        /**
         * Creates the points on the curve with literature values.
         */
        private void createPoints()
        {
            for (int i = 0; i < pointSource.length / 2; i++)
            {
                p[i] = curve.createPoint(
                    new BigInteger(Integer.toString(pointSource[2 * i])),
                    new BigInteger(Integer.toString(pointSource[2 * i + 1])));
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
        private final BigInteger aTpb = new BigInteger("1000", 2);

        // b = z^3 + 1
        private final BigInteger bTpb = new BigInteger("1001", 2);

        private final BigInteger n = new BigInteger("23");

        private final BigInteger h = new BigInteger("1");

        private final ECCurve.F2m curve = new ECCurve.F2m(m, k1, aTpb, bTpb, n, h);

        private final ECPoint.F2m infinity = (ECPoint.F2m) curve.getInfinity();

        private final String[] pointSource = { "0010", "1111", "1100", "1100",
                "0001", "0001", "1011", "0010" };

        private ECPoint[] p = new ECPoint[pointSource.length / 2];

        /**
         * Creates the points on the curve with literature values.
         */
        private void createPoints()
        {
            for (int i = 0; i < pointSource.length / 2; i++)
            {
                p[i] = curve.createPoint(
                    new BigInteger(pointSource[2 * i], 2),
                    new BigInteger(pointSource[2 * i + 1], 2));
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
            ECPoint bad = fp.curve.createPoint(new BigInteger("12"), null);
            fail();
        }
        catch (IllegalArgumentException expected)
        {
        }

        try
        {
            ECPoint bad = fp.curve.createPoint(null, new BigInteger("12"));
            fail();
        }
        catch (IllegalArgumentException expected)
        {
        }

        try
        {
            ECPoint bad = f2m.curve.createPoint(new BigInteger("1011"), null);
            fail();
        }
        catch (IllegalArgumentException expected)
        {
        }

        try
        {
            ECPoint bad = f2m.curve.createPoint(null, new BigInteger("1011"));
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
        assertPointsEqual("p0 plus p1 does not equal p2", p[2], p[0].add(p[1]));
        assertPointsEqual("p1 plus p0 does not equal p2", p[2], p[1].add(p[0]));
        for (int i = 0; i < p.length; i++)
        {
            assertPointsEqual("Adding infinity failed", p[i], p[i].add(infinity));
            assertPointsEqual("Adding to infinity failed", p[i], infinity.add(p[i]));
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
        assertPointsEqual("Twice incorrect", p[3], p[0].twice());
        assertPointsEqual("Add same point incorrect", p[3], p[0].add(p[0]));
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

    private void implTestThreeTimes(ECPoint[] p)
    {
        ECPoint P = p[0];
        ECPoint _3P = P.add(P).add(P);
        assertPointsEqual("ThreeTimes incorrect", _3P, P.threeTimes());
        assertPointsEqual("TwicePlus incorrect", _3P, P.twicePlus(P));
    }

    /**
     * Calls <code>implTestThreeTimes()</code> for <code>Fp</code> and
     * <code>F2m</code>.
     */
    public void testThreeTimes()
    {
        implTestThreeTimes(fp.p);
        implTestThreeTimes(f2m.p);
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

        BigInteger i = BigInteger.valueOf(1);
        do
        {
            adder = adder.add(p);
            multiplier = p.multiply(i);
            assertPointsEqual("Results of add() and multiply() are inconsistent "
                    + i, adder, multiplier);
            i = i.add(BigInteger.ONE);
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
            implTestAllPoints(fp.p[i], fp.infinity);
        }

        for (int i = 0; i < f2m.p.length; i++)
        {
            implTestAllPoints(f2m.p[i], f2m.infinity);
        }
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
        ECPoint ref = ECAlgorithms.referenceMultiply(p, k);
        ECPoint q = p.multiply(k);
        assertPointsEqual("ECPoint.multiply is incorrect", ref, q);
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
        BigInteger bound = BigInteger.ONE.shiftLeft(numBits);
        BigInteger k = BigInteger.ZERO;

        do
        {
            ECPoint ref = ECAlgorithms.referenceMultiply(p, k);
            ECPoint q = p.multiply(k);
            assertPointsEqual("ECPoint.multiply is incorrect", ref, q);
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
        assertPointsEqual("Twice and Add inconsistent", p.twice(), p.add(p));
        assertPointsEqual("Twice p - p is not p", p, p.twice().subtract(p));
        assertPointsEqual("TwicePlus(p, -p) is not p", p, p.twicePlus(p.negate()));
        assertPointsEqual("p - p is not infinity", infinity, p.subtract(p));
        assertPointsEqual("p plus infinity is not p", p, p.add(infinity));
        assertPointsEqual("infinity plus p is not p", p, infinity.add(p));
        assertPointsEqual("infinity plus infinity is not infinity ", infinity, infinity.add(infinity));
        assertPointsEqual("Twice infinity is not infinity ", infinity, infinity.twice());
    }

    /**
     * Calls <code>implTestAddSubtract()</code> for literature values, both
     * for <code>Fp</code> and <code>F2m</code>.
     */
    public void testAddSubtractMultiplySimple()
    {
        int fpBits = fp.curve.getOrder().bitLength();
        for (int iFp = 0; iFp < fp.pointSource.length / 2; iFp++)
        {
            implTestAddSubtract(fp.p[iFp], fp.infinity);

            implTestMultiplyAll(fp.p[iFp], fpBits);
            implTestMultiplyAll(fp.infinity, fpBits);
        }

        int f2mBits = f2m.curve.getOrder().bitLength();
        for (int iF2m = 0; iF2m < f2m.pointSource.length / 2; iF2m++)
        {
            implTestAddSubtract(f2m.p[iF2m], f2m.infinity);

            implTestMultiplyAll(f2m.p[iF2m], f2mBits);
            implTestMultiplyAll(f2m.infinity, f2mBits);
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
        byte[] unCompBarr = p.getEncoded(false);
        ECPoint decUnComp = p.getCurve().decodePoint(unCompBarr);
        assertPointsEqual("Error decoding uncompressed point", p, decUnComp);

        // Point compression
        byte[] compBarr = p.getEncoded(true);
        ECPoint decComp = p.getCurve().decodePoint(compBarr);
        assertPointsEqual("Error decoding compressed point", p, decComp);
    }

    private void implAddSubtractMultiplyTwiceEncodingTest(ECCurve curve, ECPoint q, BigInteger n)
    {
        // Get point at infinity on the curve
        ECPoint infinity = curve.getInfinity();

        implTestAddSubtract(q, infinity);
        implTestMultiply(q, n.bitLength());
        implTestMultiply(infinity, n.bitLength());

        int logSize = 32 - Integers.numberOfLeadingZeros(curve.getFieldSize() - 1);
        int rounds = Math.max(2, Math.min(10, 32 - 3 * logSize));

        ECPoint p = q;
        for (int i = 0; i < rounds; ++i)
        {
            implTestEncoding(p);
            p = p.twice();
        }
    }

    private void implSqrtTest(ECCurve c)
    {
        if (ECAlgorithms.isFpCurve(c))
        {
            BigInteger p = c.getField().getCharacteristic();
            BigInteger pMinusOne = p.subtract(ECConstants.ONE);
            BigInteger legendreExponent = p.shiftRight(1);

            int count = 0;
            while (count < 10)
            {
                BigInteger nonSquare = BigIntegers.createRandomInRange(ECConstants.TWO, pMinusOne, secRand);
                if (!nonSquare.modPow(legendreExponent, p).equals(ECConstants.ONE))
                {
                    ECFieldElement root = c.fromBigInteger(nonSquare).sqrt();
                    assertNull(root);
                    ++count;
                }
            }
        }
        else if (ECAlgorithms.isF2mCurve(c))
        {
            int m = c.getFieldSize();
            BigInteger x = new BigInteger(m, secRand);
            ECFieldElement fe = c.fromBigInteger(x);
            for (int i = 0; i < 100; ++i)
            {
                ECFieldElement sq = fe.square();
                ECFieldElement check = sq.sqrt();
                assertEquals(fe, check);
                fe = sq;
            }
        }
    }

    private void implValidityTest(ECCurve c, ECPoint g)
    {
        assertTrue(g.isValid());

        if (ECAlgorithms.isF2mCurve(c))
        {
            BigInteger h = c.getCofactor();
            if (null != h)
            {
                if (!h.testBit(0))
                {
                    ECFieldElement sqrtB = c.getB().sqrt();
                    ECPoint order2 = c.createPoint(ECConstants.ZERO, sqrtB.toBigInteger());
                    assertTrue(order2.twice().isInfinity());
                    assertFalse(order2.isValid());
                    ECPoint bad2 = g.add(order2);
                    assertFalse(bad2.isValid());
                    ECPoint good2 = bad2.add(order2);
                    assertTrue(good2.isValid());

                    if (!h.testBit(1))
                    {
                        ECFieldElement L = solveQuadraticEquation(c, c.getA());
                        assertNotNull(L);
                        ECFieldElement T = sqrtB;
                        ECFieldElement x = T.sqrt();
                        ECFieldElement y = T.add(x.multiply(L));
                        ECPoint order4 = c.createPoint(x.toBigInteger(), y.toBigInteger());
                        assertTrue(order4.twice().equals(order2));
                        assertFalse(order4.isValid());
                        ECPoint bad4_1 = g.add(order4);
                        assertFalse(bad4_1.isValid());
                        ECPoint bad4_2 = bad4_1.add(order4);
                        assertFalse(bad4_2.isValid());
                        ECPoint bad4_3 = bad4_2.add(order4);
                        assertFalse(bad4_3.isValid());
                        ECPoint good4 = bad4_3.add(order4);
                        assertTrue(good4.isValid());
                    }
                }
            }
        }
    }

    private void implAddSubtractMultiplyTwiceEncodingTestAllCoords(X9ECParameters x9ECParameters)
    {
        BigInteger n = x9ECParameters.getN();
        ECPoint G = x9ECParameters.getG();
        ECCurve C = x9ECParameters.getCurve();

        int[] coords = ECCurve.getAllCoordinateSystems();
        for (int i = 0; i < coords.length; ++i)
        {
            int coord = coords[i];
            if (C.supportsCoordinateSystem(coord))
            {
                ECCurve c = C;
                ECPoint g = G;

                if (c.getCoordinateSystem() != coord)
                {
                    c = C.configure().setCoordinateSystem(coord).create();
                    g = c.importPoint(G);
                }

                // The generator is multiplied by random b to get random q
                BigInteger b = new BigInteger(n.bitLength(), secRand);
                ECPoint q = g.multiply(b).normalize();

                implAddSubtractMultiplyTwiceEncodingTest(c, q, n);

                implSqrtTest(c);

                implValidityTest(c, g);
            }
        }
    }

    /**
     * Calls <code>implTestAddSubtract()</code>,
     * <code>implTestMultiply</code> and <code>implTestEncoding</code> for
     * the standard elliptic curves as given in <code>SECNamedCurves</code>.
     */
    public void testAddSubtractMultiplyTwiceEncoding()
    {
        Set names = new HashSet(enumToList(ECNamedCurveTable.getNames()));
        names.addAll(enumToList(CustomNamedCurves.getNames()));

        Iterator it = names.iterator();
        while (it.hasNext())
        {
            String name = (String)it.next();

            X9ECParameters x9A = ECNamedCurveTable.getByName(name);
            X9ECParameters x9B = CustomNamedCurves.getByName(name);

            if (x9A != null && x9B != null)
            {
                assertEquals(x9A.getCurve().getField(), x9B.getCurve().getField());
                assertEquals(x9A.getCurve().getA().toBigInteger(), x9B.getCurve().getA().toBigInteger());
                assertEquals(x9A.getCurve().getB().toBigInteger(), x9B.getCurve().getB().toBigInteger());
                assertOptionalValuesAgree(x9A.getCurve().getCofactor(), x9B.getCurve().getCofactor());
                assertOptionalValuesAgree(x9A.getCurve().getOrder(), x9B.getCurve().getOrder());

                assertPointsEqual("Custom curve base-point inconsistency", x9A.getG(), x9B.getG());

                assertEquals(x9A.getH(), x9B.getH());
                assertEquals(x9A.getN(), x9B.getN());
                assertOptionalValuesAgree(x9A.getSeed(), x9B.getSeed());

                BigInteger k = new BigInteger(x9A.getN().bitLength(), secRand);
                ECPoint pA = x9A.getG().multiply(k);
                ECPoint pB = x9B.getG().multiply(k);
                assertPointsEqual("Custom curve multiplication inconsistency", pA, pB);
            }

            if (x9A != null)
            {
                implAddSubtractMultiplyTwiceEncodingTestAllCoords(x9A);
            }

            if (x9B != null)
            {
                implAddSubtractMultiplyTwiceEncodingTestAllCoords(x9B);
            }
        }
    }

    public void testExampleFpB0() throws Exception
    {
        /*
         * The supersingular curve y^2 = x^3 - 3.x (i.e. with 'B' == 0) from RFC 6508 2.1, with
         * curve parameters from RFC 6509 Appendix A.
         */
        BigInteger p = fromHex(
              "997ABB1F0A563FDA65C61198DAD0657A"
            + "416C0CE19CB48261BE9AE358B3E01A2E"
            + "F40AAB27E2FC0F1B228730D531A59CB0"
            + "E791B39FF7C88A19356D27F4A666A6D0"
            + "E26C6487326B4CD4512AC5CD65681CE1"
            + "B6AFF4A831852A82A7CF3C521C3C09AA"
            + "9F94D6AF56971F1FFCE3E82389857DB0"
            + "80C5DF10AC7ACE87666D807AFEA85FEB");
        BigInteger a = p.subtract(BigInteger.valueOf(3));
        BigInteger b = BigInteger.valueOf(0);
        byte[] S = null;
        BigInteger n = p.add(BigInteger.valueOf(1)).shiftRight(2);
        BigInteger h = BigInteger.valueOf(4);

        ECCurve curve = configureCurve(new ECCurve.Fp(p, a, b, n, h));

        X9ECPoint G = configureBasepoint(curve, "04"
            // Px
            + "53FC09EE332C29AD0A7990053ED9B52A"
            + "2B1A2FD60AEC69C698B2F204B6FF7CBF"
            + "B5EDB6C0F6CE2308AB10DB9030B09E10"
            + "43D5F22CDB9DFA55718BD9E7406CE890"
            + "9760AF765DD5BCCB337C86548B72F2E1"
            + "A702C3397A60DE74A7C1514DBA66910D"
            + "D5CFB4CC80728D87EE9163A5B63F73EC"
            + "80EC46C4967E0979880DC8ABEAE63895"
            // Py
            + "0A8249063F6009F1F9F1F0533634A135"
            + "D3E82016029906963D778D821E141178"
            + "F5EA69F4654EC2B9E7F7F5E5F0DE55F6"
            + "6B598CCF9A140B2E416CFF0CA9E032B9"
            + "70DAE117AD547C6CCAD696B5B7652FE0"
            + "AC6F1E80164AA989492D979FC5A4D5F2"
            + "13515AD7E9CB99A980BDAD5AD5BB4636"
            + "ADB9B5706A67DCDE75573FD71BEF16D7");

        X9ECParameters x9 = new X9ECParameters(curve, G, n, h, S);

        implAddSubtractMultiplyTwiceEncodingTestAllCoords(x9);
    }

    private void assertPointsEqual(String message, ECPoint a, ECPoint b)
    {
        // NOTE: We intentionally test points for equality in both directions
        assertEquals(message, a, b);
        assertEquals(message, b, a);
    }

    private void assertOptionalValuesAgree(Object a, Object b)
    {
        if (a != null && b != null)
        {
            assertEquals(a, b);
        }
    }

    private void assertOptionalValuesAgree(byte[] a, byte[] b)
    {
        if (a != null && b != null)
        {
            assertTrue(Arrays.areEqual(a, b));
        }
    }

    private static X9ECPoint configureBasepoint(ECCurve curve, String encoding)
    {
        X9ECPoint G = new X9ECPoint(curve, Hex.decode(encoding));
        WNafUtil.configureBasepoint(G.getPoint());
        return G;
    }

    private static ECCurve configureCurve(ECCurve curve)
    {
        return curve;
    }

    private List enumToList(Enumeration en)
    {
        List rv = new ArrayList();

        while (en.hasMoreElements())
        {
            rv.add(en.nextElement());
        }

        return rv;
    }

    private static BigInteger fromHex(
        String hex)
    {
        return new BigInteger(1, Hex.decode(hex));
    }

    private static ECFieldElement solveQuadraticEquation(ECCurve c, ECFieldElement rhs)
    {
        if (rhs.isZero())
        {
            return rhs;
        }

        ECFieldElement gamma, z, zeroElement = c.fromBigInteger(ECConstants.ZERO);

        int m = c.getFieldSize();
        Random rand = new Random();
        do
        {
            ECFieldElement t = c.fromBigInteger(new BigInteger(m, rand));
            z = zeroElement;
            ECFieldElement w = rhs;
            for (int i = 1; i < m; i++)
            {
                ECFieldElement w2 = w.square();
                z = z.square().add(w2.multiply(t));
                w = w2.add(rhs);
            }
            if (!w.isZero())
            {
                return null;
            }
            gamma = z.square().add(z);
        }
        while (gamma.isZero());

        return z;
    }

    public static Test suite()
    {
        return new TestSuite(ECPointTest.class);
    }
}
