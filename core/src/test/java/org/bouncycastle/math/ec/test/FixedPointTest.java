package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class FixedPointTest
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int TESTS_PER_CURVE = 5;

    public void testFixedPointMultiplier()
    {
        final FixedPointCombMultiplier M = new FixedPointCombMultiplier();

        Set names = new HashSet(enumToList(ECNamedCurveTable.getNames()));
        names.addAll(enumToList(CustomNamedCurves.getNames()));

        Iterator it = names.iterator();
        while (it.hasNext())
        {
            String name = (String)it.next();

            X9ECParameters x9A = ECNamedCurveTable.getByName(name);
            X9ECParameters x9B = CustomNamedCurves.getByName(name);

            X9ECParameters x9 = x9B != null ? x9B : x9A;

            for (int i = 0; i < TESTS_PER_CURVE; ++i)
            {
                BigInteger k = new BigInteger(x9.getN().bitLength(), RANDOM);
                ECPoint pRef = ECAlgorithms.referenceMultiply(x9.getG(), k);

                if (x9A != null)
                {
                    ECPoint pA = M.multiply(x9A.getG(), k);
                    assertPointsEqual("Standard curve fixed-point failure", pRef, pA);
                }

                if (x9B != null)
                {
                    ECPoint pB = M.multiply(x9B.getG(), k);
                    assertPointsEqual("Custom curve fixed-point failure", pRef, pB);
                }
            }
        }
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

    private void assertPointsEqual(String message, ECPoint a, ECPoint b)
    {
        // NOTE: We intentionally test points for equality in both directions
        assertEquals(message, a, b);
        assertEquals(message, b, a);
    }

    public static Test suite()
    {
        return new TestSuite(FixedPointTest.class);
    }
}
