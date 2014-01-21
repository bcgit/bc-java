package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Compares the performance of the the window NAF point multiplication against conventional point
 * multiplication.
 */
public class ECPointPerformanceTest extends TestCase
{
    public static final int PRE_ROUNDS = 100;
    public static final int NUM_ROUNDS = 1000;

    private static String[] COORD_NAMES = new String[]{ "AFFINE", "HOMOGENEOUS", "JACOBIAN", "JACOBIAN-CHUDNOVSKY",
        "JACOBIAN-MODIFIED", "LAMBDA-AFFINE", "LAMBDA-PROJECTIVE", "SKEWED" };

    private void randMult(String curveName) throws Exception
    {
        X9ECParameters spec = ECNamedCurveTable.getByName(curveName);
        if (spec != null)
        {
            randMult(curveName, spec);
        }

        spec = CustomNamedCurves.getByName(curveName);
        if (spec != null)
        {
            randMult(curveName + " (custom)", spec);
        }
    }

    private void randMult(String label, X9ECParameters spec) throws Exception
    {
        ECCurve C = spec.getCurve();
        ECPoint G = (ECPoint)spec.getG();
        BigInteger n = spec.getN();

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(System.currentTimeMillis());

        System.out.println(label);

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

                double avgDuration = randMult(random, g, n);
                String coordName = COORD_NAMES[coord];
                StringBuffer sb = new StringBuffer();
                sb.append("  ");
                sb.append(coordName);
                for (int j = coordName.length(); j < 30; ++j)
                {
                    sb.append(' ');
                }
                sb.append(": ");
                sb.append(avgDuration);
                sb.append("ms");
                System.out.println(sb.toString());
            }
        }

        System.out.println();
    }

    private double randMult(SecureRandom random, ECPoint g, BigInteger n) throws Exception
    {
        BigInteger[] ks = new BigInteger[128];
        for (int i = 0; i < ks.length; ++i)
        {
            ks[i] = new BigInteger(n.bitLength() - 1, random);
        }

        int ki = 0;
        ECPoint p = g;
        for (int i = 1; i <= PRE_ROUNDS; i++)
        {
            BigInteger k = ks[ki];
            p = g.multiply(k);
            if (++ki == ks.length)
            {
                ki = 0;
                g = p;
            }
        }
        long startTime = System.currentTimeMillis();
        for (int i = 1; i <= NUM_ROUNDS; i++)
        {
            BigInteger k = ks[ki];
            p = g.multiply(k);
            if (++ki == ks.length)
            {
                ki = 0;
                g = p;
            }
        }
        long endTime = System.currentTimeMillis();

        return (double)(endTime - startTime) / NUM_ROUNDS;
    }

    public void testMultiply() throws Exception
    {
        Set oids = new HashSet();
        SortedSet names = new TreeSet(Collections.list(ECNamedCurveTable.getNames()));
        Iterator it = names.iterator();
        while (it.hasNext())
        {
            String name = (String)it.next();
            ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(name);
            if (oids.add(oid))
            {
                randMult(name);
            }
        }
    }
}
