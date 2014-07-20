package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;
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
import org.bouncycastle.util.Times;

/**
 * Compares the performance of the the window NAF point multiplication against conventional point
 * multiplication.
 */
public class ECPointPerformanceTest extends TestCase
{
    static final int MILLIS_PER_ROUND = 200;
    static final int MILLIS_WARMUP = 1000;

    static final int MULTS_PER_CHECK = 16;
    static final int NUM_ROUNDS = 10;

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

                boolean defaultCoord = (c.getCoordinateSystem() == coord);
                if (!defaultCoord)
                {
                    c = C.configure().setCoordinateSystem(coord).create();
                    g = c.importPoint(G);
                }

                double avgRate = randMult(random, g, n);
                String coordName = COORD_NAMES[coord];
                StringBuffer sb = new StringBuffer();
                sb.append("   ");
                sb.append(defaultCoord ? '*' : ' ');
                sb.append(coordName);
                for (int j = sb.length(); j < 30; ++j)
                {
                    sb.append(' ');
                }
                sb.append(": ");
                sb.append(avgRate);
                sb.append(" mults/sec");
                for (int j = sb.length(); j < 64; ++j)
                {
                    sb.append(' ');
                }
                sb.append('(');
                sb.append(1000.0 / avgRate);
                sb.append(" millis/mult)");
                System.out.println(sb.toString());
            }
        }
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

        {
            long startTime = Times.nanoTime();
            long goalTime = startTime + 1000000L * MILLIS_WARMUP;

            do
            {
                BigInteger k = ks[ki];
                p = g.multiply(k);
                if ((ki & 1) != 0)
                {
                    g = p;
                }
                if (++ki == ks.length)
                {
                    ki = 0;
                }
            }
            while (Times.nanoTime() < goalTime);
        }

        double minRate = Double.MAX_VALUE, maxRate = Double.MIN_VALUE, totalRate = 0.0;

        for (int i = 1; i <= NUM_ROUNDS; i++)
        {
            long startTime = Times.nanoTime();
            long goalTime = startTime + 1000000L * MILLIS_PER_ROUND;
            long count = 0, endTime;

            do
            {
                ++count;

                for (int j = 0; j < MULTS_PER_CHECK; ++j)
                {
                    BigInteger k = ks[ki];
                    p = g.multiply(k);
                    if ((ki & 1) != 0)
                    {
                        g = p;
                    }
                    if (++ki == ks.length)
                    {
                        ki = 0;
                    }
                }

                endTime = Times.nanoTime();
            }
            while (endTime < goalTime);

            double roundElapsed = (double)(endTime - startTime);
            double roundRate = count * MULTS_PER_CHECK * 1000000000L / roundElapsed;

            minRate = Math.min(minRate, roundRate);
            maxRate = Math.max(maxRate, roundRate);
            totalRate += roundRate;
        }

        return (totalRate - minRate - maxRate) / (NUM_ROUNDS - 2);
    }

    public void testMultiply() throws Exception
    {
        SortedSet names = new TreeSet(AllTests.enumToList(ECNamedCurveTable.getNames()));
        names.addAll(AllTests.enumToList(CustomNamedCurves.getNames()));

        Set oids = new HashSet();

        Iterator it = names.iterator();
        while (it.hasNext())
        {
            String name = (String)it.next();
            ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(name);
            if (oid == null)
            {
                oid = CustomNamedCurves.getOID(name);
            }
            if (oid != null && !oids.add(oid))
            {
                continue;
            }

            randMult(name);
        }
    }
}
