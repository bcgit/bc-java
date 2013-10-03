package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Compares the performance of the the window NAF point multiplication against
 * conventional point multiplication.
 */
public class ECPointPerformanceTest extends TestCase
{
    public static final int PRE_ROUNDS = 10;
    public static final int NUM_ROUNDS = 100;

    private static String[] COORD_NAMES = new String[]{ "AFFINE", "HOMOGENEOUS", "JACOBIAN", "JACOBIAN-CHUDNOVSKY",
        "JACOBIAN-MODIFIED", "LAMBDA-AFFINE", "LAMBDA-PROJECTIVE", "SKEWED" };

    private void randMult(final String curveName) throws Exception
    {
        X9ECParameters spec = ECNamedCurveTable.getByName(curveName);
        ECCurve C = spec.getCurve();
        ECPoint G = (ECPoint) spec.getG();
        BigInteger n = spec.getN();

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(System.currentTimeMillis());

        System.out.println(curveName);

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

                double avgDuration = randMult(random, c, g, n);
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

    private double randMult(SecureRandom random, ECCurve c, ECPoint g, BigInteger n) throws Exception
    {
        BigInteger k = new BigInteger(n.bitLength() - 1, random);

        ECPoint p = g;
        for (int i = 1; i <= PRE_ROUNDS; i++)
        {
            p = g.multiply(k);
            if (i % 10 == 0)
            {
                g = p;
            }
            k = k.flipBit(i % n.bitLength());
        }
        long startTime = System.currentTimeMillis();
        for (int i = 1; i <= NUM_ROUNDS; i++)
        {
            p = g.multiply(k);
            if (i % 10 == 0)
            {
                g = p;
            }
            k = k.flipBit(i % n.bitLength());
        }
        long endTime = System.currentTimeMillis();

        return (double) (endTime - startTime) / NUM_ROUNDS;
    }

    public void testMultiply() throws Exception
    {
//        Enumeration e = SECNamedCurves.getNames();
//        while (e.hasMoreElements())
//        {
//            String name = (String)e.nextElement();
//            randMult(name);
//        }
        
        randMult("sect163k1");
        randMult("sect163r2");
        randMult("sect233k1");
        randMult("sect233r1");
        randMult("sect283k1");
        randMult("sect283r1");
        randMult("sect409k1");
        randMult("sect409r1");
        randMult("sect571k1");
        randMult("sect571r1");
        randMult("secp224k1");
        randMult("secp224r1");
        randMult("secp256k1");
        randMult("secp256r1");
        randMult("secp384r1");
        randMult("secp521r1");
        
        randMult("brainpoolp160r1");
        randMult("brainpoolp160t1");
        randMult("brainpoolp192r1");
        randMult("brainpoolp192t1");
        randMult("brainpoolp224r1");
        randMult("brainpoolp224t1");
        randMult("brainpoolp256r1");
        randMult("brainpoolp256t1");
        randMult("brainpoolp320r1");
        randMult("brainpoolp320t1");
        randMult("brainpoolp384r1");
        randMult("brainpoolp384t1");
        randMult("brainpoolp512r1");
        randMult("brainpoolp512t1");
    }

    // public static void main(String argv[]) throws Exception
    // {
    // ECMultiplyPerformanceTest test = new ECMultiplyPerformanceTest();
    // test.testMultiply();
    // }
}
