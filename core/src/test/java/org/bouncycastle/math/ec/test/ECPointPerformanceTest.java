package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WNafMultiplier;

/**
 * Compares the performance of the the window NAF point multiplication against
 * conventional point multiplication.
 */
public class ECPointPerformanceTest extends TestCase
{
    public static final int PRE_ROUNDS = 10;
    public static final int NUM_ROUNDS = 100;

    private void randMult(final String curveName) throws Exception
    {
        final X9ECParameters spec = SECNamedCurves.getByName(curveName);
        ECCurve c = spec.getCurve();
        ECPoint g = (ECPoint) spec.getG();

        final BigInteger n = spec.getN();

        if (c instanceof ECCurve.Fp && c.getCoordinateSystem() != ECCurve.COORD_JACOBIAN
            && c.supportsCoordinateSystem(ECCurve.COORD_JACOBIAN))
        {
            c = c.configure()
                .setCoordinateSystem(ECCurve.COORD_JACOBIAN)
                .setMultiplier(new WNafMultiplier())
                .create();

            g = c.createPoint(g.getX().toBigInteger(), g.getY().toBigInteger());
        }

        final SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        final BigInteger k = new BigInteger(n.bitLength() - 1, random);

        ECPoint qMultiply = null;
        for (int i = 0; i < PRE_ROUNDS; i++)
        {
            qMultiply = g.multiply(k);
        }
        long startTime = System.currentTimeMillis();
        for (int i = 0; i < NUM_ROUNDS; i++)
        {
            qMultiply = g.multiply(k);
        }
        long endTime = System.currentTimeMillis();

        double avgDuration = (double) (endTime - startTime) / NUM_ROUNDS;
        System.out.println(curveName);
        System.out.print("Millis   : ");
        System.out.println(avgDuration);
        System.out.println();
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
    }

    // public static void main(String argv[]) throws Exception
    // {
    // ECMultiplyPerformanceTest test = new ECMultiplyPerformanceTest();
    // test.testMultiply();
    // }
}
