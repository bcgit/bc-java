package org.bouncycastle.crypto.hash2curve.test.impl;

import junit.framework.TestCase;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.crypto.hash2curve.impl.ShallueVanDeWoestijneMapToCurve;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

public class ShallueVanDeWoestijneMapToCurveTest extends TestCase {



    /*
    This test class is testing the "process" method in "ShallueVanDeWoestijneMapToCurve" class which implements 
    the Shallue van de Woestijne Map to curve according to section 6.6.1 of RFC 9380.
    */

    public void testMapToCurve() throws Exception {
        // Given
        ECCurve p256Curve = new SecP256R1Curve();


        ShallueVanDeWoestijneMapToCurve mapToCurve =
                new ShallueVanDeWoestijneMapToCurve(p256Curve, BigInteger.valueOf(-10));

        specificMappingTestcase(new BigInteger(1, Hex.decode("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")), mapToCurve);
        specificMappingTestcase(new BigInteger(1, Hex.decode("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")), mapToCurve);

//        u0 = new BigInteger("78397231975818298121002851560982570386422970797899025056634496834376049971209");

    }

    void specificMappingTestcase(BigInteger u, MapToCurve mapToCurve) throws  Exception {
        //log.info("Testing to map {}", u.toString(16));
        ECPoint qu = mapToCurve.process(u);
        //log.info("Mapped point X: {}", qu.getXCoord().toBigInteger().toString(16));
        //log.info("Mapped point Y: {}", qu.getYCoord().toBigInteger().toString(16));
    }

}
