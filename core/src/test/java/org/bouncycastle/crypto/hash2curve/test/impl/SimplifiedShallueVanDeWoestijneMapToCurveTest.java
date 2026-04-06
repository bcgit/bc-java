package org.bouncycastle.crypto.hash2curve.test.impl;

import junit.framework.TestCase;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.crypto.hash2curve.impl.SimplifiedShallueVanDeWoestijneMapToCurve;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

public class SimplifiedShallueVanDeWoestijneMapToCurveTest extends TestCase {



    /*
    This test class is testing the "process" method in "ShallueVanDeWoestijneMapToCurve" class which implements 
    the Shallue van de Woestijne Map to curve according to section 6.6.1 of RFC 9380.
    */

    public void testMapToCurve() throws Exception {
        ECCurve p256Curve = new SecP256R1Curve();

        SimplifiedShallueVanDeWoestijneMapToCurve mapToCurve =
                new SimplifiedShallueVanDeWoestijneMapToCurve(p256Curve, BigInteger.valueOf(-10));

        specificMappingTestcase(new BigInteger(1,
            Hex.decode("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")),
            mapToCurve,
            "ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5",
            "dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1"
            );
        specificMappingTestcase(new BigInteger(1,
                Hex.decode("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")),
            mapToCurve,
            "51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
            "b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac"
            );
    }

    void specificMappingTestcase(BigInteger u, MapToCurve mapToCurve, String expectedX, String expectedY) throws  Exception {
        ECPoint qu = mapToCurve.process(u);
        String x = qu.getXCoord().toBigInteger().toString(16);
        String y = qu.getYCoord().toBigInteger().toString(16);
        assertEquals(expectedX, x);
        assertEquals(expectedY, y);
    }

}
