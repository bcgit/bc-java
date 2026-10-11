package org.bouncycastle.oer.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point256;
import org.bouncycastle.util.Arrays;

public class EccP256CurvePointTest
    extends TestCase
{
    public void testCreateEncodedPoint()
    {
        ECPoint g = ECNamedCurveTable.getByName("P-256").getG();

        // multiples of G covering both y parities
        for (int k = 1; k <= 4; k++)
        {
            ECPoint p = g.multiply(BigInteger.valueOf(k)).normalize();
            byte[] x = p.getAffineXCoord().getEncoded();
            byte[] y = p.getAffineYCoord().getEncoded();

            byte[] compressed = p.getEncoded(true);
            EccP256CurvePoint cp = EccP256CurvePoint.createEncodedPoint(compressed);
            assertEquals((compressed[0] == 0x02) ? EccP256CurvePoint.compressedY0 : EccP256CurvePoint.compressedY1, cp.getChoice());
            assertTrue(Arrays.areEqual(compressed, cp.getEncodedPoint()));

            byte[] uncompressed = p.getEncoded(false);
            EccP256CurvePoint up = EccP256CurvePoint.createEncodedPoint(uncompressed);
            assertEquals(EccP256CurvePoint.uncompressedP256, up.getChoice());
            Point256 point = Point256.getInstance(up.getEccp256CurvePoint());
            assertTrue(Arrays.areEqual(x, point.getX().getOctets()));
            assertTrue(Arrays.areEqual(y, point.getY().getOctets()));
            assertTrue(Arrays.areEqual(uncompressed, up.getEncodedPoint()));

            checkRejected(Arrays.copyOfRange(compressed, 0, 32));
            checkRejected(Arrays.append(compressed, (byte)0));
            checkRejected(Arrays.copyOfRange(uncompressed, 0, 64));
            checkRejected(Arrays.append(uncompressed, (byte)0));
        }
    }

    private static void checkRejected(byte[] encoding)
    {
        try
        {
            EccP256CurvePoint.createEncodedPoint(encoding);
            fail("encoding of length " + encoding.length + " accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getMessage().endsWith("point encoding must be " + ((encoding[0] == 0x04) ? 65 : 33) + " bytes long"));
        }
    }
}
