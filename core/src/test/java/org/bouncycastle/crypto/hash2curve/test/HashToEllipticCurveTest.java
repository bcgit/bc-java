package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.hash2curve.HashToCurveProfile;
import org.bouncycastle.crypto.hash2curve.HashToEllipticCurve;
import org.bouncycastle.crypto.hash2curve.data.AffineXY;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;


/**
 * Test suite for HashToEllipticCurve class.
 */
public class HashToEllipticCurveTest
    extends TestCase
{


    public void testTestVectors()
        throws Exception
    {

        List<HashToCurveProfile> profileList = new ArrayList<HashToCurveProfile>();
        profileList.add(HashToCurveProfile.P256_XMD_SHA_256);
        profileList.add(HashToCurveProfile.P384_XMD_SHA_384);
        profileList.add(HashToCurveProfile.P521_XMD_SHA_512);
        profileList.add(HashToCurveProfile.CURVE25519W_XMD_SHA_512_ELL2);

        for (HashToCurveProfile profile : profileList)
        {
            performTestOnSpecificCurveProfile(profile);
        }
    }

    private void performTestOnSpecificCurveProfile(HashToCurveProfile profile)
        throws Exception
    {

        List<TestVectorData> testVectorList = new ArrayList<TestVectorData>();
        switch (profile)
        {
        case P256_XMD_SHA_256:
            testVectorList.add(TestVectors.P256_HTC_TEST_VECTOR_DATA);
            testVectorList.add(TestVectors.P256_ETC_TEST_VECTOR_DATA);
            break;
        case P384_XMD_SHA_384:
            testVectorList.add(TestVectors.P384_HTC_TEST_VECTOR_DATA);
            testVectorList.add(TestVectors.P384_ETC_TEST_VECTOR_DATA);
            break;
        case P521_XMD_SHA_512:
            testVectorList.add(TestVectors.P521_HTC_TEST_VECTOR_DATA);
            testVectorList.add(TestVectors.P521_ETC_TEST_VECTOR_DATA);
            break;
        case CURVE25519W_XMD_SHA_512_ELL2:
            testVectorList.add(TestVectors.curve25519_HTC_TEST_VECTOR_DATA);
            testVectorList.add(TestVectors.curve25519_ETC_TEST_VECTOR_DATA);
            break;
        default:
            throw new IllegalArgumentException("Unsupported profile: " + profile);
        }

        for (TestVectorData tvd : testVectorList)
        {
            BigInteger Z = h2bi(tvd.getZ(), tvd.getField().getP());
            int L = h2bi(tvd.getL()).intValue();

            assertEquals(Z, profile.getZ());
            assertEquals(L, profile.getL());

            HashToEllipticCurve h2c = HashToEllipticCurve.getInstance(profile, tvd.getDst());

            // Run individual vectors
            List<TestVectorData.Vector> vectors = tvd.getVectors();
            for (TestVectorData.Vector vector : vectors)
            {
                ECPoint point = execute(vector.getMsg(), h2c,
                    hexStrip(vector.getP().get("x")), hexStrip(vector.getP().get("y")), tvd.getCiphersuite().endsWith("NU_"));
                compare(vector.getP().get("x"), vector.getP().get("y"), h2c.getAffineXY(point));
            }
        }


    }

    private void compare(String x, String y, AffineXY point)
    {
        String resultX = point.getX().toString(16);
        String resultY = point.getY().toString(16);
        hexCompare(hexStrip(x), resultX);
        hexCompare(hexStrip(y), resultY);
    }

    private void hexCompare(String vectorVal, String resultVal)
    {
        int startIndex = vectorVal.length() - resultVal.length();
        assertEquals(vectorVal.substring(startIndex), resultVal);
    }

    public ECPoint execute(String msg, HashToEllipticCurve h2c, String px, String py, boolean encodeToCurve)
        throws Exception
    {
        return encodeToCurve
            ? h2c.encodeToCurve(Strings.toUTF8ByteArray(msg))
            : h2c.hashToCurve(Strings.toUTF8ByteArray(msg));
    }

    BigInteger h2bi(String hexStr)
    {
        return new BigInteger(hexStrip(hexStr), 16);
    }

    BigInteger h2bi(String hexStr, String hexOrder)
    {
        BigInteger val = h2bi(hexStr);
        BigInteger order = h2bi("00" + hexStrip(hexOrder));

        BigInteger positive = val;
        BigInteger negative = order.subtract(val);
        BigInteger result = positive.compareTo(negative) > 0 ? negative.negate() : positive;
        return result;
    }

    private String hexStrip(String hexStr)
    {
        return hexStr.startsWith("0x") || hexStr.startsWith("0X")
            ? hexStr.substring(2)
            : hexStr;
    }
}
