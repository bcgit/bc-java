package org.bouncycastle.crypto.hash2curve.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.crypto.hash2curve.HashToEllipticCurve;
import org.bouncycastle.crypto.hash2curve.HashToField;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.hash2curve.data.HashToCurveProfile;
import org.bouncycastle.crypto.hash2curve.impl.GenericCurveProcessor;
import org.bouncycastle.crypto.hash2curve.impl.GenericHashToField;
import org.bouncycastle.crypto.hash2curve.impl.ShallueVanDeWoestijneMapToCurve;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;


/**
 * Test suite for HashToEllipticCurve class.
 */
public class HashToEllipticCurveTest extends TestCase {


  public void testTestVectors() throws Exception {

    //TODO Add support for Montgomery curves (required for curve25519).

    List<HashToCurveProfile> profileList = new ArrayList<>();
    profileList.add(HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_);
    profileList.add(HashToCurveProfile.P384_XMD_SHA_384_SSWU_RO_);
    profileList.add(HashToCurveProfile.P521_XMD_SHA_512_SSWU_RO_);
    //profileList.add(HashToCurveProfile.curve25519_XMD_SHA_512_ELL2_RO_);

    for (HashToCurveProfile profile : profileList) {
      performTestOnSpecificCurveProfile(profile, false);
    }
  }

  private void performTestOnSpecificCurveProfile(HashToCurveProfile profile, boolean useTestVectorU) throws Exception {

/*
    log.info("Performing test vector tests on ciphersuite: {}", profile.getCipherSuiteID());
    log.info("Details:\n"
        + "   Curve: {}\n"
        + "   Hash: {}\n"
        + "   dst: {}\n"
        + "   L: {}\n"
        + "   Z: {}\n"
        + "   Field m: {}\n"
        + "   Field p: {}\n"
      , tvd.getCurve(), tvd.getHash(), tvd.getDst(), L, Z,
      tvd.getField().getM(), tvd.getField().getP());
*/

    ECCurve curve;
    Digest digest;
    TestVectorData tvd;
    switch (profile) {
    case P256_XMD_SHA_256_SSWU_RO_ :
      curve = new SecP256R1Curve();
      digest = new SHA256Digest();
      tvd = TestVectors.P256_TEST_VECTOR_DATA;
      break;
    case P384_XMD_SHA_384_SSWU_RO_ :
      curve = new SecP384R1Curve();
      digest = new SHA384Digest();
      tvd = TestVectors.P384_TEST_VECTOR_DATA;
      break;
    case P521_XMD_SHA_512_SSWU_RO_ :
      curve = new SecP521R1Curve();
      digest = new SHA512Digest();
      tvd = TestVectors.P521_TEST_VECTOR_DATA;
      break;
    default:
      throw new IllegalArgumentException("Unsupported profile: " + profile);
    }

    BigInteger Z = h2bi(tvd.getZ(), tvd.getField().getP());
    int L = h2bi(tvd.getL()).intValue();


    CurveProcessor curveProcessor = new GenericCurveProcessor();
    MessageExpansion messExp = new XmdMessageExpansion(digest, profile.getK());
    GenericHashToField
        hashToField = new GenericHashToField(tvd.getDst().getBytes(StandardCharsets.UTF_8), curve, messExp, profile.getL());
    MapToCurve mapToCurve = new ShallueVanDeWoestijneMapToCurve(curve, profile.getZ());

    assertEquals(Z, profile.getZ());
    assertEquals(L, profile.getL());

    TestHashToEllipticCurve h2c = new TestHashToEllipticCurve(hashToField, mapToCurve, curveProcessor);

    // Run individual vectors
    List<TestVectorData.Vector> vectors = tvd.getVectors();
    for (TestVectorData.Vector vector : vectors) {
      byte[] messageBytes = vector.getMsg().getBytes(StandardCharsets.UTF_8);

      if (useTestVectorU) {
        // Replace with test vector u values
        h2c.setNextU0(h2bi(vector.getU().get(0)));
        h2c.setNextU1(h2bi(vector.getU().get(1)));
      }

      ECPoint point = executeAndLogResult("Results for msg: " + vector.getMsg(), vector.getMsg(), h2c,
        hexStrip(vector.getP().get("x")), hexStrip(vector.getP().get("y")));
      compare(vector.getP().get("x"), vector.getP().get("y"), point);
    }

  }

  private void compare(String x, String y, ECPoint point) {
    //log.info("Expected X: {}", hexStrip(x));
    //log.info("Expected Y: {}", hexStrip(y));
    //log.info("Expected compressed point: {}", Hex.toHexString(point.getEncoded(true)));
    String resultX = point.getXCoord().toBigInteger().toString(16);
    String resultY = point.getYCoord().toBigInteger().toString(16);
    hexCompare(hexStrip(x), resultX);
    hexCompare(hexStrip(y), resultY);
    //log.info("Points match\n");
  }

  private void hexCompare(String vectorVal, String resultVal) {
    int startIndex = vectorVal.length() - resultVal.length();
    assertEquals(vectorVal.substring(startIndex), resultVal);
  }

  public ECPoint executeAndLogResult(String description, String msg, HashToEllipticCurve h2c, String px, String py) throws Exception {
    //log.info(description);
    ECPoint ecPoint = h2c.hashToEllipticCurve(msg.getBytes(StandardCharsets.UTF_8));
    String x = ecPoint.getXCoord().toString();
    //log.info("Result point X: {}", x);
    String y = ecPoint.getYCoord().toString();
    //log.info("Result point Y: {}", y);
    return ecPoint;
  }

  BigInteger h2bi(String hexStr) {
    return new BigInteger(hexStrip(hexStr), 16);
  }

  BigInteger h2bi(String hexStr, String hexOrder) {
    BigInteger val = h2bi(hexStr);
    BigInteger order = h2bi("00" + hexStrip(hexOrder));

    BigInteger positive = val;
    BigInteger negative = order.subtract(val);
    BigInteger result = positive.compareTo(negative) > 0 ? negative.negate() : positive;
    return result;
  }

  private String hexStrip(String hexStr) {
    return hexStr.startsWith("0x") || hexStr.startsWith("0X")
      ? hexStr.substring(2)
      : hexStr;
  }

  public static class TestHashToEllipticCurve extends HashToEllipticCurve {

    public TestHashToEllipticCurve(HashToField hashToField, MapToCurve mapToCurve, CurveProcessor curveProcessor) {
      super(hashToField, mapToCurve, curveProcessor);
    }

    BigInteger nextU0;
    BigInteger nextU1;

    @Override
    public ECPoint hashToEllipticCurve(byte[] message) {
      BigInteger[][] u = hashToField.process(message);
      ECPoint Q0 = mapToCurve.process(getU0(u));
      ECPoint Q1 = mapToCurve.process(getU1(u));
      ECPoint R = Q0.add(Q1);
      ECPoint P = curveProcessor.clearCofactor(R);
      return P;
    }

    public void setNextU0(final BigInteger nextU0) {
      this.nextU0 = nextU0;
    }

    public void setNextU1(final BigInteger nextU1) {
      this.nextU1 = nextU1;
    }

    BigInteger getU0(BigInteger[][] u) {
      //log.info("Calculated u0: {}", u[0][0].toString(16));
      if (nextU0 != null) {
        //log.info("Using preset u0: {}", nextU0.toString(16));
        BigInteger result = new BigInteger(nextU0.toString());
        nextU0 = null;
        return result;
      }
      return u[0][0];
    }

    BigInteger getU1(BigInteger[][] u) {
      //log.info("Calculated u1: {}", u[1][0].toString(16));
      if (nextU1 != null) {
        //log.info("Using preset u1: {}", nextU1.toString(16));
        BigInteger result = new BigInteger(nextU1.toString());
        nextU1 = null;
        return result;
      }
      return u[1][0];
    }

  }

}
