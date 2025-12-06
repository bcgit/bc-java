package org.bouncycastle.crypto.hash2curve.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.crypto.hash2curve.HashToEllipticCurve;
import org.bouncycastle.crypto.hash2curve.HashToField;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.crypto.hash2curve.HashToCurveProfile;
import org.bouncycastle.crypto.hash2curve.impl.Elligator2MapToCurveMtg;
import org.bouncycastle.crypto.hash2curve.impl.MontgomeryCurveProcessor;
import org.bouncycastle.crypto.hash2curve.impl.NistCurveProcessor;
import org.bouncycastle.crypto.hash2curve.impl.SimplifiedShallueVanDeWoestijneMapToCurve;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.djb.Curve25519;
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

    List<HashToCurveProfile> profileList = new ArrayList<>();
    profileList.add(HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_);
    profileList.add(HashToCurveProfile.P384_XMD_SHA_384_SSWU_RO_);
    profileList.add(HashToCurveProfile.P521_XMD_SHA_512_SSWU_RO_);
    profileList.add(HashToCurveProfile.curve25519_XMD_SHA_512_ELL2_RO_);

    for (HashToCurveProfile profile : profileList) {
      performTestOnSpecificCurveProfile(profile, false);
    }
  }

  private void performTestOnSpecificCurveProfile(HashToCurveProfile profile, boolean useTestVectorU) throws Exception {

    TestVectorData tvd;
    switch (profile) {
    case P256_XMD_SHA_256_SSWU_RO_ :
      tvd = TestVectors.P256_TEST_VECTOR_DATA;
      break;
    case P384_XMD_SHA_384_SSWU_RO_ :
      tvd = TestVectors.P384_TEST_VECTOR_DATA;
      break;
    case P521_XMD_SHA_512_SSWU_RO_ :
      tvd = TestVectors.P521_TEST_VECTOR_DATA;
      break;
    case curve25519_XMD_SHA_512_ELL2_RO_ :
      tvd = TestVectors.curve25519_TEST_VECTOR_DATA;
      break;
    default:
      throw new IllegalArgumentException("Unsupported profile: " + profile);
    }

    BigInteger Z = h2bi(tvd.getZ(), tvd.getField().getP());
    int L = h2bi(tvd.getL()).intValue();

    assertEquals(Z, profile.getZ());
    assertEquals(L, profile.getL());

    TestHashToEllipticCurve h2c = TestHashToEllipticCurve.getInstance(profile, tvd.getDst());

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
    String resultX = point.getXCoord().toBigInteger().toString(16);
    String resultY = point.getYCoord().toBigInteger().toString(16);
    hexCompare(hexStrip(x), resultX);
    hexCompare(hexStrip(y), resultY);
  }

  private void hexCompare(String vectorVal, String resultVal) {
    int startIndex = vectorVal.length() - resultVal.length();
    assertEquals(vectorVal.substring(startIndex), resultVal);
  }

  public ECPoint executeAndLogResult(String description, String msg, HashToEllipticCurve h2c, String px, String py) throws Exception {
    ECPoint ecPoint = h2c.hashToEllipticCurve(msg.getBytes(StandardCharsets.UTF_8));
    // TODO Note that curve25519 creates correct test vector results, but invalid points for curve25519
    // For debugging. To be deleted
    final boolean valid = ecPoint.isValid();
    String x = ecPoint.getXCoord().toString();
    String y = ecPoint.getYCoord().toString();
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

    private TestHashToEllipticCurve(HashToField hashToField, MapToCurve mapToCurve, CurveProcessor curveProcessor) {
      super(hashToField, mapToCurve, curveProcessor);
    }

    public static TestHashToEllipticCurve getInstance(final HashToCurveProfile profile, String dst) {
      byte[] dstBytes = dst.getBytes(StandardCharsets.UTF_8);
      CurveProcessor noCofactorProcessor = new NistCurveProcessor();
      ECCurve curve;
      switch (profile) {
      case P256_XMD_SHA_256_SSWU_RO_:
        curve = new SecP256R1Curve();
        return new TestHashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA256Digest(),
            profile.getK()), profile.getL()), new SimplifiedShallueVanDeWoestijneMapToCurve(curve, profile.getZ()), noCofactorProcessor);
      case P384_XMD_SHA_384_SSWU_RO_:
        curve = new SecP384R1Curve();
        return new TestHashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA384Digest(),
            profile.getK()), profile.getL()), new SimplifiedShallueVanDeWoestijneMapToCurve(curve, profile.getZ()), noCofactorProcessor);
      case P521_XMD_SHA_512_SSWU_RO_:
        curve = new SecP521R1Curve();
        return new TestHashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA512Digest(),
            profile.getK()), profile.getL()), new SimplifiedShallueVanDeWoestijneMapToCurve(curve, profile.getZ()), noCofactorProcessor);
      case curve25519_XMD_SHA_512_ELL2_RO_:
        curve = new Curve25519();
        return new TestHashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA512Digest(),
            profile.getK()), profile.getL()), new Elligator2MapToCurveMtg(curve, profile.getZ(), BigInteger.valueOf(
            profile.getmJ()), BigInteger.valueOf(profile.getmK())),
            new MontgomeryCurveProcessor(curve, profile.getmJ(), profile.getmK(), profile.getH()));

      default:
        throw new IllegalArgumentException("Unsupported profile: " + profile);
      }
    }

    BigInteger nextU0;
    BigInteger nextU1;

    @Override
    public ECPoint hashToEllipticCurve(byte[] message) {
      BigInteger[][] u = hashToField.process(message);
      ECPoint Q0 = mapToCurve.process(getU0(u));
      ECPoint Q1 = mapToCurve.process(getU1(u));
      ECPoint R = curveProcessor.add(Q0, Q1);
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
      if (nextU0 != null) {
        BigInteger result = new BigInteger(nextU0.toString());
        nextU0 = null;
        return result;
      }
      return u[0][0];
    }

    BigInteger getU1(BigInteger[][] u) {
      if (nextU1 != null) {
        BigInteger result = new BigInteger(nextU1.toString());
        nextU1 = null;
        return result;
      }
      return u[1][0];
    }
  }

}
