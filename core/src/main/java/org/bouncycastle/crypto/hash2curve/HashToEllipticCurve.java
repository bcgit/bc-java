package org.bouncycastle.crypto.hash2curve;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.hash2curve.data.AffineXY;
import org.bouncycastle.crypto.hash2curve.impl.Elligator2MapToCurve;
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

/**
 * Main class for implementing hash to elliptic curve according to RFC 9380
 * <p>
 * <code>
 * Steps: 1. u = hash_to_field(msg, 2) 2. Q0 = map_to_curve(u[0]) 3. Q1 = map_to_curve(u[1]) 4. R = Q0 + Q1
 * # Point addition 5. P = clear_cofactor(R) 6. return P
 * </code>
 */
public class HashToEllipticCurve {

  protected final HashToField hashToField;
  protected final MapToCurve mapToCurve;
  protected final CurveProcessor curveProcessor;

  protected HashToEllipticCurve(final HashToField hashToField,
      final MapToCurve mapToCurve, final CurveProcessor curveProcessor) {
    this.curveProcessor = curveProcessor;
    this.hashToField = hashToField;
    this.mapToCurve = mapToCurve;
  }

  private HashToEllipticCurve(final HashToField hashToField, final MapToCurve mapToCurve) {
    this(hashToField, mapToCurve, new NistCurveProcessor());
  }

  public static HashToEllipticCurve getInstance(final HashToCurveProfile profile, String dst) {
    byte[] dstBytes = dst.getBytes(StandardCharsets.UTF_8);
    ECCurve curve;
    switch (profile) {
    case P256_XMD_SHA_256_SSWU_RO_:
      curve = new SecP256R1Curve();
      return new HashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA256Digest(),
          profile.getK()), profile.getL()), new SimplifiedShallueVanDeWoestijneMapToCurve(curve, profile.getZ()),
          new NistCurveProcessor());
    case P384_XMD_SHA_384_SSWU_RO_:
      curve = new SecP384R1Curve();
      return new HashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA384Digest(),
          profile.getK()), profile.getL()), new SimplifiedShallueVanDeWoestijneMapToCurve(curve, profile.getZ()),
          new NistCurveProcessor());
    case P521_XMD_SHA_512_SSWU_RO_:
      curve = new SecP521R1Curve();
      return new HashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA512Digest(),
          profile.getK()), profile.getL()), new SimplifiedShallueVanDeWoestijneMapToCurve(curve, profile.getZ()),
          new NistCurveProcessor());
    case curve25519_XMD_SHA_512_ELL2_RO_:
      curve = new Curve25519();
      return new HashToEllipticCurve(new HashToField(dstBytes, curve, new XmdMessageExpansion(new SHA512Digest(),
          profile.getK()), profile.getL()), new Elligator2MapToCurve(curve, profile.getZ(), BigInteger.valueOf(
          profile.getmJ()), BigInteger.valueOf(profile.getmK())),
          new MontgomeryCurveProcessor(curve, profile.getmJ(), profile.getmK(), profile.getH()));
    default:
      throw new IllegalArgumentException("Unsupported profile: " + profile);
    }
  }

  /**
   * Hashes a message to an elliptic curve point.
   *
   * @param message the message to be hashed
   * @return the resulting elliptic curve point P
   */
  public ECPoint hashToEllipticCurve(final byte[] message) {
    final BigInteger[][] u = this.hashToField.process(message);
    final ECPoint Q0 = this.mapToCurve.process(u[0][0]);
    final ECPoint Q1 = this.mapToCurve.process(u[1][0]);
    final ECPoint R = curveProcessor.add(Q0, Q1);
    return this.curveProcessor.clearCofactor(R);
  }

  /**
   * Converts an elliptic-curve point into the affine (x, y) coordinate representation
   * defined by the hash-to-curve suite.
   *
   * <p>The returned coordinates are intended for serialization, testing, and
   * interoperability with the reference outputs defined in RFC 9380.
   * For most Weierstrass curves, this is simply the affine (x, y) coordinates of
   * the given point. For curves that use a different coordinate model in the
   * specification (e.g. Montgomery curves such as curve25519), this method applies
   * the appropriate coordinate transformation.</p>
   *
   * <p>This method does <em>not</em> change the underlying group element represented
   * by the point. It only changes how that point is expressed as field elements.
   * The input point is expected to be a valid point on the curve used by the
   * implementation.</p>
   * @param point point on the chosen ECCurve for the selected hash2Curve profile
   * @return AffineXY coordinates for the point on the curve defined in RFC 9380 for the selected profile
   */
  public AffineXY getAffineXY(ECPoint point) {
    return curveProcessor.mapToAffineXY(point);
  }



}
