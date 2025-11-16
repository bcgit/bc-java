package org.bouncycastle.crypto.hash2curve;

import org.bouncycastle.crypto.hash2curve.data.HashToCurveProfile;
import org.bouncycastle.crypto.hash2curve.impl.GenericCurveProcessor;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

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

  public HashToEllipticCurve(final HashToField hashToField,
      final MapToCurve mapToCurve, final CurveProcessor curveProcessor) {
    this.curveProcessor = curveProcessor;
    this.hashToField = hashToField;
    this.mapToCurve = mapToCurve;
  }

  public HashToEllipticCurve(final HashToField hashToField, final MapToCurve mapToCurve, BigInteger cofactor) {
    this(hashToField, mapToCurve, new GenericCurveProcessor(cofactor));
  }

  public HashToEllipticCurve(final HashToField hashToField, final MapToCurve mapToCurve) {
    this(hashToField, mapToCurve, new GenericCurveProcessor());
  }

  public static HashToEllipticCurve getInstance(final HashToCurveProfile profile) {
    return null;
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
    final ECPoint R = Q0.add(Q1);
    return this.curveProcessor.clearCofactor(R);
  }

}
