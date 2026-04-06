package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.crypto.hash2curve.SqrtRatioCalculator;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Implements the Simplified Shallue van de Woestijne Map to curve according to section 6.6.2 of RFC 9380 This is the
 * straight-line implementation optimized for Weierstrass curves as defined in section F.2.
 */
public class SimplifiedShallueVanDeWoestijneMapToCurve implements MapToCurve {

  private final ECCurve curve;
  private final BigInteger z;

  private final SqrtRatioCalculator sqrtRatioCalculator;

  /**
   * Constructs an instance of the SimplifiedShallueVanDeWoestijneMapToCurve mapping mechanism for mapping values
   * onto a Weierstrass elliptic curve. This implementation is based on section 6.6.2 of RFC 9380 and optimizations
   * defined in section F.2.
   *
   * @param curve the elliptic curve to which the mapping will be applied; must conform to the Weierstrass form
   * @param z a non-zero constant value used as a parameter in the mapping algorithm
   */
  public SimplifiedShallueVanDeWoestijneMapToCurve(final ECCurve curve, final BigInteger z) {
    this.curve = curve;
    this.z = z;
    this.sqrtRatioCalculator = new GenericSqrtRatioCalculator(curve, z);
  }

  /**
   * Processes the given input value to map it to an elliptic curve point using the Shallue-van de Woestijne
   * algorithm, optimized for Weierstrass curves. This implementation adheres to the specifications outlined
   * in RFC 9380, section 6.6.2, and section F.2 for efficient computation.
   * <p>
   * The method computes the x and y coordinates for the point on the elliptic curve, using modular arithmetic
   * and auxiliary functions for square root computation and conditional assignments.
   *
   * @param u the input value to be mapped to a point on the elliptic curve
   * @return the computed point on the elliptic curve represented as an ECPoint
   */
  @Override
  public ECPoint process(final BigInteger u) {

    final BigInteger A = this.curve.getA().toBigInteger();
    final BigInteger B = this.curve.getB().toBigInteger();
    final BigInteger p = this.curve.getField().getCharacteristic();

    BigInteger tv1 = u.modPow(BigInteger.valueOf(2), p);
    tv1 = this.z.multiply(tv1).mod(p);
    BigInteger tv2 = tv1.modPow(BigInteger.valueOf(2), p);
    tv2 = tv2.add(tv1).mod(p);
    BigInteger tv3 = tv2.add(BigInteger.ONE).mod(p);
    tv3 = B.multiply(tv3).mod(p);
    BigInteger tv4 = H2cUtils.cmov(this.z, tv2.negate(), !tv2.equals(BigInteger.ZERO));
    tv4 = A.multiply(tv4).mod(p);
    tv2 = tv3.modPow(BigInteger.valueOf(2), p);
    BigInteger tv6 = tv4.modPow(BigInteger.valueOf(2), p);
    BigInteger tv5 = A.multiply(tv6).mod(p);
    tv2 = tv2.add(tv5).mod(p);
    tv2 = tv2.multiply(tv3).mod(p);
    tv6 = tv6.multiply(tv4).mod(p);
    tv5 = B.multiply(tv6).mod(p);
    tv2 = tv2.add(tv5).mod(p);
    BigInteger x = tv1.multiply(tv3).mod(p);
    final SqrtRatio sqrtRatio = this.sqrtRatioCalculator.sqrtRatio(tv2, tv6);
    final boolean isGx1Square = sqrtRatio.isQR();
    final BigInteger y1 = sqrtRatio.getRatio();
    BigInteger y = tv1.multiply(u).mod(p);
    y = y.multiply(y1).mod(p);
    x = H2cUtils.cmov(x, tv3, isGx1Square);
    y = H2cUtils.cmov(y, y1, isGx1Square);
    final boolean e1 = H2cUtils.sgn0(u, this.curve) == H2cUtils.sgn0(y, this.curve);
    y = H2cUtils.cmov(y.negate(), y, e1).mod(p);
    x = x.multiply(tv4.modPow(BigInteger.ONE.negate(), p)).mod(p);
    return this.curve.createPoint(x, y);
  }

}
