package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Implements the Elligator 2 Map to curve according to section 6.7.1 of RFC 9380 This is the
 * straight-line implementation optimized for Montgomery curves as defined in section F.3.
 */
public class Elligator2MapToCurve implements MapToCurve {

  private final ECCurve curve;
  private final BigInteger z;
  private final BigInteger J;
  private final BigInteger K;
  private final BigInteger c1;  // J / K
  private final BigInteger c2;  // 1 / K^2
  private final BigInteger p;

  public Elligator2MapToCurve(final ECCurve curve, final BigInteger z, final BigInteger J,
      final BigInteger K) {
    this.curve = curve;
    this.z = z;
    this.J = J;
    this.K = K;

    this.p = curve.getField().getCharacteristic();

    // c1 = J / K
    final BigInteger Kinv = K.modInverse(p);
    this.c1 = J.multiply(Kinv).mod(p);

    // c2 = 1 / K^2 = (K^2)^(-1)
    final BigInteger K2inv = Kinv.multiply(Kinv).mod(p);
    this.c2 = K2inv;
  }

  /**
   * Processes the given input value to map it to an elliptic curve point using the Elligator 2
   * algorithm, optimized for Montgomery curves. This implementation adheres to the specifications outlined
   * in RFC 9380, section 6.7.1, and section F.3 for efficient computation.
   *
   * @param u the input value to be mapped to a point on the elliptic curve
   * @return the computed point on the elliptic curve represented as an ECPoint
   */
  @Override
  public ECPoint process(final BigInteger u) {

    // map_to_curve_elligator2(u)

    BigInteger tv1 = u.multiply(u).mod(p);            // tv1 = u^2
    tv1 = z.multiply(tv1).mod(p);                     // tv1 = Z * u^2

    // e1 = (tv1 == -1)
    final BigInteger minusOne = p.subtract(BigInteger.ONE);
    final boolean e1 = tv1.equals(minusOne);

    // if tv1 == -1 then tv1 = 0
    tv1 = H2cUtils.cmov(tv1, BigInteger.ZERO, e1);

    BigInteger x1 = tv1.add(BigInteger.ONE).mod(p);   // x1 = 1 + tv1
    x1 = H2cUtils.inv0(x1, p);                        // x1 = inv0(x1)
    x1 = x1.multiply(c1).negate().mod(p);             // x1 = -c1 * x1

    // gx1 = x1^3 + (J / K)*x1^2 + x1 / K^2
    BigInteger gx1 = x1.add(c1).mod(p);               // gx1 = x1 + c1
    gx1 = gx1.multiply(x1).mod(p);                    // gx1 = (x1 + c1)*x1
    gx1 = gx1.add(c2).mod(p);                         // gx1 = gx1 + c2
    gx1 = gx1.multiply(x1).mod(p);                    // gx1 = gx1 * x1

    BigInteger x2 = x1.negate().subtract(c1).mod(p);  // x2 = -x1 - c1
    BigInteger gx2 = tv1.multiply(gx1).mod(p);        // gx2 = tv1 * gx1

    // e2 = is_square(gx1)
    final boolean e2 = H2cUtils.isSquare(gx1, p);

    // x = e2 ? x1 : x2
    BigInteger x = H2cUtils.cmov(x2, x1, e2);

    // y2 = e2 ? gx1 : gx2
    BigInteger y2 = H2cUtils.cmov(gx2, gx1, e2);

    // y = sqrt(y2)
    BigInteger y = H2cUtils.sqrt(y2, p);

    // e3 = (sgn0(y) == 1)
    final boolean e3 = H2cUtils.sgn0(y, curve) == 1;

    // y = CMOV(y, -y, e2 XOR e3)
    final boolean flip = e2 ^ e3;
    final BigInteger yNeg = y.negate().mod(p);
    y = H2cUtils.cmov(y, yNeg, flip);

    // s = x * K
    // t = y * K
    BigInteger s = x.multiply(K).mod(p);
    BigInteger t = y.multiply(K).mod(p);

    return this.curve.createPoint(s, t);
  }

}
