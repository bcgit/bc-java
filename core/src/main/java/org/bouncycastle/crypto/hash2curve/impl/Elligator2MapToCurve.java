package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.crypto.hash2curve.SqrtRatioCalculator;
import org.bouncycastle.crypto.hash2curve.data.SqrtRatio;
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
  private final BigInteger p;
  private final BigInteger inv3K; // 1 / (3K) mod p
  private final BigInteger invK;  // 1 / K mod p

  public Elligator2MapToCurve(final ECCurve curve,
      final BigInteger z,
      final BigInteger J,
      final BigInteger K) {
    this.curve = curve;
    this.z = z;
    this.J = J;
    this.K = K;

    this.p = curve.getField().getCharacteristic();

    BigInteger three = BigInteger.valueOf(3);
    this.inv3K = three.multiply(K).modInverse(p); // (3K)^(-1) mod p
    this.invK = K.modInverse(p);                  // K^(-1) mod p
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
    // --- Elligator 2 in Montgomery coordinates (s, t) ---

    // map_to_curve_elligator2(u) as in F.3, but treat final (x, y) as (s, t)

    BigInteger tv1 = u.multiply(u).mod(p);    // u^2
    tv1 = z.multiply(tv1).mod(p);             // Z * u^2

    BigInteger minusOne = p.subtract(BigInteger.ONE);
    boolean e1 = tv1.equals(minusOne);
    tv1 = H2cUtils.cmov(tv1, BigInteger.ZERO, e1);

    BigInteger x1 = tv1.add(BigInteger.ONE).mod(p);
    x1 = H2cUtils.inv0(x1, p);
    x1 = x1.multiply(J).negate().mod(p);      // since c1 = J/K and K=1 for curve25519

    BigInteger gx1 = x1.add(J).mod(p);
    gx1 = gx1.multiply(x1).mod(p);
    gx1 = gx1.add(BigInteger.ONE).mod(p);     // c2 = 1/K^2 = 1 for curve25519
    gx1 = gx1.multiply(x1).mod(p);

    BigInteger x2 = x1.negate().subtract(J).mod(p);
    BigInteger gx2 = tv1.multiply(gx1).mod(p);

    boolean e2 = H2cUtils.isSquare(gx1, p);

    BigInteger x = H2cUtils.cmov(x2, x1, e2);
    BigInteger y2 = H2cUtils.cmov(gx2, gx1, e2);

    BigInteger y = H2cUtils.sqrt(y2, p);

    boolean e3 = H2cUtils.sgn0(y, curve) == 1;
    boolean flip = e2 ^ e3;
    BigInteger yNeg = y.negate().mod(p);
    y = H2cUtils.cmov(y, yNeg, flip);

    // (s, t) = (x * K, y * K); for curve25519, K = 1
    BigInteger s = x.multiply(K).mod(p);
    BigInteger t = y.multiply(K).mod(p);

    // --- Map Montgomery (s, t) to Weierstrass (xW, yW) using Appendix D.2 ---

    // xW = (3 * s + J) / (3 * K)  mod p
    BigInteger xW = BigInteger.valueOf(3).multiply(s).add(J).mod(p);
    xW = xW.multiply(inv3K).mod(p);

    // yW = t / K  mod p
    BigInteger yW = t.multiply(invK).mod(p);

    return this.curve.createPoint(xW, yW);
  }
}
