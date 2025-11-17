package org.bouncycastle.crypto.hash2curve.impl;


import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.SqrtRatioCalculator;
import org.bouncycastle.crypto.hash2curve.data.SqrtRatio;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;

/**
 * Generic implementation of the sqrt_ratio(u, v) operation defined in RFC 9380.
 *
 * <p>This computes a square root of u/v in the prime field Fp associated with an
 * elliptic curve, when such a square root exists, and otherwise returns a valid
 * square root of z·u/v for a fixed quadratic non-residue z.  This function is a
 * required component of all map-to-curve constructions in RFC 9380, including
 * the Simplified SWU and Elligator 2 maps.</p>
 *
 * <p>RFC 9380 defines optimized sqrt_ratio formulas for certain curves where
 * the field prime p satisfies special congruences (e.g. p ≡ 3 mod 4 or p ≡ 5 mod 8).
 * However, those optimizations are curve-specific and do not apply to all hash-to-curve
 * suites.  This implementation instead follows the fully generic algorithm from
 * Section 5.6.3 of RFC 9380, which is valid for any elliptic curve defined over a
 * prime field Fp.</p>
 *
 * <p>This generic version supports all curves used in the RFC 9830 test vectors,
 * including the NIST P-256 / P-384 / P-521 curves, Curve25519, Edwards25519
 * (Ristretto255), Curve448, and Edwards448 (Decaf448).  It provides a single uniform
 * implementation suitable for all supported hash-to-curve suites.</p>
 */
public class GenericSqrtRatioCalculator implements SqrtRatioCalculator {

  private final ECCurve curve;
  private final BigInteger z;

  private final BigInteger q;

  private final int c1;
  private final BigInteger c2, c3, c4, c5, c6, c7;

  public GenericSqrtRatioCalculator(final ECCurve curve, final BigInteger z) {
    this.curve = curve;
    this.q = curve.getField().getCharacteristic();
    this.z = z;
    this.c1 = this.calculateC1();

    this.c2 = this.q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2).pow(this.c1));
    this.c3 = this.c2.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
    this.c4 = BigInteger.valueOf(2).pow(this.c1).subtract(BigInteger.ONE);
    this.c5 = BigInteger.valueOf(2).pow(this.c1 - 1);
    this.c6 = z.modPow(this.c2, this.q);
    this.c7 = z.modPow(this.c2.add(BigInteger.ONE).divide(BigInteger.valueOf(2)), q);
  }

  private int calculateC1() {
    BigInteger qMinusOne = this.q.subtract(BigInteger.ONE);
    int c1 = 0;
    while (qMinusOne.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
      qMinusOne = qMinusOne.divide(BigInteger.valueOf(2));
      c1++;
    }
    return c1;
  }

  @Override
  public SqrtRatio sqrtRatio(final BigInteger u, final BigInteger v) {

    BigInteger tv1 = this.c6;
    BigInteger tv2 = v.modPow(this.c4, this.q);
    BigInteger tv3 = tv2.modPow(BigInteger.valueOf(2), this.q);
    tv3 = tv3.multiply(v).mod(this.q);
    BigInteger tv5 = u.multiply(tv3).mod(this.q);
    tv5 = tv5.modPow(this.c3, this.q);
    tv5 = tv5.multiply(tv2).mod(this.q);
    tv2 = tv5.multiply(v).mod(this.q);
    tv3 = tv5.multiply(u).mod(this.q);
    BigInteger tv4 = tv3.multiply(tv2).mod(this.q);
    tv5 = tv4.modPow(this.c5, this.q);
    final boolean isQR = tv5.equals(BigInteger.ONE);
    tv2 = tv3.multiply(this.c7).mod(this.q);
    tv5 = tv4.multiply(tv1).mod(this.q);
    tv3 = H2cUtils.cmov(tv2, tv3, isQR);
    tv4 = H2cUtils.cmov(tv5, tv4, isQR);
    for (int i = this.c1; i >= 2; i--) {
      tv5 = BigInteger.valueOf(i - 2);
      tv5 = BigInteger.valueOf(2).pow(tv5.intValue());
      tv5 = tv4.modPow(tv5, this.q);
      final boolean e1 = tv5.equals(BigInteger.ONE);
      tv2 = tv3.multiply(tv1).mod(this.q);
      tv1 = tv1.multiply(tv1).mod(this.q);
      tv5 = tv4.multiply(tv1).mod(this.q);
      tv3 = H2cUtils.cmov(tv2, tv3, e1);
      tv4 = H2cUtils.cmov(tv5, tv4, e1);
    }
    return new SqrtRatio(isQR, tv3);
  }
}
