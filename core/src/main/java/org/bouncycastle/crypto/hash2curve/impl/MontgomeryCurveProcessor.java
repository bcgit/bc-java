package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 Curve processor for Montgomery curves of the form
 B * y^2 = x^3 + A * x^2 + x

 Internally we treat this as a long Weierstrass curve
 y^2 = x^3 + a2 * x^2 + a4 * x + a6
 with
 a2 = A / B, a4 = 1 / B, a6 = 0.
 All arithmetic is done explicitly in F_p using these formulas,
 not via the ECPoint group operations, because BouncyCastle's
 Montgomery implementation does not use this model directly.
 */
public class MontgomeryCurveProcessor implements CurveProcessor {

  private final ECCurve curve;
  private final BigInteger p;

  // Weierstrass-style coefficients derived from Montgomery (A, B)
  private final BigInteger a2; // = A / B mod p
  private final BigInteger a4; // = 1 / B mod p
  private final BigInteger a6; // = 0

  // Effective cofactor h_eff (e.g. 8 for curve25519_XMD:SHA-512_ELL2_RO_)
  private final BigInteger hEff;

  public MontgomeryCurveProcessor(ECCurve curve,
      int J,
      int K,
      int hEff) {
    this.curve = curve;
    this.p = curve.getField().getCharacteristic();
    BigInteger Binv = BigInteger.valueOf(K).modInverse(p);
    this.a2 = BigInteger.valueOf(J).multiply(Binv).mod(p); // A/B
    this.a4 = Binv;
    this.a6 = BigInteger.ZERO;
    this.hEff = BigInteger.valueOf(hEff);
  }


  @Override
  public ECPoint add(final ECPoint P, final ECPoint Q) {
    return addInternal(P, Q);
  }

  @Override
  public ECPoint clearCofactor(final ECPoint P) {
    if (P.isInfinity()) {
      return P;
    }
    // Generic double-and-add on top of our explicit addInternal
    return scalarMul(hEff, P);
  }

  // ---------- internal helpers ----------

  private ECPoint addInternal(final ECPoint P, final ECPoint Q) {
    if (P.isInfinity()) {
      return Q;
    }
    if (Q.isInfinity()) {
      return P;
    }

    // Work in affine coords
    ECPoint Pn = P.normalize();
    ECPoint Qn = Q.normalize();

    BigInteger x1 = Pn.getAffineXCoord().toBigInteger();
    BigInteger y1 = Pn.getAffineYCoord().toBigInteger();
    BigInteger x2 = Qn.getAffineXCoord().toBigInteger();
    BigInteger y2 = Qn.getAffineYCoord().toBigInteger();

    // P + (-P) = O
    if (x1.equals(x2) && y1.add(y2).mod(p).equals(BigInteger.ZERO)) {
      return curve.getInfinity();
    }

    BigInteger lambda;
    if (x1.equals(x2) && y1.equals(y2)) {
      // Point doubling on y^2 = x^3 + a2 x^2 + a4 x + a6
      // lambda = (3*x1^2 + 2*a2*x1 + a4) / (2*y1)
      BigInteger x1Sq = x1.multiply(x1).mod(p);
      BigInteger num = x1Sq.multiply(BigInteger.valueOf(3)).mod(p);
      num = num.add(a2.multiply(x1).multiply(BigInteger.valueOf(2))).mod(p);
      num = num.add(a4).mod(p);

      BigInteger den = y1.multiply(BigInteger.valueOf(2)).mod(p);
      lambda = num.multiply(inv(den)).mod(p);

    } else {
      // Point addition
      // lambda = (y2 - y1) / (x2 - x1)
      BigInteger num = y2.subtract(y1).mod(p);
      BigInteger den = x2.subtract(x1).mod(p);
      lambda = num.multiply(inv(den)).mod(p);
    }

    // x3 = lambda^2 - a2 - x1 - x2
    BigInteger lambdaSq = lambda.multiply(lambda).mod(p);
    BigInteger x3 = lambdaSq.subtract(a2).subtract(x1).subtract(x2).mod(p);

    // y3 = -y1 - lambda*(x3 - x1)
    BigInteger y3 = x3.subtract(x1).mod(p);
    y3 = lambda.multiply(y3).mod(p);
    y3 = y1.negate().subtract(y3).mod(p);

    x3 = x3.mod(p);
    y3 = y3.mod(p);

    return curve.createPoint(x3, y3);

  }

  private ECPoint scalarMul(final BigInteger k, final ECPoint P) {
    if (k.signum() == 0 || P.isInfinity()) {
      return curve.getInfinity();
    }

    ECPoint R = curve.getInfinity();
    ECPoint N = P;

    for (int i = k.bitLength() - 1; i >= 0; i--) {
      // R = 2R
      R = addInternal(R, R);
      if (k.testBit(i)) {
        R = addInternal(R, N);
      }
    }
    return R;

  }

  private BigInteger inv(final BigInteger x) {
    // We rely on BigInteger.modInverse here; timing is not guaranteed constant.
    return x.modInverse(p);
  }
}
