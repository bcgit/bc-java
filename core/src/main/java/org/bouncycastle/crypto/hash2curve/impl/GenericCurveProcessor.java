package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class GenericCurveProcessor implements CurveProcessor {
  private final BigInteger cofactor;

  public GenericCurveProcessor(final BigInteger cofactor) {
    this.cofactor = cofactor;
  }

  public GenericCurveProcessor() {
    this.cofactor = BigInteger.ONE;
  }

  @Override
  public ECPoint clearCofactor(final ECPoint ecPoint) {
    // For cofactor greater than one.
    return ecPoint.multiply(cofactor);
  }

}
