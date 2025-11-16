package org.bouncycastle.crypto.hash2curve.data;

import java.math.BigInteger;

/**
 * The result of a sqrt_ration calculation
 */
public class SqrtRatio{

  private final boolean isQR;
  private final BigInteger ratio;

  public SqrtRatio(final boolean isQR, final BigInteger ratio) {
    this.isQR = isQR;
    this.ratio = ratio;
  }

  public boolean isQR() {
    return isQR;
  }

  public BigInteger getRatio() {
    return ratio;
  }
}
