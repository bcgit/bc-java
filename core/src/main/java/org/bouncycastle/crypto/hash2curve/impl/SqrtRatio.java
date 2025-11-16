package org.bouncycastle.crypto.hash2curve.impl;

import java.math.BigInteger;

/**
 * The result of a sqrt_ration calculation
 */
public class SqrtRatio{

  /**
   * A boolean flag indicating whether the computed value is a quadratic residue (QR)
   * modulo a specific field. In the context of square root calculations or related
   * operations, this variable helps distinguish cases where the ratio under consideration
   * has a valid square root (is a QR) or not.
   */
  private final boolean isQR;
  /**
   * Represents the ratio value resulting from the square root ratio computation.
   */
  private final BigInteger ratio;

  /**
   * Constructs an instance of SqrtRatio representing the result of a square root ratio computation.
   *
   * @param isQR  A boolean flag indicating whether the computed value is a quadratic residue (QR)
   *              modulo a specific field. This helps determine if the ratio under consideration
   *              has a valid square root.
   * @param ratio The ratio value resulting from the square root ratio computation.
   */
  protected SqrtRatio(final boolean isQR, final BigInteger ratio) {
    this.isQR = isQR;
    this.ratio = ratio;
  }

  /**
   * Checks whether the computed value is a quadratic residue (QR) modulo a specific field.
   *
   * @return true if the computed value is a quadratic residue (QR); false otherwise.
   */
  public boolean isQR() {
    return isQR;
  }

  /**
   * Retrieves the ratio value resulting from the square root ratio computation.
   *
   * @return the ratio value as a BigInteger.
   */
  public BigInteger getRatio() {
    return ratio;
  }
}
