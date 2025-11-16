package org.bouncycastle.crypto.hash2curve;


import org.bouncycastle.crypto.hash2curve.data.SqrtRatio;

import java.math.BigInteger;

/**
 * Interface for a calculator of SqrtRatio
 */
public interface SqrtRatioCalculator {

  /**
   * he sqrtRatio subroutine of hash2Curve in the field F
   *
   * @param u u parameter, element of F
   * @param v v parameter, element of F, such that v != 0
   * @return SqrtRatio result
   */
  SqrtRatio sqrtRatio(BigInteger u, BigInteger v);

}
