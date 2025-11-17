package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Curve processor for NIST curves (P-256, P-384, P-521) where the cofactor is 1.
 * <p>
 * Although the cofactor is 1 for all NIST curves, RFC 9380 still requires the
 * "clear_cofactor" step for consistency. In Bouncy Castle, invoking
 * {@code ECPoint.multiply(BigInteger.ONE)} is not a trivial no-op: it forces
 * normalization of the internal point representation and ensures that the
 * returned point is in canonical affine form.
 * <p>
 * This normalization step is required for correct alignment with the
 * specification and for matching the published test vectors. Returning the
 * input point directly (without normalization) may leave the point in a
 * projective or mixed representation, which causes test vector comparisons
 * to fail even though the mathematical value of the point is the same.
 */
public class NistCurveProcessor implements CurveProcessor {

  public NistCurveProcessor() {
  }

  /**
   * Clears the cofactor of the given elliptic curve point. This operation
   * ensures the point is normalized to its canonical affine form, even
   * though the cofactor is 1 for NIST curves.
   *
   * @param ecPoint the elliptic curve point to process
   * @return the normalized elliptic curve point in canonical affine form
   */
  @Override
  public ECPoint clearCofactor(final ECPoint ecPoint) {
    return ecPoint.multiply(BigInteger.ONE);
  }
}
