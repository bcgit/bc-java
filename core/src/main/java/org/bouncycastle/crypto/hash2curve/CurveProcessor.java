package org.bouncycastle.crypto.hash2curve;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Process curve specific functions
 */
public interface CurveProcessor {

  /**
   * Clears the cofactor from the given elliptic curve point.
   *
   * @param ecPoint the elliptic curve point to process
   * @return the elliptic curve point with the cofactor cleared
   */
  ECPoint clearCofactor(ECPoint ecPoint);

}
