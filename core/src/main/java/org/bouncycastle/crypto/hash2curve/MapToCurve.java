package org.bouncycastle.crypto.hash2curve;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Interface for Map to Curve
 */
public interface MapToCurve {

  /**
   * Processes the given BigInteger element and maps it to a point on the elliptic curve, as defined
   * by the hash 2 curve specification
   *
   * @param element the input BigInteger element to be mapped to a point on the curve
   * @return the elliptic curve point corresponding to the input element
   */
  ECPoint process(BigInteger element);

}
