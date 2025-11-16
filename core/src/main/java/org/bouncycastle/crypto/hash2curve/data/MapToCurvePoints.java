package org.bouncycastle.crypto.hash2curve.data;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The Hash to field points produced by hash_to_field(msg, 2)
 */
public class MapToCurvePoints {
  private final ECPoint q0;
  private final ECPoint q1;

  public MapToCurvePoints(final ECPoint q0, final ECPoint q1) {
    this.q0 = q0;
    this.q1 = q1;
  }

  public ECPoint getQ0() {
    return q0;
  }

  public ECPoint getQ1() {
    return q1;
  }
}
