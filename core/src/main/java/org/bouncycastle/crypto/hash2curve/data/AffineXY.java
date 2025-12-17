package org.bouncycastle.crypto.hash2curve.data;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/** Simple holder for affine field coordinates. */
public final class AffineXY {
  private final BigInteger x;
  private final BigInteger y;

  public AffineXY(BigInteger x, BigInteger y) {
    this.x = x;
    this.y = y;
  }

  public AffineXY(ECPoint point) {
    this(point, true);
  }

  /**
   * Constructs an {@code AffineXY} object representing the affine coordinates of the provided elliptic curve point.
   *
   * @param point the elliptic curve point from which the affine coordinates will be extracted
   * @param normalize {@code true} if the point should be normalized before extracting coordinates, {@code false} otherwise
   * @throws IllegalArgumentException if the provided point is at infinity
   */
  public AffineXY(ECPoint point, boolean normalize) {
    if (point.isInfinity()) {
      throw new IllegalArgumentException("Cannot extract affine coordinates from point at infinity");
    }
    if (normalize) {
      point = point.normalize();
    }
    this.x = point.getAffineXCoord().toBigInteger();
    this.y = point.getAffineYCoord().toBigInteger();
  }

  /**
   * Converts the affine coordinates of this object into an elliptic curve point
   * on the specified curve.
   *
   * @param curve the elliptic curve to which the point belongs
   * @return an {@code ECPoint} object created using the affine coordinates
   *         of this object on the given curve
   */
  public ECPoint toPoint(ECCurve curve) {
    return curve.createPoint(getX(), getY()).normalize();
  }

  public BigInteger getX() {
    return x;
  }

  public BigInteger getY() {
    return y;
  }
}
