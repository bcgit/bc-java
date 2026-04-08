package org.bouncycastle.crypto.hash2curve;

import org.bouncycastle.crypto.hash2curve.data.AffineXY;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Process curve specific functions
 */
public interface CurveProcessor
{
    /**
     * Add two points in the curve group. Semantics are curve-model specific.
     */
    ECPoint add(ECPoint p, ECPoint q);

    /**
     * Clears the cofactor from the given elliptic curve point.
     *
     * @param ecPoint the elliptic curve point to process
     * @return the elliptic curve point with the cofactor cleared
     */
    ECPoint clearCofactor(ECPoint ecPoint);

    /**
     * Converts an elliptic-curve point into the affine (x, y) coordinate representation defined by the
     * hash-to-curve suite.
     *
     * <p>
     * The returned coordinates are intended for serialization, testing, and interoperability with the
     * reference outputs defined in RFC 9380. For most Weierstrass curves, this is simply the affine (x,
     * y) coordinates of the given point. For curves that use a different coordinate model in the
     * specification (e.g. Montgomery curves such as curve25519), this method applies the appropriate
     * coordinate transformation.
     * </p>
     *
     * <p>
     * This method does <em>not</em> change the underlying group element represented by the point. It
     * only changes how that point is expressed as field elements. The input point is expected to be a
     * valid point on the curve used by the implementation.
     * </p>
     *
     * @param p a valid elliptic-curve point
     * @return the affine (x, y) coordinates corresponding to the suite-specific representation of the
     * given point
     */
    AffineXY mapToAffineXY(ECPoint p);
}
