package org.bouncycastle.crypto.hash2curve.data;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/** Simple holder for affine field coordinates. */
public final class AffineXY
{
    private final BigInteger x;
    private final BigInteger y;

    /**
     * Constructs an {@code AffineXY} object representing the affine coordinates of an elliptic curve
     * point.
     *
     * @param x the x-coordinate of the affine point
     * @param y the y-coordinate of the affine point
     */
    public AffineXY(BigInteger x, BigInteger y)
    {
        this.x = x;
        this.y = y;
    }

    /**
     * Constructs an {@code AffineXY} object representing the affine coordinates of the provided
     * elliptic curve point.
     *
     * @param point the elliptic curve point from which the affine coordinates will be extracted
     * @throws IllegalArgumentException if the provided point is at infinity
     */
    public AffineXY(ECPoint point)
    {
        this(point, true);
    }

    /**
     * Constructs an {@code AffineXY} object representing the affine coordinates of the provided
     * elliptic curve point.
     *
     * @param point the elliptic curve point from which the affine coordinates will be extracted
     * @param normalize {@code true} if the point should be normalized before extracting coordinates,
     * {@code false} otherwise
     * @throws IllegalArgumentException if the provided point is at infinity
     */
    public AffineXY(ECPoint point, boolean normalize)
    {
        if (point.isInfinity())
        {
            throw new IllegalArgumentException("Cannot extract affine coordinates from point at infinity");
        }
        if (normalize)
        {
            point = point.normalize();
        }
        this.x = point.getAffineXCoord().toBigInteger();
        this.y = point.getAffineYCoord().toBigInteger();
    }

    /**
     * Converts the affine coordinates of this object into an elliptic curve point on the specified
     * curve.
     *
     * @param curve the elliptic curve to which the point belongs
     * @return an {@code ECPoint} object created using the affine coordinates of this object on the
     * given curve
     */
    public ECPoint toPoint(ECCurve curve)
    {
        return curve.createPoint(getX(), getY()).normalize();
    }

    /**
     * Retrieves the x-coordinate of the affine point.
     *
     * @return the x-coordinate as a {@code BigInteger}
     */
    public BigInteger getX()
    {
        return x;
    }

    /**
     * Retrieves the y-coordinate of the affine point.
     *
     * @return the y-coordinate as a {@code BigInteger}
     */
    public BigInteger getY()
    {
        return y;
    }
}
