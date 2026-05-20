package org.bouncycastle.crypto.hash2curve.impl;

import java.math.BigInteger;

import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.crypto.hash2curve.data.AffineXY;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Curve processor for NIST curves (P-256, P-384, P-521) where the cofactor is 1.
 * <p>
 * Although the cofactor is 1 for all NIST curves, RFC 9380 still requires the "clear_cofactor" step
 * for consistency. In Bouncy Castle, invoking {@code ECPoint.multiply(BigInteger.ONE)} is not a
 * trivial no-op: it forces normalization of the internal point representation and ensures that the
 * returned point is in canonical affine form.
 * <p>
 * This normalization step is required for correct alignment with the specification and for matching
 * the published test vectors. Returning the input point directly (without normalization) may leave
 * the point in a projective or mixed representation, which causes test vector comparisons to fail
 * even though the mathematical value of the point is the same.
 */
public class NistCurveProcessor implements CurveProcessor
{
    /**
     * Constructs a new instance of NistCurveProcessor. This class processes elliptic curve operations
     * for NIST curves (P-256, P-384, P-521) with a cofactor of 1. It ensures compliance with RFC 9380
     * by performing required normalization steps, such as the "clear_cofactor" operation, to align the
     * elliptic curve points with their canonical affine form and match published test vectors.
     */
    public NistCurveProcessor()
    {
    }

    /** {@inheritDoc} */
    public ECPoint add(final ECPoint p, final ECPoint q)
    {
        return p.add(q);
    }

    /** {@inheritDoc} */
    public ECPoint clearCofactor(final ECPoint ecPoint)
    {
        return ecPoint.multiply(BigInteger.ONE);
    }

    public AffineXY mapToAffineXY(final ECPoint p)
    {
        return new AffineXY(p);
    }
}
