package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Final-stage helpers from {@code theta_isogenies.c}: convert a theta
 * product structure back to a couple of elliptic curves, and a theta
 * product point back to a couple of (X : Z) Montgomery points.
 *
 * <p>Both functions are level-independent: they use only {@link Fp2} ops
 * and the HD types. They run after a successful
 * {@link ThetaSplittingCompute#splittingCompute} call so the null point
 * is already in "product" form.</p>
 */
final class ThetaProductHelpers
{
    private ThetaProductHelpers()
    {
    }

    /**
     * {@code theta_product_structure_to_elliptic_product}: extract a couple
     * of Montgomery curves (E1, E2) from a theta product structure.
     *
     * @return 1 on success, 0 if A is not a product theta point or has a
     *         zero coordinate, or the resulting curve denominators are zero.
     */
    public static int productStructureToEllipticProduct(GfField field, ThetaCoupleCurve E12, ThetaStructure A)
    {
        if (ThetaOps.isProductThetaPoint(field, A.nullPoint) == 0)
        {
            return 0;
        }

        EcOps.curveInit(E12.E1);
        EcOps.curveInit(E12.E2);
        // Propagate the GF(p²) tag so downstream EC ops on E1/E2 use the right prime.
        E12.E1.field = field;
        E12.E2.field = field;

        if ((Fp2.isZero(A.nullPoint.x)
            | Fp2.isZero(A.nullPoint.y)
            | Fp2.isZero(A.nullPoint.z)) != 0)
        {
            return 0;
        }

        Fp2 xx = Fp2.zero(), yy = Fp2.zero();

        // E2.A = -2(x^4 + y^4) / (x^4 - y^4)
        field.fp2Sqr(xx, A.nullPoint.x);
        field.fp2Sqr(yy, A.nullPoint.y);
        field.fp2Sqr(xx, xx);
        field.fp2Sqr(yy, yy);

        field.fp2Add(E12.E2.A, xx, yy);
        field.fp2Sub(E12.E2.C, xx, yy);
        field.fp2Add(E12.E2.A, E12.E2.A, E12.E2.A);
        field.fp2Neg(E12.E2.A, E12.E2.A);

        // E1.A = -2(x^4 + z^4) / (x^4 - z^4)
        field.fp2Sqr(xx, A.nullPoint.x);
        field.fp2Sqr(yy, A.nullPoint.z);
        field.fp2Sqr(xx, xx);
        field.fp2Sqr(yy, yy);

        field.fp2Add(E12.E1.A, xx, yy);
        field.fp2Sub(E12.E1.C, xx, yy);
        field.fp2Add(E12.E1.A, E12.E1.A, E12.E1.A);
        field.fp2Neg(E12.E1.A, E12.E1.A);

        if ((Fp2.isZero(E12.E1.C) | Fp2.isZero(E12.E2.C)) != 0)
        {
            return 0;
        }
        return 1;
    }

    /**
     * {@code theta_point_to_montgomery_point}: extract a couple of Montgomery
     * points (P1, P2) from a theta product point P and the structure A.
     *
     * @return 1 on success, 0 if P is not a product theta point or if both
     *         candidate (x, z) pairs are zero (P = (0:0:0:0)).
     */
    public static int pointToMontgomery(GfField field, ThetaCouplePoint P12, ThetaPoint P, ThetaStructure A)
    {
        if (ThetaOps.isProductThetaPoint(field, P) == 0)
        {
            return 0;
        }

        Fp2 temp = Fp2.zero();

        // Pick the (x, z) pair for P2: prefer (P.x, P.y); fall back to (P.z, P.t) if both are zero.
        Fp2 x = P.x;
        Fp2 z = P.y;
        if ((Fp2.isZero(x) & Fp2.isZero(z)) != 0)
        {
            x = P.z;
            z = P.t;
        }
        if ((Fp2.isZero(x) & Fp2.isZero(z)) != 0)
        {
            return 0;
        }

        // P2.X = A.null.y * x + A.null.x * z
        // P2.Z = -A.null.y * x + A.null.x * z
        field.fp2Mul(P12.P2.x, A.nullPoint.y, x);
        field.fp2Mul(temp, A.nullPoint.x, z);
        field.fp2Sub(P12.P2.z, temp, P12.P2.x);
        field.fp2Add(P12.P2.x, P12.P2.x, temp);

        // For P1: (x, z) = (P.x, P.z), fall back to (P.y, P.t).
        x = P.x;
        z = P.z;
        if ((Fp2.isZero(x) & Fp2.isZero(z)) != 0)
        {
            x = P.y;
            z = P.t;
        }

        // P1.X = A.null.z * x + A.null.x * z
        // P1.Z = -A.null.z * x + A.null.x * z
        field.fp2Mul(P12.P1.x, A.nullPoint.z, x);
        field.fp2Mul(temp, A.nullPoint.x, z);
        field.fp2Sub(P12.P1.z, temp, P12.P1.x);
        field.fp2Add(P12.P1.x, P12.P1.x, temp);
        return 1;
    }

}
