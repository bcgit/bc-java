package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Operations on theta points and theta structures. Java port of
 * {@code src/hd/ref/lvlx/theta_structure.c} plus the inline helpers in
 * {@code theta_structure.h} ({@code hadamard}, {@code pointwise_square},
 * {@code to_squared_theta}).
 */
final class ThetaOps
{
    private ThetaOps()
    {
    }

    /**
     * Hadamard transform on a theta point:
     * (x, y, z, t) ↦ (x+y+z+t, x−y+z−t, x+y−z−t, x−y−z+t).
     */
    public static void hadamard(GfField field, ThetaPoint out, ThetaPoint in)
    {
        Fp2 t1 = Fp2.zero(), t2 = Fp2.zero();
        Fp2 t3 = Fp2.zero(), t4 = Fp2.zero();
        field.fp2Add(t1, in.x, in.y);
        field.fp2Sub(t2, in.x, in.y);
        field.fp2Add(t3, in.z, in.t);
        field.fp2Sub(t4, in.z, in.t);

        Fp2 nx = Fp2.zero(), ny = Fp2.zero(), nz = Fp2.zero(), nt = Fp2.zero();
        field.fp2Add(nx, t1, t3);
        field.fp2Add(ny, t2, t4);
        field.fp2Sub(nz, t1, t3);
        field.fp2Sub(nt, t2, t4);
        Fp2.copy(out.x, nx);
        Fp2.copy(out.y, ny);
        Fp2.copy(out.z, nz);
        Fp2.copy(out.t, nt);
    }

    /** Squares each coordinate. */
    public static void pointwiseSquare(GfField field, ThetaPoint out, ThetaPoint in)
    {
        field.fp2Sqr(out.x, in.x);
        field.fp2Sqr(out.y, in.y);
        field.fp2Sqr(out.z, in.z);
        field.fp2Sqr(out.t, in.t);
    }

    /** {@code to_squared_theta}: pointwise square followed by Hadamard. */
    public static void toSquaredTheta(GfField field, ThetaPoint out, ThetaPoint in)
    {
        pointwiseSquare(field, out, in);
        hadamard(field, out, out);
    }

    /**
     * {@code theta_precomputation}: cache the 8 multiplicative precomputed
     * values used by doubling and (2,2)-isogenies. Idempotent.
     */
    public static void thetaPrecomputation(GfField field, ThetaStructure A)
    {
        if (A.precomputation)
        {
            return;
        }

        ThetaPoint Adual = new ThetaPoint();
        toSquaredTheta(field, Adual, A.nullPoint);

        Fp2 t1 = Fp2.zero(), t2 = Fp2.zero();
        field.fp2Mul(t1, Adual.x, Adual.y);
        field.fp2Mul(t2, Adual.z, Adual.t);
        field.fp2Mul(A.XYZ0, t1, Adual.z);
        field.fp2Mul(A.XYT0, t1, Adual.t);
        field.fp2Mul(A.YZT0, t2, Adual.y);
        field.fp2Mul(A.XZT0, t2, Adual.x);

        field.fp2Mul(t1, A.nullPoint.x, A.nullPoint.y);
        field.fp2Mul(t2, A.nullPoint.z, A.nullPoint.t);
        field.fp2Mul(A.xyz0, t1, A.nullPoint.z);
        field.fp2Mul(A.xyt0, t1, A.nullPoint.t);
        field.fp2Mul(A.yzt0, t2, A.nullPoint.y);
        field.fp2Mul(A.xzt0, t2, A.nullPoint.x);

        A.precomputation = true;
    }

    /** {@code double_point}: doubling on the theta variety. */
    private static void doublePoint(GfField field, ThetaPoint out, ThetaStructure A, ThetaPoint in)
    {
        toSquaredTheta(field, out, in);
        field.fp2Sqr(out.x, out.x);
        field.fp2Sqr(out.y, out.y);
        field.fp2Sqr(out.z, out.z);
        field.fp2Sqr(out.t, out.t);

        if (!A.precomputation)
        {
            thetaPrecomputation(field, A);
        }
        field.fp2Mul(out.x, out.x, A.YZT0);
        field.fp2Mul(out.y, out.y, A.XZT0);
        field.fp2Mul(out.z, out.z, A.XYT0);
        field.fp2Mul(out.t, out.t, A.XYZ0);

        hadamard(field, out, out);

        field.fp2Mul(out.x, out.x, A.yzt0);
        field.fp2Mul(out.y, out.y, A.xzt0);
        field.fp2Mul(out.z, out.z, A.xyt0);
        field.fp2Mul(out.t, out.t, A.xyz0);
    }

    /** {@code double_iter}: out ← [2^exp] in on the theta variety. */
    public static void doubleIter(GfField field, ThetaPoint out, ThetaStructure A, ThetaPoint in, int exp)
    {
        if (exp == 0)
        {
            Fp2.copy(out.x, in.x);
            Fp2.copy(out.y, in.y);
            Fp2.copy(out.z, in.z);
            Fp2.copy(out.t, in.t);
            return;
        }
        doublePoint(field, out, A, in);
        for (int i = 1; i < exp; i++)
        {
            doublePoint(field, out, A, out);
        }
    }

    /** {@code is_product_theta_point}: returns 0xFFFFFFFF iff x·t == y·z. */
    public static int isProductThetaPoint(GfField field, ThetaPoint P)
    {
        Fp2 t1 = Fp2.zero(), t2 = Fp2.zero();
        field.fp2Mul(t1, P.x, P.t);
        field.fp2Mul(t2, P.y, P.z);
        return Fp2.isEqual(t1, t2);
    }
}
