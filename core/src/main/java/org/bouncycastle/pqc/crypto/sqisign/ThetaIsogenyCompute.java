package org.bouncycastle.pqc.crypto.sqisign;


/**
 * (2, 2) theta-isogeny computation and evaluation. Java port of
 * {@code theta_isogeny_compute}, {@code theta_isogeny_compute_4},
 * {@code theta_isogeny_compute_2}, and {@code theta_isogeny_eval} from
 * {@code src/hd/ref/lvlx/theta_isogenies.c}.
 *
 * <p>All four are level-independent: they consume domain {@link ThetaStructure}
 * and torsion points and produce a {@link ThetaIsogeny} carrying the codomain
 * structure plus a per-isogeny precomputation vector used by.</p>
 */
final class ThetaIsogenyCompute
{
    private ThetaIsogenyCompute()
    {
    }

    private static void copyThetaStructure(ThetaStructure dst, ThetaStructure src)
    {
        Fp2.copy(dst.nullPoint.x, src.nullPoint.x);
        Fp2.copy(dst.nullPoint.y, src.nullPoint.y);
        Fp2.copy(dst.nullPoint.z, src.nullPoint.z);
        Fp2.copy(dst.nullPoint.t, src.nullPoint.t);
        dst.precomputation = src.precomputation;
        Fp2.copy(dst.XYZ0, src.XYZ0);
        Fp2.copy(dst.YZT0, src.YZT0);
        Fp2.copy(dst.XZT0, src.XZT0);
        Fp2.copy(dst.XYT0, src.XYT0);
        Fp2.copy(dst.xyz0, src.xyz0);
        Fp2.copy(dst.yzt0, src.yzt0);
        Fp2.copy(dst.xzt0, src.xzt0);
        Fp2.copy(dst.xyt0, src.xyt0);
        dst.field = src.field;
    }

    private static void copyThetaPoint(ThetaPoint dst, ThetaPoint src)
    {
        Fp2.copy(dst.x, src.x);
        Fp2.copy(dst.y, src.y);
        Fp2.copy(dst.z, src.z);
        Fp2.copy(dst.t, src.t);
    }

    /**
     * {@code theta_isogeny_compute}: given a domain theta structure A and two
     * 8-torsion points T1_8, T2_8, build the (2, 2)-isogeny with kernel
     * [4](T1_8, T2_8). Returns 0 if a projective-factor zero is hit (which
     * indicates a malformed input or an unexpected splitting); 1 on success.
     * When {@code verify} is set, four extra checks ensure the 4-torsion
     * doubles are isotropic.
     */
    public static int compute(GfField field, ThetaIsogeny out, ThetaStructure A,
                              ThetaPoint T1_8, ThetaPoint T2_8,
                              boolean hadamardBool1, boolean hadamardBool2, boolean verify)
    {
        out.hadamardBool1 = hadamardBool1;
        out.hadamardBool2 = hadamardBool2;
        copyThetaStructure(out.domain, A);
        copyThetaPoint(out.T1_8, T1_8);
        copyThetaPoint(out.T2_8, T2_8);
        out.codomain.precomputation = false;

        ThetaPoint TT1 = new ThetaPoint();
        ThetaPoint TT2 = new ThetaPoint();
        if (hadamardBool1)
        {
            ThetaOps.hadamard(field, TT1, T1_8);
            ThetaOps.toSquaredTheta(field, TT1, TT1);
            ThetaOps.hadamard(field, TT2, T2_8);
            ThetaOps.toSquaredTheta(field, TT2, TT2);
        }
        else
        {
            ThetaOps.toSquaredTheta(field, TT1, T1_8);
            ThetaOps.toSquaredTheta(field, TT2, T2_8);
        }

        // Reject if the projective factor ABCDxzw is zero.
        if ((Fp2.isZero(TT2.x) | Fp2.isZero(TT2.y)
            | Fp2.isZero(TT2.z) | Fp2.isZero(TT2.t)
            | Fp2.isZero(TT1.x) | Fp2.isZero(TT1.y)) != 0)
        {
            return 0;
        }

        Fp2 t1 = Fp2.zero(), t2 = Fp2.zero();
        field.fp2Mul(t1, TT1.x, TT2.y);
        field.fp2Mul(t2, TT1.y, TT2.x);
        field.fp2Mul(out.codomain.nullPoint.x, TT2.x, t1);
        field.fp2Mul(out.codomain.nullPoint.y, TT2.y, t2);
        field.fp2Mul(out.codomain.nullPoint.z, TT2.z, t1);
        field.fp2Mul(out.codomain.nullPoint.t, TT2.t, t2);

        Fp2 t3 = Fp2.zero();
        field.fp2Mul(t3, TT2.z, TT2.t);
        field.fp2Mul(out.precomputation.x, t3, TT1.y);
        field.fp2Mul(out.precomputation.y, t3, TT1.x);
        Fp2.copy(out.precomputation.z, out.codomain.nullPoint.t);
        Fp2.copy(out.precomputation.t, out.codomain.nullPoint.z);

        if (verify)
        {
            field.fp2Mul(t1, TT1.x, out.precomputation.x);
            field.fp2Mul(t2, TT1.y, out.precomputation.y);
            if (Fp2.isEqual(t1, t2) == 0)
            {
                return 0;
            }
            field.fp2Mul(t1, TT1.z, out.precomputation.z);
            field.fp2Mul(t2, TT1.t, out.precomputation.t);
            if (Fp2.isEqual(t1, t2) == 0)
            {
                return 0;
            }
            field.fp2Mul(t1, TT2.x, out.precomputation.x);
            field.fp2Mul(t2, TT2.z, out.precomputation.z);
            if (Fp2.isEqual(t1, t2) == 0)
            {
                return 0;
            }
            field.fp2Mul(t1, TT2.y, out.precomputation.y);
            field.fp2Mul(t2, TT2.t, out.precomputation.t);
            if (Fp2.isEqual(t1, t2) == 0)
            {
                return 0;
            }
        }

        if (hadamardBool2)
        {
            ThetaOps.hadamard(field, out.codomain.nullPoint, out.codomain.nullPoint);
        }
        return 1;
    }

    /**
     * {@code theta_isogeny_compute_4}: (2,2) isogeny when only 4-torsion above
     * the kernel is known. Uses fp2 square roots — caller must ensure the
     * inputs are well-formed (only used on the signing side).
     */
    public static void compute4(GfField field, ThetaIsogeny out, ThetaStructure A,
                                ThetaPoint T1_4, ThetaPoint T2_4,
                                boolean hadamardBool1, boolean hadamardBool2)
    {
        out.hadamardBool1 = hadamardBool1;
        out.hadamardBool2 = hadamardBool2;
        copyThetaStructure(out.domain, A);
        copyThetaPoint(out.T1_8, T1_4);
        copyThetaPoint(out.T2_8, T2_4);
        out.codomain.precomputation = false;

        ThetaPoint TT1 = new ThetaPoint();
        ThetaPoint TT2 = new ThetaPoint();
        if (hadamardBool1)
        {
            ThetaOps.hadamard(field, TT1, T1_4);
            ThetaOps.toSquaredTheta(field, TT1, TT1);
            ThetaOps.hadamard(field, TT2, A.nullPoint);
            ThetaOps.toSquaredTheta(field, TT2, TT2);
        }
        else
        {
            ThetaOps.toSquaredTheta(field, TT1, T1_4);
            ThetaOps.toSquaredTheta(field, TT2, A.nullPoint);
        }

        Fp2 sqaabb = Fp2.zero(), sqaacc = Fp2.zero();
        field.fp2Mul(sqaabb, TT2.x, TT2.y);
        field.fp2Mul(sqaacc, TT2.x, TT2.z);
        field.fp2Sqrt(sqaabb);
        field.fp2Sqrt(sqaacc);

        field.fp2Mul(out.codomain.nullPoint.y, sqaabb, sqaacc);
        field.fp2Mul(out.precomputation.t, out.codomain.nullPoint.y, TT1.z);
        field.fp2Mul(out.codomain.nullPoint.y, out.codomain.nullPoint.y, TT1.x);

        field.fp2Mul(out.codomain.nullPoint.t, TT1.z, sqaabb);
        field.fp2Mul(out.codomain.nullPoint.t, out.codomain.nullPoint.t, TT2.x);

        field.fp2Mul(out.codomain.nullPoint.x, TT1.x, TT2.x);
        field.fp2Mul(out.codomain.nullPoint.z, out.codomain.nullPoint.x, TT2.z);
        field.fp2Mul(out.codomain.nullPoint.x, out.codomain.nullPoint.x, sqaacc);

        field.fp2Mul(out.precomputation.x, TT1.x, TT2.t);
        field.fp2Mul(out.precomputation.z, out.precomputation.x, TT2.y);
        field.fp2Mul(out.precomputation.x, out.precomputation.x, TT2.z);
        field.fp2Mul(out.precomputation.y, out.precomputation.x, sqaabb);
        field.fp2Mul(out.precomputation.x, out.precomputation.x, TT2.y);
        field.fp2Mul(out.precomputation.z, out.precomputation.z, sqaacc);
        field.fp2Mul(out.precomputation.t, out.precomputation.t, TT2.y);

        if (hadamardBool2)
        {
            ThetaOps.hadamard(field, out.codomain.nullPoint, out.codomain.nullPoint);
        }
    }

    /**
     * {@code theta_isogeny_compute_2}: (2,2) isogeny when only the 2-torsion
     * kernel is known. Uses fp2 square roots.
     */
    public static void compute2(GfField field, ThetaIsogeny out, ThetaStructure A,
                                ThetaPoint T1_2, ThetaPoint T2_2,
                                boolean hadamardBool1, boolean hadamardBool2)
    {
        out.hadamardBool1 = hadamardBool1;
        out.hadamardBool2 = hadamardBool2;
        copyThetaStructure(out.domain, A);
        copyThetaPoint(out.T1_8, T1_2);
        copyThetaPoint(out.T2_8, T2_2);
        out.codomain.precomputation = false;

        ThetaPoint TT2 = new ThetaPoint();
        if (hadamardBool1)
        {
            ThetaOps.hadamard(field, TT2, A.nullPoint);
            ThetaOps.toSquaredTheta(field, TT2, TT2);
        }
        else
        {
            ThetaOps.toSquaredTheta(field, TT2, A.nullPoint);
        }

        Fp2.copy(out.codomain.nullPoint.x, TT2.x);
        field.fp2Mul(out.codomain.nullPoint.y, TT2.x, TT2.y);
        field.fp2Mul(out.codomain.nullPoint.z, TT2.x, TT2.z);
        field.fp2Mul(out.codomain.nullPoint.t, TT2.x, TT2.t);
        field.fp2Sqrt(out.codomain.nullPoint.y);
        field.fp2Sqrt(out.codomain.nullPoint.z);
        field.fp2Sqrt(out.codomain.nullPoint.t);

        field.fp2Mul(out.precomputation.x, TT2.z, TT2.t);
        field.fp2Mul(out.precomputation.y, out.precomputation.x, out.codomain.nullPoint.y);
        field.fp2Mul(out.precomputation.x, out.precomputation.x, TT2.y);
        field.fp2Mul(out.precomputation.z, TT2.t, out.codomain.nullPoint.z);
        field.fp2Mul(out.precomputation.z, out.precomputation.z, TT2.y);
        field.fp2Mul(out.precomputation.t, TT2.z, out.codomain.nullPoint.t);
        field.fp2Mul(out.precomputation.t, out.precomputation.t, TT2.y);

        if (hadamardBool2)
        {
            ThetaOps.hadamard(field, out.codomain.nullPoint, out.codomain.nullPoint);
        }
    }

    /**
     * {@code theta_isogeny_eval}: evaluate phi on a theta point P.
     */
    public static void eval(GfField field, ThetaPoint out, ThetaIsogeny phi, ThetaPoint P)
    {
        if (phi.hadamardBool1)
        {
            ThetaOps.hadamard(field, out, P);
            ThetaOps.toSquaredTheta(field, out, out);
        }
        else
        {
            ThetaOps.toSquaredTheta(field, out, P);
        }
        field.fp2Mul(out.x, out.x, phi.precomputation.x);
        field.fp2Mul(out.y, out.y, phi.precomputation.y);
        field.fp2Mul(out.z, out.z, phi.precomputation.z);
        field.fp2Mul(out.t, out.t, phi.precomputation.t);

        if (phi.hadamardBool2)
        {
            ThetaOps.hadamard(field, out, out);
        }
    }

    // ------------------------------------------------------------------
    // lvl1 convenience overloads
    // ------------------------------------------------------------------

    public static int compute(ThetaIsogeny out, ThetaStructure A,
                              ThetaPoint T1_8, ThetaPoint T2_8,
                              boolean hadamardBool1, boolean hadamardBool2, boolean verify)
    {
        int r = compute(A.field, out, A, T1_8, T2_8, hadamardBool1, hadamardBool2, verify);
        out.codomain.field = A.field;
        return r;
    }
}
