package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Init / normalize / predicate operations on Montgomery curves and x-only
 * points. Java port of the corresponding helpers in
 * {@code src/ec/ref/lvlx/ec.c}.
 *
 * <p>Operations whose result is level-independent (point/curve init, cswap,
 * select, isZero on projective coordinates) don't take a {@link GfField};
 * operations that involve modular arithmetic (inv, mul, normalize, j-inv, …)
 * do, and provide an lvl1 convenience overload for existing callers.</p>
 */
final class EcOps
{
    private EcOps()
    {
    }

    /** {@code ec_point_init}: set to point at infinity (1 : 0). */
    public static void pointInit(EcPoint P)
    {
        Fp2.setOne(P.x);
        Fp2.setZero(P.z);
    }

    /** {@code ec_curve_init}: A = 0, C = 1, A24 = (1 : 0). */
    public static void curveInit(EcCurve E)
    {
        Fp2.setZero(E.A);
        Fp2.setOne(E.C);
        pointInit(E.A24);
        E.isA24ComputedAndNormalized = false;
    }

    /** Constant-time point select. {@code option == 0} keeps {@code P1}; {@code option == 0xFFFFFFFF} switches to {@code P2}. */
    public static void selectPoint(EcPoint Q, EcPoint P1, EcPoint P2, int option)
    {
        Fp2.select(Q.x, P1.x, P2.x, option);
        Fp2.select(Q.z, P1.z, P2.z, option);
    }

    public static void cswapPoints(EcPoint P, EcPoint Q, int option)
    {
        Fp2.cswap(P.x, Q.x, option);
        Fp2.cswap(P.z, Q.z, option);
    }

    /** {@code ec_normalize_point}: reduce (X : Z) to (X/Z : 1). */
    public static void normalizePoint(GfField field, EcPoint P)
    {
        field.fp2Inv(P.z);
        field.fp2Mul(P.x, P.x, P.z);
        Fp2.setOne(P.z);
    }

    /** {@code ec_normalize_curve}: reduce (A : C) to (A/C : 1). */
    public static void normalizeCurve(GfField field, EcCurve E)
    {
        field.fp2Inv(E.C);
        field.fp2Mul(E.A, E.A, E.C);
        Fp2.setOne(E.C);
    }

    /** {@code AC_to_A24} inline helper: A24 = (A + 2C : 4C). */
    public static void acToA24(GfField field, EcPoint A24, EcCurve E)
    {
        if (E.isA24ComputedAndNormalized)
        {
            EcPoint.copy(A24, E.A24);
            return;
        }
        field.fp2Add(A24.z, E.C, E.C);          // 2C
        field.fp2Add(A24.x, E.A, A24.z);        // A + 2C
        field.fp2Add(A24.z, A24.z, A24.z);      // 4C
    }

    /** {@code A24_to_AC}: recover (A : C) from (A + 2C : 4C). */
    public static void a24ToAc(GfField field, EcCurve E, EcPoint A24)
    {
        field.fp2Add(E.A, A24.x, A24.x);
        field.fp2Sub(E.A, E.A, A24.z);
        field.fp2Add(E.A, E.A, E.A);
        Fp2.copy(E.C, A24.z);
    }

    /** {@code ec_curve_normalize_A24}: cache normalised A24. */
    public static void curveNormalizeA24(GfField field, EcCurve E)
    {
        if (!E.isA24ComputedAndNormalized)
        {
            acToA24(field, E.A24, E);
            normalizePoint(field, E.A24);
            E.isA24ComputedAndNormalized = true;
        }
    }

    /** {@code ec_normalize_curve_and_A24}. */
    public static void normalizeCurveAndA24(GfField field, EcCurve E)
    {
        if (Fp2.isOne(E.C) == 0)
        {
            normalizeCurve(field, E);
        }
        if (!E.isA24ComputedAndNormalized)
        {
            // (A + 2) / 4 with A normalised
            field.fp2AddOne(E.A24.x, E.A);
            field.fp2AddOne(E.A24.x, E.A24.x);
            Fp.copy(E.A24.x.im, E.A.im);
            field.fp2Half(E.A24.x, E.A24.x);
            field.fp2Half(E.A24.x, E.A24.x);
            Fp2.setOne(E.A24.z);
            E.isA24ComputedAndNormalized = true;
        }
    }

    /** {@code ec_is_zero}: point at infinity iff z = 0. */
    public static int isZero(EcPoint P)
    {
        return Fp2.isZero(P.z);
    }

    public static int hasZeroCoordinate(EcPoint P)
    {
        return Fp2.isZero(P.x) | Fp2.isZero(P.z);
    }

    /** {@code ec_is_equal}: equality of projective points. */
    public static int isEqual(GfField field, EcPoint P, EcPoint Q)
    {
        Fp2 t0 = Fp2.zero();
        Fp2 t1 = Fp2.zero();
        int lZero = isZero(P);
        int rZero = isZero(Q);
        field.fp2Mul(t0, P.x, Q.z);
        field.fp2Mul(t1, P.z, Q.x);
        int lrEqual = Fp2.isEqual(t0, t1);
        // Both zero OR both non-zero AND coordinate-products equal.
        return (lZero & rZero) | (~lZero & ~rZero & lrEqual);
    }

    /** {@code ec_curve_verify_A}: A² ≠ 4. */
    public static int curveVerifyA(GfField field, Fp2 A)
    {
        Fp2 t = Fp2.one();
        field.fpAdd(t.re, t.re, t.re);          // t = 2
        if (Fp2.isEqual(A, t) != 0)
        {
            return 0;
        }
        field.fpNeg(t.re, t.re);                // t = -2
        if (Fp2.isEqual(A, t) != 0)
        {
            return 0;
        }
        return 1;
    }

    /** {@code ec_curve_init_from_A}: validate and seed (A : 1). */
    public static int curveInitFromA(GfField field, EcCurve E, Fp2 A)
    {
        curveInit(E);
        Fp2.copy(E.A, A);
        return curveVerifyA(field, A);
    }

    /** {@code ec_j_inv}: j-invariant of the projective Montgomery curve. */
    public static void jInv(GfField field, Fp2 jInv, EcCurve curve)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero();
        field.fp2Sqr(t1, curve.C);
        field.fp2Sqr(jInv, curve.A);
        field.fp2Add(t0, t1, t1);
        field.fp2Sub(t0, jInv, t0);
        field.fp2Sub(t0, t0, t1);
        field.fp2Sub(jInv, t0, t1);
        field.fp2Sqr(t1, t1);
        field.fp2Mul(jInv, jInv, t1);
        field.fp2Add(t0, t0, t0);
        field.fp2Add(t0, t0, t0);
        field.fp2Sqr(t1, t0);
        field.fp2Mul(t0, t0, t1);
        field.fp2Add(t0, t0, t0);
        field.fp2Add(t0, t0, t0);
        field.fp2Inv(jInv);
        field.fp2Mul(jInv, t0, jInv);
    }

    /** {@code ec_is_two_torsion}. */
    public static int isTwoTorsion(GfField field, EcPoint P, EcCurve E)
    {
        if (isZero(P) != 0)
        {
            return 0;
        }
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero();
        field.fp2Add(t0, P.x, P.z);
        field.fp2Sqr(t0, t0);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Sqr(t1, t1);
        field.fp2Sub(t2, t0, t1);
        field.fp2Add(t1, t0, t1);
        field.fp2Mul(t2, t2, E.A);
        field.fp2Mul(t1, t1, E.C);
        field.fp2Add(t1, t1, t1);
        field.fp2Add(t0, t1, t2);
        int xIsZero = Fp2.isZero(P.x);
        int tmpIsZero = Fp2.isZero(t0);
        return xIsZero | tmpIsZero;
    }

    /** {@code ec_is_four_torsion}. */
    public static int isFourTorsion(GfField field, EcPoint P, EcCurve E)
    {
        EcPoint test = new EcPoint();
        EcArith.xDBL_A24(field, test, P, E.A24, E.isA24ComputedAndNormalized);
        return isTwoTorsion(field, test, E);
    }

    /** {@code ec_is_basis_four_torsion}. */
    public static int isBasisFourTorsion(GfField field, EcBasis B, EcCurve E)
    {
        EcPoint P2 = new EcPoint();
        EcPoint Q2 = new EcPoint();
        EcArith.xDBL_A24(field, P2, B.P, E.A24, E.isA24ComputedAndNormalized);
        EcArith.xDBL_A24(field, Q2, B.Q, E.A24, E.isA24ComputedAndNormalized);
        return isTwoTorsion(field, P2, E) & isTwoTorsion(field, Q2, E) & ~isEqual(field, P2, Q2);
    }

    // ------------------------------------------------------------------
    // Field-from-curve convenience overloads (see EcLadder for rationale).
    // Overloads that don't take a curve still default to lvl1.
    // ------------------------------------------------------------------

    public static void normalizeCurve(EcCurve E)
    {
        normalizeCurve(E.field, E);
    }

    public static void curveNormalizeA24(EcCurve E)
    {
        curveNormalizeA24(E.field, E);
    }

    public static void normalizeCurveAndA24(EcCurve E)
    {
        normalizeCurveAndA24(E.field, E);
    }

    /**
     * Lvl1-default convenience overload — for unit tests on lvl1 curves
     * only. Production paths that may run under lvl3 / lvl5 must use the
     * field-taking {@link #isEqual(GfField, EcPoint, EcPoint)} form.
     */
    public static int isEqual(EcPoint P, EcPoint Q)
    {
        return isEqual(GfFieldLvl1.INSTANCE, P, Q);
    }

    public static int curveVerifyA(Fp2 A)
    {
        return curveVerifyA(GfFieldLvl1.INSTANCE, A);
    }

    public static int curveInitFromA(EcCurve E, Fp2 A)
    {
        return curveInitFromA(E.field, E, A);
    }

    public static int isTwoTorsion(EcPoint P, EcCurve E)
    {
        return isTwoTorsion(E.field, P, E);
    }

    public static int isBasisFourTorsion(EcBasis B, EcCurve E)
    {
        return isBasisFourTorsion(E.field, B, E);
    }
}
