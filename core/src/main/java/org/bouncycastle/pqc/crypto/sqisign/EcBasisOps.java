package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Helpers from {@code src/ec/ref/lvlx/basis.c} that don't depend on the
 * level-specific precomp tables. The top-level {@code ec_curve_to_basis_2f_*}
 * functions will land in a separate, lvl1-specific class once the precomp
 * constants ({@code p_cofactor_for_2f}, {@code TORSION_EVEN_POWER},
 * {@code BASIS_E0_PX}, {@code BASIS_E0_QX}) are regenerated for Java.
 */
final class EcBasisOps
{
    private EcBasisOps()
    {
    }

    /**
     * {@code ec_recover_y}: recover the y-coordinate from x on the Montgomery
     * curve {@code y² = x³ + (A/C) x² + x}. Returns 0xFFFFFFFF iff (x, y) is
     * on the curve (square root verified).
     */
    public static int recoverY(GfField field, Fp2 y, Fp2 Px, EcCurve curve)
    {
        Fp2 t0 = Fp2.zero();
        field.fp2Sqr(t0, Px);
        field.fp2Mul(y, t0, curve.A);     // A·x²
        field.fp2Add(y, y, Px);            // A·x² + x
        field.fp2Mul(t0, t0, Px);
        field.fp2Add(y, y, t0);            // x³ + A·x² + x
        return field.fp2SqrtVerify(y);
    }

    /**
     * Deterministic choice for x(P - Q) given x(P), x(Q). Based on Proposition 3
     * of <a href="https://eprint.iacr.org/2017/518.pdf">eprint 2017/518</a>.
     * Mirrors C {@code difference_point}.
     */
    public static void differencePoint(GfField field, EcPoint PQ, EcPoint P, EcPoint Q, EcCurve curve)
    {
        Fp2 Bxx = Fp2.zero(), Bxz = Fp2.zero(), Bzz = Fp2.zero();
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero();

        field.fp2Mul(t0, P.x, Q.x);
        field.fp2Mul(t1, P.z, Q.z);
        field.fp2Sub(Bxx, t0, t1);
        field.fp2Sqr(Bxx, Bxx);
        field.fp2Mul(Bxx, Bxx, curve.C);
        field.fp2Add(Bxz, t0, t1);
        field.fp2Mul(t0, P.x, Q.z);
        field.fp2Mul(t1, P.z, Q.x);
        field.fp2Add(Bzz, t0, t1);
        field.fp2Mul(Bxz, Bxz, Bzz);
        field.fp2Sub(Bzz, t0, t1);
        field.fp2Sqr(Bzz, Bzz);
        field.fp2Mul(Bzz, Bzz, curve.C);
        field.fp2Mul(Bxz, Bxz, curve.C);
        field.fp2Mul(t0, t0, t1);
        field.fp2Mul(t0, t0, curve.A);
        field.fp2Add(t0, t0, t0);
        field.fp2Add(Bxz, Bxz, t0);

        // Normalize by C·C̄²·(P.z)̄²·(Q.z)̄²  — bar = Frobenius conjugate.
        // The conjugate of (re + im·i) is (re - im·i): keep re, negate im.
        Fp.copy(t0.re, curve.C.re);
        field.fpNeg(t0.im, curve.C.im);
        field.fp2Sqr(t0, t0);
        field.fp2Mul(t0, t0, curve.C);

        Fp.copy(t1.re, P.z.re);
        field.fpNeg(t1.im, P.z.im);
        field.fp2Sqr(t1, t1);
        field.fp2Mul(t0, t0, t1);

        Fp.copy(t1.re, Q.z.re);
        field.fpNeg(t1.im, Q.z.im);
        field.fp2Sqr(t1, t1);
        field.fp2Mul(t0, t0, t1);

        field.fp2Mul(Bxx, Bxx, t0);
        field.fp2Mul(Bxz, Bxz, t0);
        field.fp2Mul(Bzz, Bzz, t0);

        // Solve the quadratic: t0 = Bxz² - Bxx·Bzz; PQ.x = Bxz + sqrt(t0); PQ.z = Bzz.
        field.fp2Sqr(t0, Bxz);
        field.fp2Mul(t1, Bxx, Bzz);
        field.fp2Sub(t0, t0, t1);
        field.fp2Sqrt(t0);
        field.fp2Add(PQ.x, Bxz, t0);
        Fp2.copy(PQ.z, Bzz);
    }

    /**
     * {@code lift_basis_normalized}: lift x-only basis to Jacobian assuming
     * the curve is normalised (C = 1) and B.P.z = 1.
     */
    public static int liftBasisNormalized(GfField field, JacPoint P, JacPoint Q, EcBasis B, EcCurve E)
    {
        Fp2.copy(P.x, B.P.x);
        Fp2.copy(Q.x, B.Q.x);
        Fp2.copy(Q.z, B.Q.z);
        Fp2.setOne(P.z);
        int ret = recoverY(field, P.y, P.x, E);

        Fp2 v1 = Fp2.zero(), v2 = Fp2.zero(), v3 = Fp2.zero(), v4 = Fp2.zero();
        field.fp2Mul(v1, P.x, Q.z);
        field.fp2Add(v2, Q.x, v1);
        field.fp2Sub(v3, Q.x, v1);
        field.fp2Sqr(v3, v3);
        field.fp2Mul(v3, v3, B.PmQ.x);
        field.fp2Add(v1, E.A, E.A);
        field.fp2Mul(v1, v1, Q.z);
        field.fp2Add(v2, v2, v1);
        field.fp2Mul(v4, P.x, Q.x);
        field.fp2Add(v4, v4, Q.z);
        field.fp2Mul(v2, v2, v4);
        field.fp2Mul(v1, v1, Q.z);
        field.fp2Sub(v2, v2, v1);
        field.fp2Mul(v2, v2, B.PmQ.z);
        field.fp2Sub(Q.y, v3, v2);
        field.fp2Add(v1, P.y, P.y);
        field.fp2Mul(v1, v1, Q.z);
        field.fp2Mul(v1, v1, B.PmQ.z);
        field.fp2Mul(Q.x, Q.x, v1);
        field.fp2Mul(Q.z, Q.z, v1);

        field.fp2Sqr(v1, Q.z);
        field.fp2Mul(Q.y, Q.y, v1);
        field.fp2Mul(Q.x, Q.x, Q.z);
        return ret;
    }

    /**
     * {@code lift_basis}: normalise the curve + first basis point, then call
     * {@link #liftBasisNormalized}.
     */
    public static int liftBasis(GfField field, JacPoint P, JacPoint Q, EcBasis B, EcCurve E)
    {
        Fp2[] inverses = new Fp2[]{B.P.z.copy(), E.C.copy()};
        field.fp2BatchedInv(inverses, 2);

        Fp2.setOne(B.P.z);
        Fp2.setOne(E.C);
        field.fp2Mul(B.P.x, B.P.x, inverses[0]);
        field.fp2Mul(E.A, E.A, inverses[1]);

        return liftBasisNormalized(field, P, Q, B, E);
    }

    /**
     * {@code is_on_curve}: returns 0xFFFFFFFF iff (x, ?) is on the curve.
     * Assumes the curve is normalised (C = 1).
     */
    public static int isOnCurve(GfField field, Fp2 x, EcCurve curve)
    {
        Fp2 t0 = Fp2.zero();
        field.fp2Add(t0, x, curve.A);
        field.fp2Mul(t0, t0, x);
        field.fp2AddOne(t0, t0);
        field.fp2Mul(t0, t0, x);
        return field.fp2IsSquare(t0);
    }

    /**
     * {@code find_nqr_factor}: search for an integer b such that 1 + b² is
     * a non-quadratic residue in Fp. Writes x = -A / (1 + i·b) and returns
     * the hint (b, capped at 127; 0 signals overflow / fallback).
     */
    public static int findNqrFactor(GfField field, Fp2 x, EcCurve curve, int start)
    {
        Fp tmp = new Fp();
        boolean qrB = true;
        int n = start;

        Fp2 z = Fp2.zero();
        Fp2 t0 = Fp2.zero();
        Fp2 t1 = Fp2.zero();
        boolean found;

        do
        {
            while (qrB)
            {
                Fp.setSmall(tmp, (long)n * n + 1L);
                qrB = field.fpIsSquare(tmp) != 0;
                n++;
            }
            // b = n - 1; z = 1 + i·b; t0 = i·b
            Fp b = new Fp();
            Fp.setSmall(b, n - 1);
            Fp2.setZero(t0);
            Fp2.setOne(z);
            Fp.copy(z.im, b);
            Fp.copy(t0.im, b);

            // A²·(z - 1) - z²
            field.fp2Sqr(t1, curve.A);
            field.fp2Mul(t0, t0, t1);
            field.fp2Sqr(t1, z);
            field.fp2Sub(t0, t0, t1);
            found = field.fp2IsSquare(t0) == 0;

            qrB = true;
        }
        while (!found);

        // x = -A / (1 + i·b)
        Fp2.copy(x, z);
        field.fp2Inv(x);
        field.fp2Mul(x, x, curve.A);
        field.fp2Neg(x, x);

        return n <= 128 ? n - 1 : 0;
    }

    /**
     * {@code find_nA_x_coord}: find x = n·A (with n the smallest positive
     * integer making x a valid curve point). Caller must ensure A is NQR.
     * Returns the hint (n, capped at 127; 0 signals overflow).
     */
    public static int findNaXCoord(GfField field, Fp2 x, EcCurve curve, int start)
    {
        int n = start;
        if (n == 1)
        {
            Fp2.copy(x, curve.A);
        }
        else
        {
            field.fp2MulSmall(x, curve.A, n);
        }
        while (isOnCurve(field, x, curve) == 0)
        {
            field.fp2Add(x, x, curve.A);
            n++;
        }
        return n < 128 ? n : 0;
    }

    // ------------------------------------------------------------------
    // Field-from-curve convenience overloads (see EcLadder for rationale).
    // ------------------------------------------------------------------

    public static void differencePoint(EcPoint PQ, EcPoint P, EcPoint Q, EcCurve curve)
    {
        differencePoint(curve.field, PQ, P, Q, curve);
    }

    public static int liftBasisNormalized(JacPoint P, JacPoint Q, EcBasis B, EcCurve E)
    {
        return liftBasisNormalized(E.field, P, Q, B, E);
    }

    public static int liftBasis(JacPoint P, JacPoint Q, EcBasis B, EcCurve E)
    {
        return liftBasis(E.field, P, Q, B, E);
    }


    public static int findNqrFactor(Fp2 x, EcCurve curve, int start)
    {
        return findNqrFactor(curve.field, x, curve, start);
    }

    public static int findNaXCoord(Fp2 x, EcCurve curve, int start)
    {
        return findNaXCoord(curve.field, x, curve, start);
    }
}
