package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Jacobian-coordinate arithmetic on Montgomery curves. Java port of
 * {@code src/ec/ref/lvlx/ec_jac.c}.
 *
 * <p>A Jacobian point (X : Y : Z) corresponds to the affine point
 * (X/Z², Y/Z³). The identity is (0 : 1 : 0).</p>
 */
final class EcJac
{
    private EcJac()
    {
    }

    /** {@code jac_init}: identity element (0 : 1 : 0). */
    public static void init(JacPoint P)
    {
        Fp2.setZero(P.x);
        Fp2.setOne(P.y);
        Fp2.setZero(P.z);
    }

    /** {@code jac_is_equal}: equality on the affine projection. */
    public static int isEqual(GfField field, JacPoint P, JacPoint Q)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero(), t3 = Fp2.zero();
        field.fp2Sqr(t0, Q.z);
        field.fp2Mul(t2, P.x, t0);          // x1*z2^2
        field.fp2Sqr(t1, P.z);
        field.fp2Mul(t3, Q.x, t1);          // x2*z1^2
        field.fp2Sub(t2, t2, t3);

        field.fp2Mul(t0, t0, Q.z);
        field.fp2Mul(t0, P.y, t0);          // y1*z2^3
        field.fp2Mul(t1, t1, P.z);
        field.fp2Mul(t1, Q.y, t1);          // y2*z1^3
        field.fp2Sub(t0, t0, t1);

        return Fp2.isZero(t0) & Fp2.isZero(t2);
    }

    /** {@code jac_to_xz}: drop the y coordinate, square z. Special case (0:1:0) → (1:0). */
    public static void toXz(GfField field, EcPoint P, JacPoint xyP)
    {
        Fp2.copy(P.x, xyP.x);
        Fp2.copy(P.z, xyP.z);
        field.fp2Sqr(P.z, P.z);

        // If (xyP) = (0:1:0), now P = (0 : 0); fix to (1 : 0).
        Fp2 one = Fp2.one();
        int c1 = Fp2.isZero(P.x);
        int c2 = Fp2.isZero(P.z);
        Fp2.select(P.x, P.x, one, c1 & c2);
    }

    /**
     * {@code jac_to_ws}: change of model to short Weierstrass, writing
     * {@code t = a · Z^4} and {@code ao3 = A/3} (for the inverse map). When
     * the Montgomery A is zero, a = 1 and ao3 is unused.
     */
    public static void toWs(GfField field, JacPoint Q, Fp2 t, Fp2 ao3, JacPoint P, EcCurve curve)
    {
        Fp one = new Fp();
        Fp.setOne(one);
        if (Fp2.isZero(curve.A) == 0)
        {
            field.fpDiv3(ao3.re, curve.A.re);
            field.fpDiv3(ao3.im, curve.A.im);
            field.fp2Sqr(t, P.z);
            field.fp2Mul(Q.x, ao3, t);
            field.fp2Add(Q.x, Q.x, P.x);
            field.fp2Sqr(t, t);
            Fp2 a = Fp2.zero();
            field.fp2Mul(a, ao3, curve.A);
            field.fpSub(a.re, one, a.re);
            field.fpNeg(a.im, a.im);
            field.fp2Mul(t, t, a);
        }
        else
        {
            Fp2.copy(Q.x, P.x);
            field.fp2Sqr(t, P.z);
            field.fp2Sqr(t, t);
        }
        Fp2.copy(Q.y, P.y);
        Fp2.copy(Q.z, P.z);
    }

    /** {@code jac_from_ws}: inverse of toWs. */
    public static void fromWs(GfField field, JacPoint Q, JacPoint P, Fp2 ao3, EcCurve curve)
    {
        Fp2 t = Fp2.zero();
        if (Fp2.isZero(curve.A) == 0)
        {
            field.fp2Sqr(t, P.z);
            field.fp2Mul(t, t, ao3);
            field.fp2Sub(Q.x, P.x, t);
        }
        else
        {
            Fp2.copy(Q.x, P.x);
        }
        Fp2.copy(Q.y, P.y);
        Fp2.copy(Q.z, P.z);
    }

    /** {@code jac_neg}: negate y. */
    public static void neg(GfField field, JacPoint Q, JacPoint P)
    {
        Fp2.copy(Q.x, P.x);
        field.fp2Neg(Q.y, P.y);
        Fp2.copy(Q.z, P.z);
    }

    /** {@code DBL}: Q ← 2·P on Montgomery curve with coefficient A. */
    public static void dbl(GfField field, JacPoint Q, JacPoint P, EcCurve AC)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero(), t3 = Fp2.zero();
        int flag = Fp2.isZero(P.x) & Fp2.isZero(P.z);

        field.fp2Sqr(t0, P.x);
        field.fp2Add(t1, t0, t0);
        field.fp2Add(t0, t0, t1);               // t0 = 3x1^2
        field.fp2Sqr(t1, P.z);                  // t1 = z1^2
        field.fp2Mul(t2, P.x, AC.A);
        field.fp2Add(t2, t2, t2);               // t2 = 2Ax1
        field.fp2Add(t2, t1, t2);               // t2 = 2Ax1 + z1^2
        field.fp2Mul(t2, t1, t2);               // t2 = z1^2(2Ax1 + z1^2)
        field.fp2Add(t2, t0, t2);               // t2 = alpha
        field.fp2Mul(Q.z, P.y, P.z);
        field.fp2Add(Q.z, Q.z, Q.z);            // z2 = 2y1z1
        field.fp2Sqr(t0, Q.z);
        field.fp2Mul(t0, t0, AC.A);             // t0 = 4Ay1^2z1^2
        field.fp2Sqr(t1, P.y);
        field.fp2Add(t1, t1, t1);               // t1 = 2y1^2
        field.fp2Add(t3, P.x, P.x);             // t3 = 2x1
        field.fp2Mul(t3, t1, t3);               // t3 = 4x1y1^2
        field.fp2Sqr(Q.x, t2);
        field.fp2Sub(Q.x, Q.x, t0);
        field.fp2Sub(Q.x, Q.x, t3);
        field.fp2Sub(Q.x, Q.x, t3);
        field.fp2Sub(Q.y, t3, Q.x);
        field.fp2Mul(Q.y, Q.y, t2);
        field.fp2Sqr(t1, t1);
        field.fp2Sub(Q.y, Q.y, t1);
        field.fp2Sub(Q.y, Q.y, t1);

        // Preserve identity: if P was (0:y:0), keep Q.x = P.x and Q.z = P.z.
        Fp2.select(Q.x, Q.x, P.x, -flag);
        Fp2.select(Q.z, Q.z, P.z, -flag);
    }

    /**
     * {@code DBLW}: Q ← 2·P in modified Jacobian coordinates on the short
     * Weierstrass model, updating the cache {@code u = a·Z^4}. The {@code t}
     * argument carries {@code a · (old Z)^4}.
     */
    public static void dblW(GfField field, JacPoint Q, Fp2 u, JacPoint P, Fp2 t)
    {
        int flag = Fp2.isZero(P.x) & Fp2.isZero(P.z);

        Fp2 xx = Fp2.zero(), c = Fp2.zero(), cc = Fp2.zero();
        Fp2 r = Fp2.zero(), s = Fp2.zero(), m = Fp2.zero();

        field.fp2Sqr(xx, P.x);
        field.fp2Sqr(c, P.y);
        field.fp2Add(c, c, c);
        field.fp2Sqr(cc, c);
        field.fp2Add(r, cc, cc);
        field.fp2Add(s, P.x, c);
        field.fp2Sqr(s, s);
        field.fp2Sub(s, s, xx);
        field.fp2Sub(s, s, cc);
        field.fp2Add(m, xx, xx);
        field.fp2Add(m, m, xx);
        field.fp2Add(m, m, t);
        field.fp2Sqr(Q.x, m);
        field.fp2Sub(Q.x, Q.x, s);
        field.fp2Sub(Q.x, Q.x, s);
        field.fp2Mul(Q.z, P.y, P.z);
        field.fp2Add(Q.z, Q.z, Q.z);
        field.fp2Sub(Q.y, s, Q.x);
        field.fp2Mul(Q.y, Q.y, m);
        field.fp2Sub(Q.y, Q.y, r);
        field.fp2Mul(u, t, r);
        field.fp2Add(u, u, u);

        Fp2.select(Q.x, Q.x, P.x, -flag);
        Fp2.select(Q.z, Q.z, P.z, -flag);
    }

    /** Constant-time-ish Jacobian point select. */
    public static void selectPoint(JacPoint Q, JacPoint P1, JacPoint P2, int option)
    {
        Fp2.select(Q.x, P1.x, P2.x, option);
        Fp2.select(Q.y, P1.y, P2.y, option);
        Fp2.select(Q.z, P1.z, P2.z, option);
    }

    /**
     * {@code ADD}: Jacobian-coordinate point addition R ← P + Q on
     * Montgomery curve with coefficient A. Handles all edge cases (point at
     * infinity, doubling case, P = -Q).
     */
    public static void add(GfField field, JacPoint R, JacPoint P, JacPoint Q, EcCurve AC)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero(), t3 = Fp2.zero();
        Fp2 u1 = Fp2.zero(), u2 = Fp2.zero(), v1 = Fp2.zero();
        Fp2 dx = Fp2.zero(), dy = Fp2.zero();

        int ctl1 = Fp2.isZero(P.z);
        int ctl2 = Fp2.isZero(Q.z);

        field.fp2Sqr(t0, P.z);
        field.fp2Sqr(t1, Q.z);

        field.fp2Mul(v1, t1, Q.z);
        field.fp2Mul(t2, t0, P.z);
        field.fp2Mul(v1, v1, P.y);
        field.fp2Mul(t2, t2, Q.y);
        field.fp2Sub(dy, t2, v1);
        field.fp2Mul(u2, t0, Q.x);
        field.fp2Mul(u1, t1, P.x);
        field.fp2Sub(dx, u2, u1);

        // Doubling-case dx, dy.
        field.fp2Add(t1, P.y, P.y);
        field.fp2Add(t2, AC.A, AC.A);
        field.fp2Mul(t2, t2, P.x);
        field.fp2Add(t2, t2, t0);
        field.fp2Mul(t2, t2, t0);
        field.fp2Sqr(t0, P.x);
        field.fp2Add(t2, t2, t0);
        field.fp2Add(t2, t2, t0);
        field.fp2Add(t2, t2, t0);
        field.fp2Mul(t2, t2, Q.z);

        int ctl = Fp2.isZero(dx) & Fp2.isZero(dy);
        Fp2.select(dx, dx, t1, ctl);
        Fp2.select(dy, dy, t2, ctl);

        field.fp2Mul(t0, P.z, Q.z);
        field.fp2Sqr(t1, t0);
        field.fp2Sqr(t2, dx);
        field.fp2Sqr(t3, dy);

        field.fp2Mul(R.x, AC.A, t1);
        field.fp2Add(R.x, R.x, u1);
        field.fp2Add(R.x, R.x, u2);
        field.fp2Mul(R.x, R.x, t2);
        field.fp2Sub(R.x, t3, R.x);

        field.fp2Mul(R.y, u1, t2);
        field.fp2Sub(R.y, R.y, R.x);
        field.fp2Mul(R.y, R.y, dy);
        field.fp2Mul(t3, t2, dx);
        field.fp2Mul(t3, t3, v1);
        field.fp2Sub(R.y, R.y, t3);

        field.fp2Mul(R.z, dx, t0);

        // R = P if Q is ∞; R = Q if P is ∞.
        selectPoint(R, R, Q, ctl1);
        selectPoint(R, R, P, ctl2);
    }

    /**
     * {@code jac_to_xz_add_components}: compute (u, v, w) such that
     * x(P + Q) = (u - v : w) and x(P - Q) = (u + v : w).
     */
    public static void toXzAddComponents(GfField field, AddComponents addComp, JacPoint P, JacPoint Q, EcCurve AC)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero();
        Fp2 t3 = Fp2.zero(), t4 = Fp2.zero(), t5 = Fp2.zero(), t6 = Fp2.zero();

        field.fp2Sqr(t0, P.z);
        field.fp2Sqr(t1, Q.z);
        field.fp2Mul(t2, P.x, t1);
        field.fp2Mul(t3, t0, Q.x);
        field.fp2Mul(t4, P.y, Q.z);
        field.fp2Mul(t4, t4, t1);
        field.fp2Mul(t5, P.z, Q.y);
        field.fp2Mul(t5, t5, t0);
        field.fp2Mul(t0, t0, t1);
        field.fp2Mul(t6, t4, t5);
        field.fp2Add(addComp.v, t6, t6);
        field.fp2Sqr(t4, t4);
        field.fp2Sqr(t5, t5);
        field.fp2Add(t4, t4, t5);
        field.fp2Add(t5, t2, t3);
        field.fp2Add(t6, t3, t3);
        field.fp2Sub(t6, t5, t6);
        field.fp2Sqr(t6, t6);
        field.fp2Mul(t1, AC.A, t0);
        field.fp2Add(t1, t5, t1);
        field.fp2Mul(t1, t1, t6);
        field.fp2Sub(addComp.u, t4, t1);
        field.fp2Mul(addComp.w, t6, t0);
    }

    // ------------------------------------------------------------------
    // Field-from-curve convenience overloads (see EcLadder for rationale).
    // Curve-less overloads ({@code isEqual}, {@code toXz}, {@code neg}) keep
    // the lvl1 default; non-lvl1 callers there must use the field-taking form.
    // ------------------------------------------------------------------

    public static int isEqual(JacPoint P, JacPoint Q)
    {
        return isEqual(GfFieldLvl1.INSTANCE, P, Q);
    }

    public static void toWs(JacPoint Q, Fp2 t, Fp2 ao3, JacPoint P, EcCurve curve)
    {
        toWs(curve.field, Q, t, ao3, P, curve);
    }

    public static void fromWs(JacPoint Q, JacPoint P, Fp2 ao3, EcCurve curve)
    {
        fromWs(curve.field, Q, P, ao3, curve);
    }

    public static void neg(JacPoint Q, JacPoint P)
    {
        neg(GfFieldLvl1.INSTANCE, Q, P);
    }

    public static void dbl(JacPoint Q, JacPoint P, EcCurve AC)
    {
        dbl(AC.field, Q, P, AC);
    }

    public static void add(JacPoint R, JacPoint P, JacPoint Q, EcCurve AC)
    {
        add(AC.field, R, P, Q, AC);
    }

    public static void toXzAddComponents(AddComponents addComp, JacPoint P, JacPoint Q, EcCurve AC)
    {
        toXzAddComponents(AC.field, addComp, P, Q, AC);
    }
}
