package org.bouncycastle.pqc.crypto.sqisign;


/**
 * X-only Montgomery curve arithmetic primitives. Java port of {@code xDBL_E0},
 * {@code xDBL}, {@code xDBL_A24}, {@code xADD}, {@code xDBLADD} from
 * {@code src/ec/ref/lvlx/ec.c}.
 *
 * <p>All routines operate on the projective Kummer line: a point is (X : Z)
 * with affine x-coordinate X/Z; the point at infinity is (1 : 0).</p>
 *
 * <p>Each method takes a {@link GfField} as its first parameter, dispatching
 * arithmetic through the level-specific field implementation. The lvl1
 * overloads (without the field parameter) remain as convenience wrappers for
 * the existing lvl1 callers; new code at lvl3/lvl5 must pass the field.</p>
 */
final class EcArith
{
    private EcArith()
    {
    }

    /**
     * {@code xDBL_E0}: Q ← 2·P on the special curve E0 with (A : C) = (0 : 1).
     */
    public static void xDBL_E0(GfField field, EcPoint Q, EcPoint P)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero();

        field.fp2Add(t0, P.x, P.z);
        field.fp2Sqr(t0, t0);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Sqr(t1, t1);
        field.fp2Sub(t2, t0, t1);
        field.fp2Add(t1, t1, t1);
        field.fp2Mul(Q.x, t0, t1);
        field.fp2Add(Q.z, t1, t2);
        field.fp2Mul(Q.z, Q.z, t2);
    }

    /**
     * {@code xDBL}: Q ← 2·P, deriving the Edwards-style coefficients (A+2C, 4C)
     * on the fly from the curve coefficients (A : C).
     */
    public static void xDBL(GfField field, EcPoint Q, EcPoint P, EcPoint AC)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero(), t3 = Fp2.zero();

        field.fp2Add(t0, P.x, P.z);
        field.fp2Sqr(t0, t0);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Sqr(t1, t1);
        field.fp2Sub(t2, t0, t1);
        field.fp2Add(t3, AC.z, AC.z);
        field.fp2Mul(t1, t1, t3);
        field.fp2Add(t1, t1, t1);
        field.fp2Mul(Q.x, t0, t1);
        field.fp2Add(t0, t3, AC.x);
        field.fp2Mul(t0, t0, t2);
        field.fp2Add(t0, t0, t1);
        field.fp2Mul(Q.z, t0, t2);
    }

    /**
     * {@code xDBL_A24}: Q ← 2·P given the precomputed (A+2C : 4C).
     * If {@code a24Normalized}, A24.z is assumed to be 1.
     */
    public static void xDBL_A24(GfField field, EcPoint Q, EcPoint P, EcPoint A24, boolean a24Normalized)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero();

        field.fp2Add(t0, P.x, P.z);
        field.fp2Sqr(t0, t0);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Sqr(t1, t1);
        field.fp2Sub(t2, t0, t1);
        if (!a24Normalized)
        {
            field.fp2Mul(t1, t1, A24.z);
        }
        field.fp2Mul(Q.x, t0, t1);
        field.fp2Mul(t0, t2, A24.x);
        field.fp2Add(t0, t0, t1);
        field.fp2Mul(Q.z, t0, t2);
    }

    /**
     * {@code xADD}: differential addition R ← P + Q given PQ = P − Q.
     */
    public static void xADD(GfField field, EcPoint R, EcPoint P, EcPoint Q, EcPoint PQ)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero(), t3 = Fp2.zero();

        field.fp2Add(t0, P.x, P.z);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Add(t2, Q.x, Q.z);
        field.fp2Sub(t3, Q.x, Q.z);
        field.fp2Mul(t0, t0, t3);
        field.fp2Mul(t1, t1, t2);
        field.fp2Add(t2, t0, t1);
        field.fp2Sub(t3, t0, t1);
        field.fp2Sqr(t2, t2);
        field.fp2Sqr(t3, t3);
        field.fp2Mul(t2, PQ.z, t2);
        field.fp2Mul(R.z, PQ.x, t3);
        Fp2.copy(R.x, t2);
    }

    /**
     * {@code xDBLADD}: simultaneous R ← 2P and S ← P + Q.
     */
    public static void xDBLADD(GfField field, EcPoint R, EcPoint S, EcPoint P, EcPoint Q, EcPoint PQ,
                               EcPoint A24, boolean a24Normalized)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero(), t2 = Fp2.zero();

        field.fp2Add(t0, P.x, P.z);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Sqr(R.x, t0);
        field.fp2Sub(t2, Q.x, Q.z);
        field.fp2Add(S.x, Q.x, Q.z);
        field.fp2Mul(t0, t0, t2);
        field.fp2Sqr(R.z, t1);
        field.fp2Mul(t1, t1, S.x);
        field.fp2Sub(t2, R.x, R.z);
        if (!a24Normalized)
        {
            field.fp2Mul(R.z, R.z, A24.z);
        }
        field.fp2Mul(R.x, R.x, R.z);
        field.fp2Mul(S.x, A24.x, t2);
        field.fp2Sub(S.z, t0, t1);
        field.fp2Add(R.z, R.z, S.x);
        field.fp2Add(S.x, t0, t1);
        field.fp2Mul(R.z, R.z, t2);
        field.fp2Sqr(S.z, S.z);
        field.fp2Sqr(S.x, S.x);
        field.fp2Mul(S.z, S.z, PQ.x);
        field.fp2Mul(S.x, S.x, PQ.z);
    }

    // ------------------------------------------------------------------
    // lvl1 convenience overloads — let existing callers keep working
    // without the field parameter while the rest of the codebase migrates.
    // ------------------------------------------------------------------

    public static void xDBL_E0(EcPoint Q, EcPoint P)
    {
        xDBL_E0(GfFieldLvl1.INSTANCE, Q, P);
    }

    public static void xDBL_A24(EcPoint Q, EcPoint P, EcPoint A24, boolean a24Normalized)
    {
        xDBL_A24(GfFieldLvl1.INSTANCE, Q, P, A24, a24Normalized);
    }
}
