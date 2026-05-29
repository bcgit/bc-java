package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Scalar multiplication on x-only Montgomery curves: the Montgomery ladder
 * ({@code xMUL}), iterated doubling, basic wrappers, and the 3-point ladder
 * ({@code ec_ladder3pt}). Java port of the corresponding routines in
 * {@code src/ec/ref/lvlx/ec.c}.
 *
 * <p>Each method takes a {@link GfField} as its first parameter; lvl1
 * convenience overloads (without the field) preserve existing call sites.</p>
 */
final class EcLadder
{
    private EcLadder()
    {
    }

    /** {@code ec_dbl}: P → 2P, choosing the optimal doubling primitive. */
    public static void dbl(GfField field, EcPoint res, EcPoint P, EcCurve curve)
    {
        if (curve.isA24ComputedAndNormalized)
        {
            EcArith.xDBL_A24(field, res, P, curve.A24, true);
        }
        else
        {
            // xDBL takes (X : Z) for AC; reuse the curve's A/C as a "fake" point.
            EcPoint AC = new EcPoint();
            Fp2.copy(AC.x, curve.A);
            Fp2.copy(AC.z, curve.C);
            EcArith.xDBL(field, res, P, AC);
        }
    }

    /** {@code ec_dbl_iter}: res ← [2^n] P. */
    public static void dblIter(GfField field, EcPoint res, int n, EcPoint P, EcCurve curve)
    {
        if (n == 0)
        {
            EcPoint.copy(res, P);
            return;
        }
        if (n > 50)
        {
            EcOps.curveNormalizeA24(field, curve);
        }
        if (curve.isA24ComputedAndNormalized)
        {
            EcArith.xDBL_A24(field, res, P, curve.A24, true);
            for (int i = 0; i < n - 1; i++)
            {
                EcArith.xDBL_A24(field, res, res, curve.A24, true);
            }
        }
        else
        {
            EcPoint AC = new EcPoint();
            Fp2.copy(AC.x, curve.A);
            Fp2.copy(AC.z, curve.C);
            EcArith.xDBL(field, res, P, AC);
            for (int i = 0; i < n - 1; i++)
            {
                EcArith.xDBL(field, res, res, AC);
            }
        }
    }

    /** {@code ec_dbl_iter_basis}: double each of P, Q, P-Q n times. */
    public static void dblIterBasis(GfField field, EcBasis res, int n, EcBasis B, EcCurve curve)
    {
        dblIter(field, res.P, n, B.P, curve);
        dblIter(field, res.Q, n, B.Q, curve);
        dblIter(field, res.PmQ, n, B.PmQ, curve);
    }

    /**
     * {@code xMUL}: Montgomery ladder Q ← [k]·P.
     *
     * @param kbits number of bits to iterate (must be ≥ k's actual bitlength
     *              to avoid losing the high bit). Passing
     *              {@code k.bitLength()} works for all positive k.
     */
    public static void xMUL(GfField field, EcPoint Q, EcPoint P, BigInteger k, int kbits, EcCurve curve)
    {
        EcPoint A24 = new EcPoint();
        if (!curve.isA24ComputedAndNormalized)
        {
            // A24 = (A + 2C : 4C) computed on the fly
            field.fp2Add(A24.x, curve.C, curve.C);
            field.fp2Add(A24.z, A24.x, A24.x);
            field.fp2Add(A24.x, A24.x, curve.A);
        }
        else
        {
            EcPoint.copy(A24, curve.A24);
        }

        EcPoint R0 = new EcPoint();
        EcOps.pointInit(R0);
        EcPoint R1 = P.copy();

        int prevbit = 0;
        for (int i = kbits - 1; i >= 0; i--)
        {
            int bit = k.testBit(i) ? 1 : 0;
            int swap = bit ^ prevbit;
            prevbit = bit;
            int mask = -swap;
            EcOps.cswapPoints(R0, R1, mask);
            EcArith.xDBLADD(field, R0, R1, R0, R1, P, A24, curve.isA24ComputedAndNormalized);
        }
        int finalSwap = -prevbit;
        EcOps.cswapPoints(R0, R1, finalSwap);

        Fp2.copy(Q.x, R0.x);
        Fp2.copy(Q.z, R0.z);
    }

    /**
     * {@code ec_mul}: wrapper around xMUL that normalises A24 for long
     * scalars.
     */
    public static void mul(GfField field, EcPoint res, BigInteger scalar, int kbits, EcPoint P, EcCurve curve)
    {
        if (kbits > 50)
        {
            EcOps.curveNormalizeA24(field, curve);
        }
        xMUL(field, res, P, scalar, kbits, curve);
    }

    /**
     * {@code ec_ladder3pt}: Bernstein's 3-point Montgomery ladder.
     * Returns R ← P + [m]·Q given P, Q, P-Q and the curve.
     *
     * @return 0 if the formulas can't be applied (PQ has a zero coordinate or
     *         the curve's A24 hasn't been normalised), 1 on success.
     */
    public static int ladder3pt(GfField field, EcPoint R, BigInteger m, int mbits,
                                EcPoint P, EcPoint Q, EcPoint PQ, EcCurve E)
    {
        if (!E.isA24ComputedAndNormalized)
        {
            return 0;
        }
        if (Fp2.isOne(E.A24.z) == 0)
        {
            return 0;
        }
        if (EcOps.hasZeroCoordinate(PQ) != 0)
        {
            return 0;
        }

        EcPoint X0 = Q.copy();
        EcPoint X1 = P.copy();
        EcPoint X2 = PQ.copy();

        for (int i = 0; i < mbits; i++)
        {
            int bit = m.testBit(i) ? 1 : 0;
            int mask = -((bit ^ 1) & 1);  // swap if bit == 0
            EcOps.cswapPoints(X1, X2, mask);
            EcArith.xDBLADD(field, X0, X1, X0, X1, X2, E.A24, true);
            EcOps.cswapPoints(X1, X2, mask);
        }
        EcPoint.copy(R, X1);
        return 1;
    }

    // ------------------------------------------------------------------
    // Field-from-curve convenience overloads. The GF(p²) implementation
    // travels with the curve (EcCurve.field), so callers that have a curve
    // in hand don't need to pass a field explicitly. Default field is lvl1,
    // so legacy lvl1 call sites are unaffected.
    // ------------------------------------------------------------------

    public static void dbl(EcPoint res, EcPoint P, EcCurve curve)
    {
        dbl(curve.field, res, P, curve);
    }

    public static void dblIter(EcPoint res, int n, EcPoint P, EcCurve curve)
    {
        dblIter(curve.field, res, n, P, curve);
    }

    public static void dblIterBasis(EcBasis res, int n, EcBasis B, EcCurve curve)
    {
        dblIterBasis(curve.field, res, n, B, curve);
    }

    public static void mul(EcPoint res, BigInteger scalar, int kbits, EcPoint P, EcCurve curve)
    {
        mul(curve.field, res, scalar, kbits, P, curve);
    }

    public static int ladder3pt(EcPoint R, BigInteger m, int mbits,
                                EcPoint P, EcPoint Q, EcPoint PQ, EcCurve E)
    {
        return ladder3pt(E.field, R, m, mbits, P, Q, PQ, E);
    }
}
