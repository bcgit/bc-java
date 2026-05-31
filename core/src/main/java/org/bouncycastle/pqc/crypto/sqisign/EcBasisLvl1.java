package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Level-1 specific entry points from {@code src/ec/ref/lvlx/basis.c}: the
 * top-level {@code ec_curve_to_basis_2f_to_hint} / {@code from_hint} pair
 * plus {@code ec_basis_E0_2f} and the cofactor-clearing helper. These were
 * blocked on precomp lvl1 constants ({@link PrecompLvl1#TORSION_EVEN_POWER},
 * {@link E0BasisLvl1#BASIS_E0_PX}, {@link E0BasisLvl1#BASIS_E0_QX}, and the
 * odd-cofactor {@code p_cofactor_for_2f}); those are now in place so this
 * class can use them.
 *
 * <p>For lvl1 the odd cofactor of p+1 is 5 (since p+1 = 5·2^248), so the
 * call sequence to clear the cofactor and reach a point of order 2^f is:
 * scale by 5, then double {@code TORSION_EVEN_POWER - f} times.</p>
 */
final class EcBasisLvl1
{
    private static final GfField field = GfFieldLvl1.INSTANCE;

    /** Odd cofactor of p+1 for lvl1: p+1 = 5·2^248, so the cofactor is 5. */
    public static final BigInteger P_COFACTOR_FOR_2F = BigInteger.valueOf(5);

    /** Bit-length of {@link #P_COFACTOR_FOR_2F} (= 3 for lvl1). */
    public static final int P_COFACTOR_FOR_2F_BITLENGTH = 3;

    private EcBasisLvl1()
    {
    }

    /**
     * {@code clear_cofactor_for_maximal_even_order}: given a point P of order
     * k·2^n (with n maximal and k odd), produce a point of order 2^f.
     * Multiplies by the odd cofactor, then doubles
     * {@code TORSION_EVEN_POWER − f} times. Mirrors the static helper in
     * basis.c.
     */
    public static void clearCofactorForMaximalEvenOrder(EcPoint P, EcCurve curve, int f)
    {
        // Clear the odd cofactor (= 5 for lvl1).
        EcLadder.mul(P, P_COFACTOR_FOR_2F, P_COFACTOR_FOR_2F_BITLENGTH, P, curve);
        // Clear the higher even part down to 2^f.
        for (int i = 0; i < PrecompLvl1.TORSION_EVEN_POWER - f; i++)
        {
            EcArith.xDBL_A24(P, P, curve.A24, curve.isA24ComputedAndNormalized);
        }
    }

    /**
     * {@code ec_basis_E0_2f}: hard-coded basis for E₀ — uses the precomputed
     * {@link E0BasisLvl1#BASIS_E0_PX} / {@link E0BasisLvl1#BASIS_E0_QX} and
     * doubles them down to the requested order 2^f. Caller must guarantee
     * the curve has A = 0 (E₀).
     */
    public static void basisE02f(EcBasis PQ2, EcCurve curve, int f)
    {
        if (Fp2.isZero(curve.A) == 0)
        {
            throw new IllegalArgumentException("basisE02f requires A = 0");
        }
        EcPoint P = new EcPoint(E0BasisLvl1.BASIS_E0_PX, Fp2.one());
        EcPoint Q = new EcPoint(E0BasisLvl1.BASIS_E0_QX, Fp2.one());

        for (int i = 0; i < PrecompLvl1.TORSION_EVEN_POWER - f; i++)
        {
            EcArith.xDBL_E0(P, P);
            EcArith.xDBL_E0(Q, Q);
        }

        EcPoint.copy(PQ2.P, P);
        EcPoint.copy(PQ2.Q, Q);
        EcBasisOps.differencePoint(PQ2.PmQ, P, Q, curve);
    }

    /**
     * {@code ec_curve_to_basis_2f_to_hint}: deterministic basis for E[2^f]
     * with Q above (0 : 0). Returns a 7-bit hint packed with hint_A (a flag
     * recording whether A is a quadratic residue) in the LSB. The companion
     * {@link #fromHint} routine reconstructs the same basis from the hint.
     */
    public static int toHint(EcBasis PQ2, EcCurve curve, int f)
    {
        EcOps.normalizeCurveAndA24(curve);

        if (Fp2.isZero(curve.A) != 0)
        {
            basisE02f(PQ2, curve, f);
            return 0;
        }

        EcPoint P = new EcPoint();
        EcPoint Q = new EcPoint();
        int hintA = field.fp2IsSquare(curve.A) != 0 ? 1 : 0;
        int hint;

        if (hintA == 0)
        {
            hint = EcBasisOps.findNaXCoord(P.x, curve, 1);
        }
        else
        {
            hint = EcBasisOps.findNqrFactor(P.x, curve, 1);
        }
        Fp2.setOne(P.z);

        // Q.x = -(A + P.x).
        field.fp2Add(Q.x, curve.A, P.x);
        field.fp2Neg(Q.x, Q.x);
        Fp2.setOne(Q.z);

        clearCofactorForMaximalEvenOrder(P, curve, f);
        clearCofactorForMaximalEvenOrder(Q, curve, f);

        EcBasisOps.differencePoint(PQ2.Q, P, Q, curve);
        EcPoint.copy(PQ2.P, P);
        EcPoint.copy(PQ2.PmQ, Q);

        return ((hint & 0x7F) << 1) | hintA;
    }

    /**
     * {@code ec_curve_to_basis_2f_from_hint}: rebuild the basis given the
     * hint produced by {@link #toHint}. Returns 1 on success.
     */
    public static int fromHint(EcBasis PQ2, EcCurve curve, int f, int hint)
    {
        EcOps.normalizeCurveAndA24(curve);

        if (Fp2.isZero(curve.A) != 0)
        {
            basisE02f(PQ2, curve, f);
            return 1;
        }

        int hintA = hint & 1;
        int hintP = (hint >>> 1) & 0x7F;

        EcPoint P = new EcPoint();
        EcPoint Q = new EcPoint();

        if (hintP == 0)
        {
            // Fallback when the original toHint overflowed past 128 attempts.
            if (hintA == 0)
            {
                EcBasisOps.findNaXCoord(P.x, curve, 128);
            }
            else
            {
                EcBasisOps.findNqrFactor(P.x, curve, 128);
            }
        }
        else if (hintA == 0)
        {
            // x(P) = hintP · A
            field.fp2MulSmall(P.x, curve.A, hintP);
        }
        else
        {
            // x(P) = -A / (1 + i·hintP)
            Fp.setOne(P.x.re);
            Fp.setSmall(P.x.im, hintP);
            field.fp2Inv(P.x);
            field.fp2Mul(P.x, P.x, curve.A);
            field.fp2Neg(P.x, P.x);
        }
        Fp2.setOne(P.z);

        field.fp2Add(Q.x, curve.A, P.x);
        field.fp2Neg(Q.x, Q.x);
        Fp2.setOne(Q.z);

        clearCofactorForMaximalEvenOrder(P, curve, f);
        clearCofactorForMaximalEvenOrder(Q, curve, f);

        EcBasisOps.differencePoint(PQ2.Q, P, Q, curve);
        EcPoint.copy(PQ2.P, P);
        EcPoint.copy(PQ2.PmQ, Q);
        return 1;
    }

    /** Helper for callers that only need an Fp2 with a small im part. */
    @SuppressWarnings("unused")
    private static Fp2 onePlusIB(int b)
    {
        Fp2 z = Fp2.one();
        Fp.setSmall(z.im, b);
        return z;
    }
}
