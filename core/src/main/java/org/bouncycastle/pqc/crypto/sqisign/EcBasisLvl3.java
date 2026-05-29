package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Level-3 specific entry points from {@code src/ec/ref/lvlx/basis.c} —
 * sibling of {@link EcBasisLvl1}, dispatching through
 * {@link GfFieldLvl3#INSTANCE} and using the lvl3 odd cofactor of
 * {@code p+1}.
 *
 * <p>For lvl3 the prime is {@code p = 65·2^376 − 1}, so {@code p+1 = 65·2^376}
 * and the odd cofactor is 65 (7 bits).</p>
 */
final class EcBasisLvl3
{
    private static final GfField field = GfFieldLvl3.INSTANCE;

    /** Odd cofactor of p+1 for lvl3: p+1 = 65·2^376, so the cofactor is 65. */
    public static final BigInteger P_COFACTOR_FOR_2F = BigInteger.valueOf(65);

    /** Bit-length of {@link #P_COFACTOR_FOR_2F} (= 7 for lvl3). */
    public static final int P_COFACTOR_FOR_2F_BITLENGTH = 7;

    private EcBasisLvl3()
    {
    }

    public static void clearCofactorForMaximalEvenOrder(EcPoint P, EcCurve curve, int f)
    {
        EcLadder.mul(field, P, P_COFACTOR_FOR_2F, P_COFACTOR_FOR_2F_BITLENGTH, P, curve);
        for (int i = 0; i < PrecompLvl3.TORSION_EVEN_POWER - f; i++)
        {
            EcArith.xDBL_A24(field, P, P, curve.A24, curve.isA24ComputedAndNormalized);
        }
    }

    public static void basisE02f(EcBasis PQ2, EcCurve curve, int f)
    {
        if (Fp2.isZero(curve.A) == 0)
        {
            throw new IllegalArgumentException("basisE02f requires A = 0");
        }
        EcPoint P = new EcPoint(E0BasisLvl3.BASIS_E0_PX, Fp2.one());
        EcPoint Q = new EcPoint(E0BasisLvl3.BASIS_E0_QX, Fp2.one());

        for (int i = 0; i < PrecompLvl3.TORSION_EVEN_POWER - f; i++)
        {
            EcArith.xDBL_E0(field, P, P);
            EcArith.xDBL_E0(field, Q, Q);
        }

        EcPoint.copy(PQ2.P, P);
        EcPoint.copy(PQ2.Q, Q);
        EcBasisOps.differencePoint(field, PQ2.PmQ, P, Q, curve);
    }

    public static int toHint(EcBasis PQ2, EcCurve curve, int f)
    {
        EcOps.normalizeCurveAndA24(field, curve);

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
            hint = EcBasisOps.findNaXCoord(field, P.x, curve, 1);
        }
        else
        {
            hint = EcBasisOps.findNqrFactor(field, P.x, curve, 1);
        }
        Fp2.setOne(P.z);

        field.fp2Add(Q.x, curve.A, P.x);
        field.fp2Neg(Q.x, Q.x);
        Fp2.setOne(Q.z);

        clearCofactorForMaximalEvenOrder(P, curve, f);
        clearCofactorForMaximalEvenOrder(Q, curve, f);

        EcBasisOps.differencePoint(field, PQ2.Q, P, Q, curve);
        EcPoint.copy(PQ2.P, P);
        EcPoint.copy(PQ2.PmQ, Q);

        return ((hint & 0x7F) << 1) | hintA;
    }

    public static int fromHint(EcBasis PQ2, EcCurve curve, int f, int hint)
    {
        EcOps.normalizeCurveAndA24(field, curve);

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
            if (hintA == 0)
            {
                EcBasisOps.findNaXCoord(field, P.x, curve, 128);
            }
            else
            {
                EcBasisOps.findNqrFactor(field, P.x, curve, 128);
            }
        }
        else if (hintA == 0)
        {
            field.fp2MulSmall(P.x, curve.A, hintP);
        }
        else
        {
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

        EcBasisOps.differencePoint(field, PQ2.Q, P, Q, curve);
        EcPoint.copy(PQ2.P, P);
        EcPoint.copy(PQ2.PmQ, Q);
        return 1;
    }
}
