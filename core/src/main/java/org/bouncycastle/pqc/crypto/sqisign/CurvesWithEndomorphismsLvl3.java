package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Builds the typed lvl3 {@code CURVES_WITH_ENDOMORPHISMS} array from the flat
 * {@link EndomorphismActionLvl3#CURVE_FP} / {@link EndomorphismActionLvl3#CURVE_IBZ}
 * tables. Mirrors {@link EndomorphismActionLvl1#CURVES_WITH_ENDOMORPHISMS}.
 *
 * <p>Layout per entry — see {@link EndomorphismActionLvl3}'s class doc.</p>
 */
final class CurvesWithEndomorphismsLvl3
{
    public static final int NUM_CURVES = EndomorphismActionLvl3.NUM_CURVES;

    public static final CurveWithEndomorphismRing[] CURVES_WITH_ENDOMORPHISMS;

    static
    {
        CURVES_WITH_ENDOMORPHISMS = new CurveWithEndomorphismRing[NUM_CURVES];
        for (int i = 0; i < NUM_CURVES; i++)
        {
            CURVES_WITH_ENDOMORPHISMS[i] = new CurveWithEndomorphismRing();
            populate(CURVES_WITH_ENDOMORPHISMS[i], i);
        }
    }

    private static void populate(CurveWithEndomorphismRing dst, int i)
    {
        BigInteger[] fp = EndomorphismActionLvl3.CURVE_FP[i];
        Ibz[] ibz = EndomorphismActionLvl3.CURVE_IBZ[i];

        // Curve A, C
        Fp2.copy(dst.curve.A, new Fp2(new Fp(fp[0]), new Fp(fp[1])));
        Fp2.copy(dst.curve.C, new Fp2(new Fp(fp[2]), new Fp(fp[3])));
        // A24 (x, z)
        Fp2.copy(dst.curve.A24.x, new Fp2(new Fp(fp[4]), new Fp(fp[5])));
        Fp2.copy(dst.curve.A24.z, new Fp2(new Fp(fp[6]), new Fp(fp[7])));
        dst.curve.isA24ComputedAndNormalized = false;
        // Tag with the lvl3 GF(p²) implementation so arithmetic-dispatching
        // helpers route through p_lvl3 = 65·2^376 − 1 rather than the lvl1
        // default. See EcCurve.field.
        dst.curve.field = org.bouncycastle.pqc.crypto.sqisign.GfFieldLvl3.INSTANCE;

        // Even-torsion basis P, Q, PmQ
        setPoint(dst.basisEven.P,
            fp[8], fp[9], fp[10], fp[11]);
        setPoint(dst.basisEven.Q,
            fp[12], fp[13], fp[14], fp[15]);
        setPoint(dst.basisEven.PmQ,
            fp[16], fp[17], fp[18], fp[19]);

        // 6 × 2×2 action matrices.
        setMatrix(dst.actionI,    ibz,  0);
        setMatrix(dst.actionJ,    ibz,  4);
        setMatrix(dst.actionK,    ibz,  8);
        setMatrix(dst.actionGen2, ibz, 12);
        setMatrix(dst.actionGen3, ibz, 16);
        setMatrix(dst.actionGen4, ibz, 20);
    }

    private static void setPoint(EcPoint p, BigInteger xRe, BigInteger xIm,
                                            BigInteger zRe, BigInteger zIm)
    {
        Fp2.copy(p.x, new Fp2(new Fp(xRe), new Fp(xIm)));
        Fp2.copy(p.z, new Fp2(new Fp(zRe), new Fp(zIm)));
    }

    private static void setMatrix(Ibz[][] dst, Ibz[] src, int base)
    {
        Ibz.copy(dst[0][0], src[base + 0]);
        Ibz.copy(dst[0][1], src[base + 1]);
        Ibz.copy(dst[1][0], src[base + 2]);
        Ibz.copy(dst[1][1], src[base + 3]);
    }

    private CurvesWithEndomorphismsLvl3()
    {
    }
}
