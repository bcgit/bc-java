package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Level-5 E₀ basis constants. Sibling of {@link E0BasisLvl1}, but sourced
 * from {@link EndomorphismActionLvl5#CURVE_FP CURVE_FP[0]} (the basis_even.P/Q
 * fields of CURVES_WITH_ENDOMORPHISMS[0]) since the lvl5 C reference embeds
 * the basis inside {@code endomorphism_action.c}.
 */
final class E0BasisLvl5
{
    /** x-coordinate of the deterministic basis point P on E₀ (lvl5). */
    public static final Fp2 BASIS_E0_PX;

    /** x-coordinate of the deterministic basis point Q on E₀ (lvl5). */
    public static final Fp2 BASIS_E0_QX;

    static
    {
        BigInteger[] e0 = EndomorphismActionLvl5.CURVE_FP[0];
        BASIS_E0_PX = new Fp2(new Fp(e0[8]),  new Fp(e0[9]));
        BASIS_E0_QX = new Fp2(new Fp(e0[12]), new Fp(e0[13]));
    }

    private E0BasisLvl5()
    {
    }
}
