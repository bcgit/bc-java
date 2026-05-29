package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Level-3 E₀ basis constants. Sibling of {@link E0BasisLvl1}, but the
 * underlying x-coordinates are sourced from
 * {@link EndomorphismActionLvl3#CURVE_FP CURVE_FP[0]} (the basis_even.P/Q
 * fields of CURVES_WITH_ENDOMORPHISMS[0]) rather than from a separate
 * {@code e0_basis.c}: the lvl3 C reference embeds the data inside
 * {@code endomorphism_action.c}, and we have already mechanically extracted
 * and Montgomery-decoded it into {@code CURVE_FP[0]}.
 */
final class E0BasisLvl3
{
    /** x-coordinate of the deterministic basis point P on E₀ (lvl3). */
    public static final Fp2 BASIS_E0_PX;

    /** x-coordinate of the deterministic basis point Q on E₀ (lvl3). */
    public static final Fp2 BASIS_E0_QX;

    static
    {
        BigInteger[] e0 = pickRow(0);
        BASIS_E0_PX = new Fp2(new Fp(e0[8]),  new Fp(e0[9]));
        BASIS_E0_QX = new Fp2(new Fp(e0[12]), new Fp(e0[13]));
    }

    private static BigInteger[] pickRow(int i)
    {
        return EndomorphismActionLvl3.CURVE_FP[i];
    }

    private E0BasisLvl3()
    {
    }
}
