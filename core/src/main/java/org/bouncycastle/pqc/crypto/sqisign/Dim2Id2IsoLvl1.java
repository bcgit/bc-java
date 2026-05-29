package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;


/**
 * Top-level entry for keygen step 3:
 * {@code dim2id2iso_arbitrary_isogeny_evaluation}. Java mirror of
 * {@code src/id2iso/ref/lvlx/dim2id2iso.c}.
 *
 * <p>The level-independent algorithmic body (find_uv, fixed_degree_isogeny,
 * the (2,2)-chain, endomorphism action) is in {@link Dim2Id2IsoClapotis}.
 * This class supplies the level-1 precomp bundle and delegates.</p>
 *
 * <p>The level-1 precomp bundle is fully populated:
 * {@link EndomorphismActionLvl1#CURVES_WITH_ENDOMORPHISMS} (the primary curve
 * E&#8320; plus six alternate starting curves and their endomorphism-action
 * matrices), {@code ALTERNATE_CONNECTING_IDEALS}, {@code CONNECTING_IDEALS} and
 * {@code QuatRepresentIntegerParamsLvl1.INSTANCES}. {@link #buildPrecomp()}
 * assembles it and the evaluation calls straight through to
 * {@link Dim2Id2IsoClapotis#idealToIsogenyClapotis}.</p>
 *
 * <p>As a defensive invariant, {@code buildPrecomp} returns {@code null} — and
 * the evaluation throws {@link UnsupportedOperationException} — if any
 * alternate-curve table is ever found unpopulated. Under normal operation that
 * path is unreachable.</p>
 */
final class Dim2Id2IsoLvl1
{
    private Dim2Id2IsoLvl1()
    {
    }

    /**
     * Build the lvl1 clapotis precomp bundle from the precomp constants
     * already in the Java tree. Returns {@code null} if any required piece
     * is missing — callers use that as the trigger to throw a descriptive
     * error.
     */
    private static Dim2Id2IsoClapotis.Precomp buildPrecomp()
    {
        CurveWithEndomorphismRing[] curves = EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS;
        if (curves == null || curves.length != EndomorphismActionLvl1.NUM_CURVES)
        {
            return null;
        }

        // Sanity-check that the alternate entries are populated (a zero
        // action_gen2 row indicates the scaffold default).
        for (int i = 1; i < curves.length; i++)
        {
            if (curves[i].actionGen2[0][0].v.signum() == 0
                && curves[i].actionGen3[0][0].v.signum() == 0
                && curves[i].actionGen4[0][0].v.signum() == 0)
            {
                return null;
            }
        }

        return new Dim2Id2IsoClapotis.Precomp(
            curves,
            ConnectingIdealsLvl1.ALTERNATE_CONNECTING_IDEALS,
            ConnectingIdealsLvl1.CONNECTING_IDEALS,
            QuatRepresentIntegerParamsLvl1.INSTANCES,
            PrecompLvl1.NUM_ALTERNATE_EXTREMAL_ORDERS,
            PrecompLvl1.TORSION_EVEN_POWER,
            PrecompLvl1.HD_EXTRA_TORSION,
            PrecompLvl1.QUAT_REPRES_BOUND_INPUT,
            PrecompLvl1.FINDUV_BOX_SIZE,
            PrecompLvl1.FINDUV_CUBE_SIZE,
            PrecompLvl1.IBZ_TORSION_PLUS_2POWER);
    }

    /**
     * {@code dim2id2iso_arbitrary_isogeny_evaluation}: given a left ideal of
     * the standard maximal order O₀, compute the codomain curve E_A and the
     * canonical 2^TORSION_EVEN_POWER-torsion basis on E_A that is the image
     * of the standard basis on E₀ under the secret isogeny.
     *
     * <p>The algorithmic body is in {@link Dim2Id2IsoClapotis#idealToIsogenyClapotis};
     * the lvl1 precomp tables it consumes are assembled by {@link #buildPrecomp()}.</p>
     *
     * @param basis     output: the canonical 2-power torsion basis on the
     *                  codomain curve.
     * @param codomain  output: the codomain curve E_A.
     * @param lideal    input: the secret left ideal.
     * @param random    source of randomness for the rejection-sampling steps;
     *                  callers thread their own {@code SecureRandom} here (KAT
     *                  replay supplies a deterministic one).
     * @return 1 on success, 0 if the isogeny evaluation rejects.
     * @throws UnsupportedOperationException defensive guard, normally
     *         unreachable: only if the lvl1 precomp tables are unexpectedly
     *         unpopulated.
     */
    public static int arbitraryIsogenyEvaluation(EcBasis basis, EcCurve codomain,
                                                 QuatLeftIdeal lideal, SecureRandom random)
    {
        Dim2Id2IsoClapotis.Precomp precomp = buildPrecomp();
        if (precomp == null)
        {
            throw new UnsupportedOperationException(
                "dim2id2iso_arbitrary_isogeny_evaluation: lvl1 precomp tables are"
                + " unpopulated (CURVES_WITH_ENDOMORPHISMS alternate entries,"
                + " ALTERNATE_CONNECTING_IDEALS, CONNECTING_IDEALS, or"
                + " QuatRepresentIntegerParamsLvl1.INSTANCES) - this should not happen.");
        }

        Dim2Id2IsoClapotis.Result result =
            Dim2Id2IsoClapotis.idealToIsogenyClapotis(lideal, PrecompLvl1.QUATALG_PINFTY, precomp, random);
        if (result == null)
        {
            return 0;
        }
        EcBasis.copy(basis, result.basis);
        EcCurve.copy(codomain, result.codomain);
        return 1;
    }
}
