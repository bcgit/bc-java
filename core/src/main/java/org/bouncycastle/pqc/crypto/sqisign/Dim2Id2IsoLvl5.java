package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;


/**
 * Level-5 wrapper for {@code dim2id2iso_arbitrary_isogeny_evaluation}.
 * Sibling of {@link Dim2Id2IsoLvl1}; supplies the lvl5 precomp bundle and
 * delegates to {@link Dim2Id2IsoClapotis}.
 */
final class Dim2Id2IsoLvl5
{
    private Dim2Id2IsoLvl5()
    {
    }

    private static Dim2Id2IsoClapotis.Precomp buildPrecomp()
    {
        CurveWithEndomorphismRing[] curves = CurvesWithEndomorphismsLvl5.CURVES_WITH_ENDOMORPHISMS;
        return new Dim2Id2IsoClapotis.Precomp(
            GfFieldLvl5.INSTANCE,
            curves,
            ConnectingIdealsLvl5.ALTERNATE_CONNECTING_IDEALS,
            ConnectingIdealsLvl5.CONNECTING_IDEALS,
            QuatRepresentIntegerParamsLvl5.INSTANCES,
            PrecompLvl5.NUM_ALTERNATE_EXTREMAL_ORDERS,
            PrecompLvl5.TORSION_EVEN_POWER,
            PrecompLvl5.HD_EXTRA_TORSION,
            PrecompLvl5.QUAT_REPRES_BOUND_INPUT,
            PrecompLvl5.FINDUV_BOX_SIZE,
            PrecompLvl5.FINDUV_CUBE_SIZE,
            PrecompLvl5.IBZ_TORSION_PLUS_2POWER);
    }

    public static int arbitraryIsogenyEvaluation(EcBasis basis, EcCurve codomain,
                                                 QuatLeftIdeal lideal, SecureRandom random)
    {
        Dim2Id2IsoClapotis.Result result =
            Dim2Id2IsoClapotis.idealToIsogenyClapotis(
                lideal, QuatRepresentIntegerParamsLvl5.QUATALG_PINFTY,
                buildPrecomp(), random);
        if (result == null)
        {
            return 0;
        }
        EcBasis.copy(basis, result.basis);
        EcCurve.copy(codomain, result.codomain);
        return 1;
    }
}
