package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;


/**
 * Level-3 wrapper for {@code dim2id2iso_arbitrary_isogeny_evaluation}.
 * Sibling of {@link Dim2Id2IsoLvl1}; supplies the lvl3 precomp bundle and
 * delegates the algorithmic body to {@link Dim2Id2IsoClapotis}.
 */
final class Dim2Id2IsoLvl3
{
    private Dim2Id2IsoLvl3()
    {
    }

    private static Dim2Id2IsoClapotis.Precomp buildPrecomp()
    {
        CurveWithEndomorphismRing[] curves = CurvesWithEndomorphismsLvl3.CURVES_WITH_ENDOMORPHISMS;
        return new Dim2Id2IsoClapotis.Precomp(
            GfFieldLvl3.INSTANCE,
            curves,
            ConnectingIdealsLvl3.ALTERNATE_CONNECTING_IDEALS,
            ConnectingIdealsLvl3.CONNECTING_IDEALS,
            QuatRepresentIntegerParamsLvl3.INSTANCES,
            PrecompLvl3.NUM_ALTERNATE_EXTREMAL_ORDERS,
            PrecompLvl3.TORSION_EVEN_POWER,
            PrecompLvl3.HD_EXTRA_TORSION,
            PrecompLvl3.QUAT_REPRES_BOUND_INPUT,
            PrecompLvl3.FINDUV_BOX_SIZE,
            PrecompLvl3.FINDUV_CUBE_SIZE,
            PrecompLvl3.IBZ_TORSION_PLUS_2POWER);
    }

    public static int arbitraryIsogenyEvaluation(EcBasis basis, EcCurve codomain,
                                                 QuatLeftIdeal lideal, SecureRandom random)
    {
        Dim2Id2IsoClapotis.Result result =
            Dim2Id2IsoClapotis.idealToIsogenyClapotis(
                lideal, QuatRepresentIntegerParamsLvl3.QUATALG_PINFTY,
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
