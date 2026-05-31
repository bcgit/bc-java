package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;


/**
 * Lvl3 driver for the shared {@link SQIsignSign} engine.
 */
final class SQIsignSignLvl3
{
    private static final SQIsignSign.Params PARAMS = new SQIsignSign.Params(
        GfFieldLvl3.INSTANCE,
        PrecompLvl3.COM_DEGREE,
        QuatRepresentIntegerParamsLvl3.QUATALG_PINFTY,
        PrecompLvl3.QUAT_PRIMALITY_NUM_ITER,
        PrecompLvl3.QUAT_EQUIV_BOUND_COEFF,
        QuatRepresentIntegerParamsLvl3.INSTANCE,
        ExtremalOrdersLvl3.MAXORD_O0,
        ExtremalOrdersLvl3.QUAT_PRIME_COFACTOR,
        PrecompLvl3.SQIsign_RESPONSE_LENGTH,
        PrecompLvl3.TORSION_EVEN_POWER,
        PrecompLvl3.HD_EXTRA_TORSION,
        PrecompLvl3.P_COFACTOR_FOR_2F.longValueExact(),
        PrecompLvl3.IBZ_TORSION_PLUS_2POWER,
        CurvesWithEndomorphismsLvl3.CURVES_WITH_ENDOMORPHISMS[0].actionI,
        CurvesWithEndomorphismsLvl3.CURVES_WITH_ENDOMORPHISMS[0].actionJ,
        CurvesWithEndomorphismsLvl3.CURVES_WITH_ENDOMORPHISMS[0].actionGen2,
        CurvesWithEndomorphismsLvl3.CURVES_WITH_ENDOMORPHISMS[0].actionGen3,
        CurvesWithEndomorphismsLvl3.CURVES_WITH_ENDOMORPHISMS[0].actionGen4,
        Dim2Id2IsoLvl3::arbitraryIsogenyEvaluation,
        EcBasisLvl3::toHint,
        ThetaChainLvl3::chainComputeAndEvalRandomized,
        SQIsignHashLvl3::hashToChallenge);

    private SQIsignSignLvl3()
    {
    }

    public static int protocolsSign(SQIsignSignatureLvl3 sig,
                                    EcCurve pkCurve, SQIsignSecretKeyData sk,
                                    byte[] message, SecureRandom random)
    {
        return SQIsignSign.protocolsSign(PARAMS, sig, pkCurve, sk, message, random);
    }
}
