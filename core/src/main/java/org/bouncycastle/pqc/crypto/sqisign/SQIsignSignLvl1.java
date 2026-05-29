package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;


/**
 * Lvl1 driver for the shared {@link SQIsignSign} engine.
 */
final class SQIsignSignLvl1
{
    private static final SQIsignSign.Params PARAMS = new SQIsignSign.Params(
        GfFieldLvl1.INSTANCE,
        PrecompLvl1.COM_DEGREE,
        PrecompLvl1.QUATALG_PINFTY,
        PrecompLvl1.QUAT_PRIMALITY_NUM_ITER,
        PrecompLvl1.QUAT_EQUIV_BOUND_COEFF,
        QuatRepresentIntegerParamsLvl1.INSTANCE,
        ExtremalOrdersLvl1.MAXORD_O0,
        ExtremalOrdersLvl1.QUAT_PRIME_COFACTOR,
        PrecompLvl1.SQIsign_RESPONSE_LENGTH,
        PrecompLvl1.TORSION_EVEN_POWER,
        PrecompLvl1.HD_EXTRA_TORSION,
        PrecompLvl1.P_COFACTOR_FOR_2F.longValueExact(),
        PrecompLvl1.IBZ_TORSION_PLUS_2POWER,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionI,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionJ,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionGen2,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionGen3,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionGen4,
        Dim2Id2IsoLvl1::arbitraryIsogenyEvaluation,
        EcBasisLvl1::toHint,
        ThetaChainLvl1::chainComputeAndEvalRandomized,
        SQIsignHashLvl1::hashToChallenge);

    private SQIsignSignLvl1()
    {
    }

    public static int protocolsSign(SQIsignSignatureLvl1 sig,
                                    EcCurve pkCurve, SQIsignSecretKeyData sk,
                                    byte[] message, SecureRandom random)
    {
        return SQIsignSign.protocolsSign(PARAMS, sig, pkCurve, sk, message, random);
    }
}
