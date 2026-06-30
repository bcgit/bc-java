package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;


/**
 * Lvl5 driver for the shared {@link SQIsignSign} engine.
 */
final class SQIsignSignLvl5
{
    private static final SQIsignSign.Params PARAMS = new SQIsignSign.Params(
        GfFieldLvl5.INSTANCE,
        PrecompLvl5.COM_DEGREE,
        QuatRepresentIntegerParamsLvl5.QUATALG_PINFTY,
        PrecompLvl5.QUAT_PRIMALITY_NUM_ITER,
        PrecompLvl5.QUAT_EQUIV_BOUND_COEFF,
        QuatRepresentIntegerParamsLvl5.INSTANCE,
        ExtremalOrdersLvl5.MAXORD_O0,
        ExtremalOrdersLvl5.QUAT_PRIME_COFACTOR,
        PrecompLvl5.SQIsign_RESPONSE_LENGTH,
        PrecompLvl5.TORSION_EVEN_POWER,
        PrecompLvl5.HD_EXTRA_TORSION,
        BigIntegers.longValueExact(PrecompLvl5.P_COFACTOR_FOR_2F),
        PrecompLvl5.IBZ_TORSION_PLUS_2POWER,
        CurvesWithEndomorphismsLvl5.CURVES_WITH_ENDOMORPHISMS[0].actionI,
        CurvesWithEndomorphismsLvl5.CURVES_WITH_ENDOMORPHISMS[0].actionJ,
        CurvesWithEndomorphismsLvl5.CURVES_WITH_ENDOMORPHISMS[0].actionGen2,
        CurvesWithEndomorphismsLvl5.CURVES_WITH_ENDOMORPHISMS[0].actionGen3,
        CurvesWithEndomorphismsLvl5.CURVES_WITH_ENDOMORPHISMS[0].actionGen4,
        new SQIsignSign.IdealToIsogeny()
        {
            public int arbitraryIsogenyEvaluation(EcBasis basis, EcCurve codomain,
                                                  QuatLeftIdeal lideal, SecureRandom random)
            {
                return Dim2Id2IsoLvl5.arbitraryIsogenyEvaluation(basis, codomain, lideal, random);
            }
        },
        new SQIsignSign.ToHint()
        {
            public int toHint(EcBasis basis, EcCurve curve, int torsionEvenPower)
            {
                return EcBasisLvl5.toHint(basis, curve, torsionEvenPower);
            }
        },
        new SQIsignSign.ChainComputeAndEvalRandomized()
        {
            public int chainComputeAndEvalRandomized(int n, ThetaCoupleCurve E12,
                                                     ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                     ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                                     SecureRandom random)
            {
                return ThetaChainLvl5.chainComputeAndEvalRandomized(n, E12, ker, extraTorsion, E34, P12, numP, random);
            }
        },
        new SQIsignSign.HashToChallenge()
        {
            public BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
            {
                return SQIsignHashLvl5.hashToChallenge(pkCurve, comCurve, message);
            }
        });

    private SQIsignSignLvl5()
    {
    }

    public static int protocolsSign(SQIsignSignatureLvl5 sig,
                                    EcCurve pkCurve, SQIsignSecretKeyData sk,
                                    byte[] message, SecureRandom random)
    {
        return SQIsignSign.protocolsSign(PARAMS, sig, pkCurve, sk, message, random);
    }
}
