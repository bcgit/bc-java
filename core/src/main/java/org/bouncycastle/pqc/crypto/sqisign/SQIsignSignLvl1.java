package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;


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
        BigIntegers.longValueExact(PrecompLvl1.P_COFACTOR_FOR_2F),
        PrecompLvl1.IBZ_TORSION_PLUS_2POWER,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionI,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionJ,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionGen2,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionGen3,
        EndomorphismActionLvl1.CURVES_WITH_ENDOMORPHISMS[0].actionGen4,
        new SQIsignSign.IdealToIsogeny()
        {
            public int arbitraryIsogenyEvaluation(EcBasis basis, EcCurve codomain,
                                                  QuatLeftIdeal lideal, SecureRandom random)
            {
                return Dim2Id2IsoLvl1.arbitraryIsogenyEvaluation(basis, codomain, lideal, random);
            }
        },
        new SQIsignSign.ToHint()
        {
            public int toHint(EcBasis basis, EcCurve curve, int torsionEvenPower)
            {
                return EcBasisLvl1.toHint(basis, curve, torsionEvenPower);
            }
        },
        new SQIsignSign.ChainComputeAndEvalRandomized()
        {
            public int chainComputeAndEvalRandomized(int n, ThetaCoupleCurve E12,
                                                     ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                     ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                                     SecureRandom random)
            {
                return ThetaChainLvl1.chainComputeAndEvalRandomized(n, E12, ker, extraTorsion, E34, P12, numP, random);
            }
        },
        new SQIsignSign.HashToChallenge()
        {
            public BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
            {
                return SQIsignHashLvl1.hashToChallenge(pkCurve, comCurve, message);
            }
        });

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
