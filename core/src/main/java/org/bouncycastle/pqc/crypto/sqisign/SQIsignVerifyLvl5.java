package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Lvl5 driver for the shared {@link SQIsignVerify} engine.
 */
final class SQIsignVerifyLvl5
{
    private SQIsignVerifyLvl5()
    {
    }

    public static int protocolsVerify(SQIsignSignatureLvl5 sig,
                                      EcCurve pkCurve, int hintPk,
                                      byte[] message)
    {
        return SQIsignVerify.protocolsVerify(GfFieldLvl5.INSTANCE, sig, pkCurve, hintPk, message,
            PrecompLvl5.TORSION_EVEN_POWER, PrecompLvl5.SQIsign_RESPONSE_LENGTH,
            PrecompLvl5.HD_EXTRA_TORSION,
            new SQIsignVerify.FromHint()
            {
                public int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint)
                {
                    return EcBasisLvl5.fromHint(basis, curve, torsionEvenPower, hint);
                }
            },
            new SQIsignVerify.ChainComputeAndEvalVerify()
            {
                public int chainComputeAndEvalVerify(int n, ThetaCoupleCurve E12,
                                                     ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                     ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP)
                {
                    return ThetaChainLvl5.chainComputeAndEvalVerify(n, E12, ker, extraTorsion, E34, P12, numP);
                }
            },
            new SQIsignVerify.HashToChallenge()
            {
                public BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
                {
                    return SQIsignHashLvl5.hashToChallenge(pkCurve, comCurve, message);
                }
            });
    }
}
