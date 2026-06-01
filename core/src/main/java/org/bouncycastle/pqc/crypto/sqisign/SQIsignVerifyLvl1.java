package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Lvl1 driver for the shared {@link SQIsignVerify} engine.
 */
final class SQIsignVerifyLvl1
{
    private SQIsignVerifyLvl1()
    {
    }

    public static int protocolsVerify(SQIsignSignatureLvl1 sig,
                                      EcCurve pkCurve, int hintPk,
                                      byte[] message)
    {
        return SQIsignVerify.protocolsVerify(GfFieldLvl1.INSTANCE, sig, pkCurve, hintPk, message,
            PrecompLvl1.TORSION_EVEN_POWER, PrecompLvl1.SQIsign_RESPONSE_LENGTH,
            PrecompLvl1.HD_EXTRA_TORSION,
            new SQIsignVerify.FromHint()
            {
                public int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint)
                {
                    return EcBasisLvl1.fromHint(basis, curve, torsionEvenPower, hint);
                }
            },
            new SQIsignVerify.ChainComputeAndEvalVerify()
            {
                public int chainComputeAndEvalVerify(int n, ThetaCoupleCurve E12,
                                                     ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                     ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP)
                {
                    return ThetaChainLvl1.chainComputeAndEvalVerify(n, E12, ker, extraTorsion, E34, P12, numP);
                }
            },
            new SQIsignVerify.HashToChallenge()
            {
                public BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
                {
                    return SQIsignHashLvl1.hashToChallenge(pkCurve, comCurve, message);
                }
            });
    }
}
