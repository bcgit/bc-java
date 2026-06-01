package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Lvl3 driver for the shared {@link SQIsignVerify} engine.
 */
final class SQIsignVerifyLvl3
{
    private SQIsignVerifyLvl3()
    {
    }

    public static int protocolsVerify(SQIsignSignatureLvl3 sig,
                                      EcCurve pkCurve, int hintPk,
                                      byte[] message)
    {
        return SQIsignVerify.protocolsVerify(GfFieldLvl3.INSTANCE, sig, pkCurve, hintPk, message,
            PrecompLvl3.TORSION_EVEN_POWER, PrecompLvl3.SQIsign_RESPONSE_LENGTH,
            PrecompLvl3.HD_EXTRA_TORSION,
            new SQIsignVerify.FromHint()
            {
                public int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint)
                {
                    return EcBasisLvl3.fromHint(basis, curve, torsionEvenPower, hint);
                }
            },
            new SQIsignVerify.ChainComputeAndEvalVerify()
            {
                public int chainComputeAndEvalVerify(int n, ThetaCoupleCurve E12,
                                                     ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                     ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP)
                {
                    return ThetaChainLvl3.chainComputeAndEvalVerify(n, E12, ker, extraTorsion, E34, P12, numP);
                }
            },
            new SQIsignVerify.HashToChallenge()
            {
                public BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
                {
                    return SQIsignHashLvl3.hashToChallenge(pkCurve, comCurve, message);
                }
            });
    }
}
