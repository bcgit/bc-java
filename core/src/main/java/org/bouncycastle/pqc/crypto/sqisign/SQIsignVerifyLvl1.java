package org.bouncycastle.pqc.crypto.sqisign;

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
            EcBasisLvl1::fromHint,
            ThetaChainLvl1::chainComputeAndEvalVerify,
            SQIsignHashLvl1::hashToChallenge);
    }
}
