package org.bouncycastle.pqc.crypto.sqisign;

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
            EcBasisLvl5::fromHint,
            ThetaChainLvl5::chainComputeAndEvalVerify,
            SQIsignHashLvl5::hashToChallenge);
    }
}
