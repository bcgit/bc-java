package org.bouncycastle.pqc.crypto.sqisign;

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
            EcBasisLvl3::fromHint,
            ThetaChainLvl3::chainComputeAndEvalVerify,
            SQIsignHashLvl3::hashToChallenge);
    }
}
