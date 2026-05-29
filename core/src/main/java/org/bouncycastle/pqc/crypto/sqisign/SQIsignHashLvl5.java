package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * SQIsign level-5 challenge-hash wrapper. Delegates to {@link SQIsignHash}
 * with the lvl5 field instance and {@link PrecompLvl5} constants.
 */
final class SQIsignHashLvl5
{
    private SQIsignHashLvl5()
    {
    }

    public static BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
    {
        return SQIsignHash.hashToChallenge(GfFieldLvl5.INSTANCE, pkCurve, comCurve, message,
            PrecompLvl5.SECURITY_BITS, PrecompLvl5.HASH_ITERATIONS,
            PrecompLvl5.TORSION_EVEN_POWER, PrecompLvl5.SQIsign_RESPONSE_LENGTH);
    }
}
