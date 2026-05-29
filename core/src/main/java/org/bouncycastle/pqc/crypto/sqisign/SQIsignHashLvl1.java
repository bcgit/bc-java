package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * SQIsign level-1 challenge-hash wrapper. Delegates to {@link SQIsignHash}
 * with the lvl1 field instance and {@link PrecompLvl1} constants.
 */
final class SQIsignHashLvl1
{
    private SQIsignHashLvl1()
    {
    }

    public static BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
    {
        return SQIsignHash.hashToChallenge(GfFieldLvl1.INSTANCE, pkCurve, comCurve, message,
            PrecompLvl1.SECURITY_BITS, PrecompLvl1.HASH_ITERATIONS,
            PrecompLvl1.TORSION_EVEN_POWER, PrecompLvl1.SQIsign_RESPONSE_LENGTH);
    }
}
