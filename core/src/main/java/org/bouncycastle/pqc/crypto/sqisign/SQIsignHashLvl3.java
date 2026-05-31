package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * SQIsign level-3 challenge-hash wrapper. Delegates to {@link SQIsignHash}
 * with the lvl3 field instance and {@link PrecompLvl3} constants.
 */
final class SQIsignHashLvl3
{
    private SQIsignHashLvl3()
    {
    }

    public static BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message)
    {
        return SQIsignHash.hashToChallenge(GfFieldLvl3.INSTANCE, pkCurve, comCurve, message,
            PrecompLvl3.SECURITY_BITS, PrecompLvl3.HASH_ITERATIONS,
            PrecompLvl3.TORSION_EVEN_POWER, PrecompLvl3.SQIsign_RESPONSE_LENGTH);
    }
}
