package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Level-independent challenge-hash core. Java port of {@code hash_to_challenge}
 * from {@code src/verification/ref/lvlx/common.c}.
 *
 * <p>Inputs: the public-key curve, the commitment curve, and the message
 * bytes. Computes their j-invariants, encodes them as fp² byte blobs, then
 * runs SHAKE256 over {@code (j1 || j2 || message)}. Iterates
 * {@code hashIterations} times re-absorbing the output; the final iteration
 * produces a scalar mod {@code 2^securityBits}.</p>
 *
 * <p>Driven from {@link SQIsignHashLvl1}, {@link SQIsignHashLvl3},
 * {@link SQIsignHashLvl5}, each of which supplies the field instance and
 * the level-specific constants from {@code PrecompLvlN}.</p>
 */
final class SQIsignHash
{
    private SQIsignHash()
    {
    }

    static BigInteger hashToChallenge(GfField field, EcCurve pkCurve, EcCurve comCurve,
                                      byte[] message,
                                      int securityBits, int hashIterations,
                                      int torsionEvenPower, int responseLength)
    {
        int fp2Bytes = field.fp2EncodedBytes();

        Fp2 j1 = Fp2.zero();
        Fp2 j2 = Fp2.zero();
        EcOps.jInv(field, j1, pkCurve);
        EcOps.jInv(field, j2, comCurve);

        byte[] buf = new byte[2 * fp2Bytes];
        field.fp2Encode(buf, 0, j1);
        field.fp2Encode(buf, fp2Bytes, j2);

        int hashBytes = ((2 * securityBits) + 7) / 8;
        int finalBits = 2 * securityBits;
        int extraBits = finalBits & 7;
        byte mask = (byte)(extraBits == 0 ? 0xFF : ((1 << extraBits) - 1));

        byte[] scalar = new byte[hashBytes];
        SHAKEDigest ctx = new SHAKEDigest(256);
        ctx.update(buf, 0, buf.length);
        ctx.update(message, 0, message.length);
        ctx.doOutput(scalar, 0, hashBytes);
        scalar[hashBytes - 1] &= mask;

        for (int i = 2; i < hashIterations; i++)
        {
            ctx = new SHAKEDigest(256);
            ctx.update(scalar, 0, hashBytes);
            ctx.doOutput(scalar, 0, hashBytes);
            scalar[hashBytes - 1] &= mask;
        }

        ctx = new SHAKEDigest(256);
        ctx.update(scalar, 0, hashBytes);

        int finalScalarBits = torsionEvenPower - responseLength;
        int finalScalarBytes = (finalScalarBits + 7) / 8;
        int finalScalarExtraBits = finalScalarBits & 7;
        byte finalMask = (byte)(finalScalarExtraBits == 0 ? 0xFF
            : ((1 << finalScalarExtraBits) - 1));

        byte[] outScalar = new byte[finalScalarBytes];
        ctx.doOutput(outScalar, 0, finalScalarBytes);
        outScalar[finalScalarBytes - 1] &= finalMask;

        BigInteger v = leBytesToBigInteger(outScalar);
        BigInteger mod = BigInteger.ONE.shiftLeft(securityBits);
        return v.mod(mod);
    }

    private static BigInteger leBytesToBigInteger(byte[] le)
    {
        byte[] be = new byte[le.length + 1];
        be[0] = 0;
        for (int i = 0; i < le.length; i++)
        {
            be[1 + i] = le[le.length - 1 - i];
        }
        return new BigInteger(be);
    }
}
