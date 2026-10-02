package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * The steps the SM9 KGC's signature and encryption key derivations share (GM/T 0044.2-2016 5.3,
 * GM/T 0044.4-2016 5.3): the width the master scalar is encoded at, and the user-key scalar
 * t2 = s * t1^-1 mod N with t1 = H1(ID || hid, N) + s, for the master secret s. Held once so that
 * the constant-time treatment of s cannot drift between the two master-key classes.
 */
final class SM9KeyDerivation
{
    private SM9KeyDerivation()
    {
    }

    /**
     * t2 = s * (H1(identity || hid, N) + s)^-1 mod N for the master secret s.
     * <p>
     * Every step touches s, so each avoids the variable-time BigInteger arithmetic: modAdd for the
     * sum, modOddInverse rather than modInverse, and modMult for the product. N is the group order
     * and so is odd, h1 returns a value in [1, N-1] and the master-key constructors pin s to
     * [1, N-1], so both stay inside the [0, N) contract those helpers require. The identity is
     * public and supplied by the caller, so a reduction whose cost varied with the sum or the
     * product would answer a question about s once per identity served, and those answers combine.
     *
     * @param regenerate the message to report t1 = 0 with, the case in which the master key has to
     *                   be regenerated for this identity.
     */
    static BigInteger t2(BigInteger s, byte[] identity, byte hid, String regenerate)
    {
        BigInteger n = SM9Curve.N;
        BigInteger t1 = BigIntegers.modAdd(n, SM9Sm3.h1(Arrays.append(identity, hid), n), s);
        if (t1.signum() == 0)
        {
            throw new IllegalStateException(regenerate);
        }
        return BigIntegers.modMult(n, s, BigIntegers.modOddInverse(n, t1));
    }

    /**
     * The master scalar is written as exactly 32 big-endian bytes by the master keys'
     * {@code getEncoded()}, and only that is read back: a shorter or longer input names the same
     * value through several encodings, and the range check on the scalar catches neither. The JCE
     * KeyFactory path already required the exact length; the lightweight API it wraps did not.
     */
    static void checkScalarEncoding(byte[] enc)
    {
        if (enc.length != 32)
        {
            throw new IllegalArgumentException("SM9 master private key must be 32 bytes");
        }
    }
}
