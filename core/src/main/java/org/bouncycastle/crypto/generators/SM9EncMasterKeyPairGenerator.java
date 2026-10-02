package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.BigIntegers;

/**
 * Generates an SM9 encryption master key pair (ke, P_pub-e = [ke]P1), with the
 * master private key ke chosen uniformly from [1, N-1] (GM/T 0044.4-2016).
 */
public class SM9EncMasterKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    /**
     * Draws of ke allowed for one key pair. A draw is discarded when it falls outside [1, N-1],
     * which a draw of N's bit length does with probability under 0.29, so needing this many in a
     * row has a probability below 2^-220: reaching it means the random source is not producing
     * usable values rather than that the draws were unlucky.
     */
    private static final int MAX_REDRAWS = 128;

    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);
        // ke in [1, N-1], drawn and range-checked here rather than by
        // BigIntegers.createRandomInRange, which after a thousand draws out of range falls back to
        // one that cannot fail - for a source that yields only zeros, ke = 1
        BigInteger n = SM9Curve.N;
        BigInteger ke;
        int attempt = 0;
        do
        {
            if (attempt++ == MAX_REDRAWS)
            {
                throw new IllegalStateException("SM9 master key generation could not draw a usable key");
            }
            ke = BigIntegers.createRandomBigInteger(n.bitLength(), rand);
        }
        while (ke.signum() == 0 || ke.compareTo(n) >= 0);
        SM9EncMasterPrivateKeyParameters priv = new SM9EncMasterPrivateKeyParameters(ke);
        return new AsymmetricCipherKeyPair(priv.getPublicKeyParameters(), priv);
    }
}
