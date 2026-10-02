package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.BigIntegers;

/**
 * Generates an SM9 signature master key pair (ks, P_pub-s = [ks]P2), where the
 * master private key ks is chosen uniformly from [1, N-1] (GM/T 0044.2-2016, 5.3).
 */
public class SM9SigMasterKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    /**
     * Draws of ks allowed for one key pair. A draw is discarded when it falls outside [1, N-1],
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
        // ks in [1, N-1], drawn and range-checked here rather than by
        // BigIntegers.createRandomInRange, which after a thousand draws out of range falls back to
        // one that cannot fail - for a source that yields only zeros, ks = 1
        BigInteger n = SM9Curve.N;
        BigInteger ks;
        int attempt = 0;
        do
        {
            if (attempt++ == MAX_REDRAWS)
            {
                throw new IllegalStateException("SM9 master key generation could not draw a usable key");
            }
            ks = BigIntegers.createRandomBigInteger(n.bitLength(), rand);
        }
        while (ks.signum() == 0 || ks.compareTo(n) >= 0);
        SM9SigMasterPrivateKeyParameters priv = new SM9SigMasterPrivateKeyParameters(ks);
        return new AsymmetricCipherKeyPair(priv.getPublicKeyParameters(), priv);
    }
}
