package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.BigIntegers;

/**
 * Generates an SM9 signature master key pair (ks, P_pub-s = [ks]P2), where the
 * master private key ks is chosen uniformly from [1, N-1] (GM/T 0044.2-2016, 5.3).
 */
public class SM9SigMasterKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);
        BigInteger ks = BigIntegers.createRandomInRange(
            ECConstants.ONE, SM9Curve.N.subtract(ECConstants.ONE), rand);
        SM9SigMasterPrivateKeyParameters priv = new SM9SigMasterPrivateKeyParameters(ks);
        return new AsymmetricCipherKeyPair(priv.getPublicKeyParameters(), priv);
    }
}
