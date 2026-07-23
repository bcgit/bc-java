package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.BigIntegers;

/**
 * Generates an SM9 encryption master key pair (ke, P_pub-e = [ke]P1), with the
 * master private key ke chosen uniformly from [1, N-1] (GM/T 0044.4-2016).
 */
public class SM9EncMasterKeyPairGenerator
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
        BigInteger ke = BigIntegers.createRandomInRange(
            ECConstants.ONE, SM9Curve.N.subtract(ECConstants.ONE), rand);
        SM9EncMasterPrivateKeyParameters priv = new SM9EncMasterPrivateKeyParameters(ke);
        return new AsymmetricCipherKeyPair(priv.getPublicKeyParameters(), priv);
    }
}
