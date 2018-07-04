package org.bouncycastle.pqc.jcajce.provider.newhope;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

public class NHKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    NHKeyPairGenerator engine = new NHKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public NHKeyPairGeneratorSpi()
    {
        super("NH");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        if (strength != 1024)
        {
            throw new IllegalArgumentException("strength must be 1024 bits");
        }
        engine.init(new KeyGenerationParameters(random, 1024));
        initialised = true;
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("parameter object not recognised");
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            engine.init(new KeyGenerationParameters(random, 1024));
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        NHPublicKeyParameters pub = (NHPublicKeyParameters)pair.getPublic();
        NHPrivateKeyParameters priv = (NHPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCNHPublicKey(pub), new BCNHPrivateKey(priv));
    }
}
