package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;

/**
 * Generator for SM9 encryption <b>master</b> key pairs (GM/T 0044.4), registered as
 * {@code KeyPairGenerator.SM9-ENC}: the KGC's randomly-generated root of the scheme.
 * A <b>user's</b> key pair is not generated here - it is derived from the master
 * private key via
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey#generateUserKeyPair(byte[])},
 * the deterministic KGC operation (hid = 0x03) identity-based schemes call key extraction.
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private final SM9EncMasterKeyPairGenerator engine = new SM9EncMasterKeyPairGenerator();
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("SM9-ENC");
    }

    public void initialize(int strength, SecureRandom random)
    {
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
        this.initialised = false;
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException(
            "SM9-ENC master key generation takes no AlgorithmParameterSpec; user key pairs come from SM9EncMasterPrivateKey.generateUserKeyPair()");
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            engine.init(new KeyGenerationParameters(random, 256));
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        return new KeyPair(
            new BCSM9EncMasterPublicKey((SM9EncMasterPublicKeyParameters)pair.getPublic()),
            new BCSM9EncMasterPrivateKey((SM9EncMasterPrivateKeyParameters)pair.getPrivate()));
    }
}
