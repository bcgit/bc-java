package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.generators.SM9SigMasterKeyPairGenerator;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;

/**
 * Generator for SM9 encryption <b>master</b> key pairs (GM/T 0044.4), registered as
 * {@code KeyPairGenerator.SM9-ENC}: the KGC's randomly-generated root of the scheme.
 * A <b>user's</b> key pair is not generated here - it is derived from the master
 * private key via
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey#generateUserKeyPair(byte[], byte)},
 * the deterministic KGC operation (hid = 0x03) identity-based schemes call key extraction.
 * <p>
 * The signature master key generator, {@link Sign}, differs from this one only in the
 * lightweight generator it drives and the key classes it hands back, which is all it overrides.
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private final AsymmetricCipherKeyPairGenerator engine;
    private final String userKeyPairSource;
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        this("SM9-ENC", new SM9EncMasterKeyPairGenerator(), "SM9EncMasterPrivateKey.generateUserKeyPair(identity, hid)");
    }

    KeyPairGeneratorSpi(String algorithm, AsymmetricCipherKeyPairGenerator engine, String userKeyPairSource)
    {
        super(algorithm);
        this.engine = engine;
        this.userKeyPairSource = userKeyPairSource;
    }

    public void initialize(int strength, SecureRandom random)
    {
        checkStrength(strength);
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
        this.initialised = false;
    }

    /**
     * SM9 has one parameter set, the 256-bit BN curve of GM/T 0044.5, so 256 is the only
     * strength there is. Anything else was silently ignored, handing back a 256-bit key to a
     * caller who had asked for another size and would reasonably take a key at all as having
     * got what was asked for.
     */
    static void checkStrength(int strength)
    {
        if (strength != 256)
        {
            throw new InvalidParameterException(
                "SM9 is defined only on its 256-bit curve; strength must be 256, not " + strength);
        }
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException(getAlgorithm()
            + " master key generation takes no AlgorithmParameterSpec; user key pairs come from " + userKeyPairSource);
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            engine.init(new KeyGenerationParameters(random, 256));
            initialised = true;
        }

        return wrap(engine.generateKeyPair());
    }

    KeyPair wrap(AsymmetricCipherKeyPair pair)
    {
        return new KeyPair(
            new BCSM9EncMasterPublicKey((SM9EncMasterPublicKeyParameters)pair.getPublic()),
            new BCSM9EncMasterPrivateKey((SM9EncMasterPrivateKeyParameters)pair.getPrivate()));
    }

    /**
     * Generator for the SM9 signature master key pair (GM/T 0044.2), registered as
     * {@code KeyPairGenerator.SM9-SIGN}. A user's signing key pair is derived from
     * the master private key via
     * {@link org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey#generateUserKeyPair(byte[])},
     * the deterministic KGC operation (hid = 0x01).
     */
    public static class Sign
        extends KeyPairGeneratorSpi
    {
        public Sign()
        {
            super("SM9-SIGN", new SM9SigMasterKeyPairGenerator(), "SM9SigMasterPrivateKey.generateUserKeyPair()");
        }

        KeyPair wrap(AsymmetricCipherKeyPair pair)
        {
            return new KeyPair(
                new BCSM9SigMasterPublicKey((SM9SigMasterPublicKeyParameters)pair.getPublic()),
                new BCSM9SigMasterPrivateKey((SM9SigMasterPrivateKeyParameters)pair.getPrivate()));
        }
    }
}
