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
import org.bouncycastle.jcajce.spec.SM9UserKeyParameterSpec;

/**
 * Generator for SM9 encryption key pairs (GM/T 0044.4), registered as
 * {@code KeyPairGenerator.SM9-ENC}. What it generates is selected by initialisation,
 * mirroring how EC key generation is parameterised by curve:
 * <ul>
 * <li><b>uninitialised</b> (or {@code initialize(int, SecureRandom)}) - a fresh
 *     <b>master</b> key pair, the KGC's randomly-generated root of the scheme;</li>
 * <li>{@code initialize(}{@link SM9UserKeyParameterSpec}{@code )} - the <b>user</b> key
 *     pair for the spec's identity under its master private key: the public key to
 *     encapsulate to and the private key that decapsulates. This derivation is
 *     deterministic (a KGC operation, hid = 0x03) - the same master key and identity
 *     always yield the same pair.</li>
 * </ul>
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private final SM9EncMasterKeyPairGenerator engine = new SM9EncMasterKeyPairGenerator();
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;
    private SM9UserKeyParameterSpec userSpec = null;

    public KeyPairGeneratorSpi()
    {
        super("SM9-ENC");
    }

    public void initialize(int strength, SecureRandom random)
    {
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
        this.initialised = false;
        this.userSpec = null;
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof SM9UserKeyParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(
                "SM9-ENC user key generation requires an SM9UserKeyParameterSpec");
        }
        SM9UserKeyParameterSpec spec = (SM9UserKeyParameterSpec)params;
        if (!(spec.getMasterPrivateKey() instanceof BCSM9EncMasterPrivateKey))
        {
            throw new InvalidAlgorithmParameterException(
                "SM9-ENC user key generation requires an SM9-ENC master private key");
        }
        this.userSpec = spec;
    }

    public KeyPair generateKeyPair()
    {
        if (userSpec != null)
        {
            BCSM9EncMasterPrivateKey master = (BCSM9EncMasterPrivateKey)userSpec.getMasterPrivateKey();
            byte[] id = userSpec.getIdentity();

            return new KeyPair(
                new BCSM9EncPublicKey(master.getMasterPublicKey(), id),
                master.extractPrivateKey(id));
        }

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
