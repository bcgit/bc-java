package org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Generates key pairs compatible with the X-Wing hybrid Key Encapsulation Mechanism (KEM).
 * <p>
 * This class produces key pairs that include both X25519 and ML-KEM-768 components,
 * suitable for use in the X-Wing KEM as specified in the IETF draft.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/07/">X-Wing KEM Draft</a>
 */
public class XWingKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    static AsymmetricCipherKeyPair genKeyPair(byte[] seed)
    {
        // Step 2: Expand seed to 96 bytes using SHAKE256
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, seed.length);
        byte[] expanded = new byte[96];
        shake.doOutput(expanded, 0, expanded.length);

        // Step 3: Split expanded bytes
        byte[] mlkemSeed = Arrays.copyOfRange(expanded, 0, 64);
        byte[] skX = Arrays.copyOfRange(expanded, 64, 96);

        // Step 4a: Generate ML-KEM key pair deterministically
        SecureRandom mlkemRandom = new FixedSecureRandom(mlkemSeed);
        MLKEMKeyPairGenerator mlkemKeyGen = new MLKEMKeyPairGenerator();
        mlkemKeyGen.init(new MLKEMKeyGenerationParameters(mlkemRandom, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair mlkemKp = mlkemKeyGen.generateKeyPair();
        MLKEMPublicKeyParameters mlkemPub = (MLKEMPublicKeyParameters)mlkemKp.getPublic();
        MLKEMPrivateKeyParameters mlkemPriv = (MLKEMPrivateKeyParameters)mlkemKp.getPrivate();

        // Step 4b: Generate X25519 key pair deterministically
        SecureRandom xdhRandom = new FixedSecureRandom(skX);
        X25519KeyPairGenerator xdhKeyGen = new X25519KeyPairGenerator();
        xdhKeyGen.init(new X25519KeyGenerationParameters(xdhRandom));
        AsymmetricCipherKeyPair xdhKp = xdhKeyGen.generateKeyPair();
        X25519PublicKeyParameters xdhPub = (X25519PublicKeyParameters)xdhKp.getPublic();
        X25519PrivateKeyParameters xdhPriv = (X25519PrivateKeyParameters)xdhKp.getPrivate();

        // Step 5: Create X-Wing keys
        return new AsymmetricCipherKeyPair(
            new XWingPublicKeyParameters(mlkemPub, xdhPub),
            new XWingPrivateKeyParameters(seed, mlkemPriv, xdhPriv, mlkemPub, xdhPub)
        );
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        // Step 1: Generate 32-byte random seed
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        return genKeyPair(seed);
    }
}
