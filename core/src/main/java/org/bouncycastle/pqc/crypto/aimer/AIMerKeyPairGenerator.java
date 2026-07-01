package org.bouncycastle.pqc.crypto.aimer;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
/**
 * Implementation of the AIMer asymmetric key pair generator following the AIMer signature scheme specifications.
 * <p>
 * This generator produces {@link AIMerPublicKeyParameters} and {@link AIMerPrivateKeyParameters} based on the
 * AIMer algorithm parameters. The implementation follows the specification defined in the official AIMer
 * documentation and reference implementation.
 * </p>
 *
 * <p>AIMer is a <b>selected algorithm</b> in the <b>Korean Post-Quantum Cryptography (KPQC) project</b>.
 *
 * <p>References:</p>
 * <ul>
 *   <li><a href="https://aimer-signature.org/">AIMer Official Website</a></li>
 *   <li><a href="https://aimer-signature.org/docs/AIMer_Specification_v260130.pdf">AIMer Specification Document</a></li>
 *   <li><a href="https://github.com/samsungsds-research-papers/AIMer">AIMer Reference Implementation (unavailable right now)</a></li>
 * </ul>
 */
public class AIMerKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    private AIMerKeyGenerationParameters aimerKeyGenerationParameters;

    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters params)
    {
        this.aimerKeyGenerationParameters = (AIMerKeyGenerationParameters)params;
        this.random = params.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pk = new byte[aimerKeyGenerationParameters.getParameters().getPublicKeyBytes()];
        byte[] sk = new byte[aimerKeyGenerationParameters.getParameters().getSecretKeyBytes()];
        int AIM2_IV_SIZE = aimerKeyGenerationParameters.getParameters().getAim2IVSize();
        int AIM2_NUM_BYTES_FIELD = aimerKeyGenerationParameters.getParameters().getAim2NumBytesField();
        AIMerEngine engine = new AIMerEngine(aimerKeyGenerationParameters.getParameters());
        byte[] tmp = new byte[AIM2_NUM_BYTES_FIELD];
        byte[] iv = new byte[AIM2_IV_SIZE];
        random.nextBytes(tmp);  // Fill entire sk array with random bytes
        random.nextBytes(iv);  // Fill entire pk array with random bytes
        System.arraycopy(tmp, 0, sk, 0, AIM2_IV_SIZE);
        System.arraycopy(iv, 0, pk, 0, AIM2_IV_SIZE);

        byte[] ciphertext = new byte[AIM2_NUM_BYTES_FIELD];
        engine.aim2(ciphertext, sk, iv);

        // Copy ciphertext to pk after IV
        System.arraycopy(ciphertext, 0, pk, AIM2_IV_SIZE, AIM2_NUM_BYTES_FIELD);

        System.arraycopy(pk, 0, sk, AIM2_NUM_BYTES_FIELD, AIM2_IV_SIZE + AIM2_NUM_BYTES_FIELD);

        // form keys
        AIMerPublicKeyParameters publicKey = new AIMerPublicKeyParameters(aimerKeyGenerationParameters.getParameters(), pk);
        AIMerPrivateKeyParameters privateKey = new AIMerPrivateKeyParameters(aimerKeyGenerationParameters.getParameters(), sk);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}

