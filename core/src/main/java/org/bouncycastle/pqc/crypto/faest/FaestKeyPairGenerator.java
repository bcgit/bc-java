package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * FAEST key-pair generator.
 * <p>
 * Mirrors the upstream {@code faest_<lambda>_keygen} flow:
 * <ol>
 *   <li>Draw {@code lambda/8} bytes of OWF key material, rejecting any sample
 *       whose low two bits are both set (matches the upstream validity check on
 *       {@code SK_KEY}).</li>
 *   <li>Draw {@code owfInputSize} bytes for the OWF input.</li>
 *   <li>Compute {@code owfOutput = OWF(owfKey, owfInput)} via {@link Faest#owf}.</li>
 *   <li>Pack {@code pk = owfInput || owfOutput} and {@code sk = owfInput || owfKey}.</li>
 * </ol>
 */
public class FaestKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private FaestParameters params;
    private SecureRandom random;
    private boolean initialized;

    @Override
    public void init(KeyGenerationParameters param)
    {
        FaestKeyGenerationParameters fp = (FaestKeyGenerationParameters)param;
        this.params = fp.getParameters();
        this.random = fp.getRandom();
        this.initialized = true;
    }

    /**
     * Generate a fresh FAEST key pair.
     * <p>
     * <b>Side-channel note:</b> the OWF-key validity check (low two bits not
     * both set, matching upstream {@code faest_param.c:39-42}) is enforced by
     * a rejection-sampling loop. The loop's iteration count therefore depends
     * on bytes drawn from the supplied {@link java.security.SecureRandom} and
     * is observable via timing. The information leaked is about the
     * <em>discarded</em> DRBG draws, not the accepted OWF key, so the loop
     * does not expose secret key bits. Callers that need to suppress even
     * that signal can pass a deterministic / pre-conditioned random source.
     */
    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        if (!initialized)
        {
            throw new IllegalStateException("FAEST key pair generator not initialized");
        }

        int lambdaBytes = params.getLambdaBytes();
        int owfInputBytes = params.getOwfInputSize();
        int owfOutputBytes = params.getOwfOutputSize();

        byte[] owfKey = new byte[lambdaBytes];
        // Reject samples whose low two bits are both set — see class javadoc.
        while (true)
        {
            random.nextBytes(owfKey);
            if ((owfKey[0] & 0x03) != 0x03)
            {
                break;
            }
        }

        byte[] owfInput = new byte[owfInputBytes];
        random.nextBytes(owfInput);

        byte[] owfOutput = new byte[owfOutputBytes];
        Faest.owf(owfKey, owfInput, owfOutput, params);

        byte[] pk = new byte[params.getPkSize()];
        System.arraycopy(owfInput, 0, pk, 0, owfInputBytes);
        System.arraycopy(owfOutput, 0, pk, owfInputBytes, owfOutputBytes);

        byte[] sk = new byte[params.getSkSize()];
        System.arraycopy(owfInput, 0, sk, 0, owfInputBytes);
        System.arraycopy(owfKey, 0, sk, owfInputBytes, lambdaBytes);

        return new AsymmetricCipherKeyPair(
            new FaestPublicKeyParameters(params, pk),
            new FaestPrivateKeyParameters(params, sk));
    }
}
