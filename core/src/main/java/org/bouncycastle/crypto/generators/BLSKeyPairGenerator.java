package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.params.BLSKeyGenerationParameters;
import org.bouncycastle.crypto.params.BLSParameters;
import org.bouncycastle.crypto.params.BLSPrivateKeyParameters;
import org.bouncycastle.crypto.params.BLSPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * Generates a BLS signature scheme keypair. The secret key is derived from
 * {@link SecureRandom} input keying material via the
 * draft-irtf-cfrg-bls-signature sec. 2.3 {@code KeyGen} procedure
 * (HKDF-SHA256 with the spec's salt rotation), so a given random source
 * produces a uniform secret in {@code [1, r - 1]}.
 */
public class BLSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private BLSParameters parameters;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        if (!(param instanceof BLSKeyGenerationParameters))
        {
            throw new IllegalArgumentException("param must be a BLSKeyGenerationParameters");
        }
        this.parameters = ((BLSKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        if (parameters == null)
        {
            throw new IllegalStateException("generator not initialised");
        }
        if (parameters != BLSParameters.bls12_381)
        {
            throw new IllegalStateException("unsupported BLS family: " + parameters.getName());
        }

        // Draw 32 bytes of IKM from the SecureRandom (the spec's minimum).
        // Feeding this through KeyGen / HKDF gives a uniform secret in
        // [1, r - 1].
        //
        // The try/finally wipe of ikm is load-bearing: KeyGen is a pure
        // deterministic function of (IKM, salt, key_info), and salt /
        // key_info are fixed public constants for this generator. So
        // anyone who reads ikm from a heap dump can derive the same sk by
        // re-running keyGen offline — i.e. ikm is effectively a second
        // copy of the secret-key bytes. Without the wipe, the bytes
        // survive until the next GC collects the local stack frame and
        // the array body; with the wipe the residence window is the body
        // of the try-block. (The constant-time scalar-mult work at
        // sign-time would be pointless if a heap inspector could just
        // read the seed material from a separate file.)
        byte[] ikm = new byte[32];
        try
        {
            random.nextBytes(ikm);
            BigInteger sk = BLS12_381BasicScheme.keyGen(ikm, new byte[0]);

            ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
            return new AsymmetricCipherKeyPair(
                new BLSPublicKeyParameters(parameters, pk),
                new BLSPrivateKeyParameters(parameters, sk));
        }
        finally
        {
            Arrays.fill(ikm, (byte)0);
        }
    }
}
