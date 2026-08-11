package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * The RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2.
 * <p>
 * Decapsulation raises the caller-supplied encapsulation to the private exponent through
 * {@link RSABlindedEngine}, so the operation is blinded where the key permits it - a
 * decapsulation oracle is attacker-driven, and an unblinded exponentiation exposes the
 * private exponent to a remote timing attack. Blinding requires CRT key material carrying
 * a public exponent (an {@link org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters});
 * for a key holding only the private exponent the exponentiation is unblinded, as elsewhere
 * in the provider.
 */
public class RSAKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final RSAKeyParameters privKey;
    private final int keyLen;
    private final SecureRandom random;
    private DerivationFunction kdf;

    /**
     * Equivalent to {@link #RSAKEMExtractor(RSAKeyParameters, int, DerivationFunction, SecureRandom)}
     * with a {@link SecureRandom} obtained from {@link CryptoServicesRegistrar}.
     *
     * @param privKey the decryption key.
     * @param keyLen length in bytes of key to generate.
     * @param kdf the key derivation function to be used.
     */
    public RSAKEMExtractor(
        RSAKeyParameters privKey,
        int keyLen,
        DerivationFunction kdf)
    {
        this(privKey, keyLen, kdf, CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Set up the RSA-KEM.
     *
     * @param privKey the decryption key.
     * @param keyLen length in bytes of key to generate.
     * @param kdf the key derivation function to be used.
     * @param random source of randomness for the decapsulation blinding factor; must not be
     *               {@code null} - use {@link #RSAKEMExtractor(RSAKeyParameters, int, DerivationFunction)}
     *               for the {@link CryptoServicesRegistrar} default.
     */
    public RSAKEMExtractor(
        RSAKeyParameters privKey,
        int keyLen,
        DerivationFunction kdf,
        SecureRandom random)
    {
        if (privKey == null)
        {
            throw new NullPointerException("'privKey' cannot be null");
        }
        if (!privKey.isPrivate())
        {
            throw new IllegalArgumentException("private key required for encryption");
        }
        if (random == null)
        {
            throw new NullPointerException("'random' cannot be null");
        }

        this.privKey = privKey;
        this.keyLen = keyLen;
        this.kdf = kdf;
        this.random = random;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSAKem",
                    ConstraintUtils.bitsOfSecurityFor(this.privKey.getModulus()), privKey, CryptoServicePurpose.DECRYPTION));
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        BigInteger n = privKey.getModulus();

        RSABlindedEngine engine = new RSABlindedEngine();

        engine.init(false, new ParametersWithRandom(privKey, random));

        // Decrypt the ephemeral random and encode it
        byte[] rEnc = engine.processBlock(encapsulation, 0, encapsulation.length);

        BigInteger r = new BigInteger(1, rEnc);

        Arrays.fill(rEnc, (byte)0);

        return RSAKEMGenerator.generateKey(kdf, n, r, keyLen);
    }

    public int getEncapsulationLength()
    {
        return (privKey.getModulus().bitLength() + 7) / 8;
    }
}
