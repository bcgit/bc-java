package org.bouncycastle.crypto.kems;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.KeyEncapsulation;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * The RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2.
 * @deprecated use RSAKEMGenerator, RSAKEMExtractor
 */
public class RSAKeyEncapsulation
    implements KeyEncapsulation
{
    private DerivationFunction kdf;
    private SecureRandom rnd;
    private RSAKeyParameters key;

    /**
     * Set up the RSA-KEM.
     *
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public RSAKeyEncapsulation(
        DerivationFunction kdf,
        SecureRandom rnd)
    {
        this.kdf = kdf;
        this.rnd = rnd;
    }

    /**
     * Initialise the RSA-KEM.
     *
     * @param key the recipient's public (for encryption) or private (for decryption) key.
     */
    public void init(CipherParameters key)
        throws IllegalArgumentException
    {
        if (!(key instanceof RSAKeyParameters))
        {
            throw new IllegalArgumentException("RSA key required");
        }

        this.key = (RSAKeyParameters)key;
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSAKem",
            ConstraintUtils.bitsOfSecurityFor(this.key.getModulus()), key, this.key.isPrivate() ? CryptoServicePurpose.DECRYPTION : CryptoServicePurpose.ENCRYPTION));
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param outOff the offset for the output buffer.
     * @param keyLen the length of the random session key.
     * @return the random session key.
     */
    public CipherParameters encrypt(byte[] out, int outOff, int keyLen)
        throws IllegalArgumentException
    {
        if (key.isPrivate())
        {
            throw new IllegalArgumentException("Public key required for encryption");
        }

        RSAKEMGenerator kemGen = new RSAKEMGenerator(keyLen, kdf, rnd);

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(key);

        byte[] encLen = secEnc.getEncapsulation();
        System.arraycopy(encLen, 0, out, outOff, encLen.length);

        return new KeyParameter(secEnc.getSecret());
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param keyLen the length of the random session key.
     * @return the random session key.
     */
    public CipherParameters encrypt(byte[] out, int keyLen)
    {
        return encrypt(out, 0, keyLen);
    }

    /**
     * Decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param inOff  the offset for the input buffer.
     * @param inLen  the length of the encapsulated key.
     * @param keyLen the length of the session key.
     * @return the session key.
     */
    public CipherParameters decrypt(byte[] in, int inOff, int inLen, int keyLen)
        throws IllegalArgumentException
    {
        if (!key.isPrivate())
        {
            throw new IllegalArgumentException("Private key required for decryption");
        }

        RSAKEMExtractor kemGen = new RSAKEMExtractor(key, keyLen, kdf);

        byte[] secEnc = kemGen.extractSecret(Arrays.copyOfRange(in, inOff, inOff + inLen));

        return new KeyParameter(secEnc);
    }

    /**
     * Decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param keyLen the length of the session key.
     * @return the session key.
     */
    public CipherParameters decrypt(byte[] in, int keyLen)
    {
        return decrypt(in, 0, in.length, keyLen);
    }
}
