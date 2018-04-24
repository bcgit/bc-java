package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;

/**
 * Interface supporting the generation of key material and other SSL/TLS secret values from PRFs.
 */
public interface TlsSecret
{
    /**
     * Return a new secret based on applying a PRF to this one.
     *
     * @param prfAlgorithm PRF algorithm to use.
     * @param label the label details.
     * @param seed the seed details.
     * @param length the size (in bytes) of the secret to generate.
     * @return the new secret.
     */
    TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length);

    /**
     * Create a cipher suite that matches the passed in encryption algorithm and mac algorithm.
     * <p>
     * See enumeration classes {@link EncryptionAlgorithm}, {@link MACAlgorithm} for appropriate argument values.
     * </p>
     * @param cryptoParams context specific parameters.
     * @param encryptionAlgorithm the encryption algorithm to be employed by the cipher suite.
     * @param macAlgorithm  the MAC algorithm to be employed by the cipher suite.
     * @return a TlsCipherSuite supporting the encryption and mac algorithm.
     * @throws IOException
     */
    TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) throws IOException;

    /**
     * Destroy the internal state of the secret. After this call, any attempt to use the
     * {@link TlsSecret} will result in an {@link IllegalStateException} being thrown.
     */
    void destroy();

    /**
     * Return the an encrypted copy of the data this secret is based on.
     *
     * @param certificate the certificate containing the public key to use for protecting the internal data.
     * @return an encrypted copy of secret's internal data.
     */
    byte[] encrypt(TlsCertificate certificate) throws IOException;

    /**
     * Return the internal data from this secret. The {@link TlsSecret} does not keep a copy of the
     * data. After this call, any attempt to use the {@link TlsSecret} will result in an
     * {@link IllegalStateException} being thrown.
     *
     * @return the secret's internal data.
     */
    byte[] extract();
}
