package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipherSuite;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Base class for a TlsCrypto implementation that provides some needed methods from elsewhere in the impl package.
 */
public abstract class AbstractTlsCrypto
    implements TlsCrypto
{
    /**
     * Adopt the passed in secret, creating a new copy of it..
     *
     * @param secret the secret to make a copy of.
     * @return a TlsSecret based the original secret.
     */
    public TlsSecret adoptSecret(TlsSecret secret)
    {
        if (secret instanceof AbstractTlsSecret)
        {
            AbstractTlsSecret sec = (AbstractTlsSecret)secret;

            return createSecret(sec.copyData());
        }

        throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.getClass().getName());
    }

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
    protected abstract TlsCipherSuite createCipherSuite(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
            throws IOException;


    /**
     * Return an encryptor based on the public key in certificate.
     *
     * @param certificate the certificate carrying the public key.
     * @return a TlsEncryptor based on the certificate's public key.
     */
    protected abstract TlsEncryptor createEncryptor(TlsCertificate certificate)
        throws IOException;
}
