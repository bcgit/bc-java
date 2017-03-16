package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Credentialed class generating agreed secrets from a peer's public key for our end of the TLS connection using the JCE.
 */
public class JceDefaultTlsCredentialedAgreement
    implements TlsCredentialedAgreement
{
    private final JcaTlsCrypto crypto;
    private final String algorithm;
    private final Certificate certificate;
    private final PrivateKey privateKey;

    public JceDefaultTlsCredentialedAgreement(JcaTlsCrypto crypto, Certificate certificate, PrivateKey privateKey)
    {
        if (crypto == null)
        {
            throw new IllegalArgumentException("'crypto' cannot be null");
        }
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }

        this.crypto = crypto;
        this.certificate = certificate;
        this.privateKey = privateKey;

        if (privateKey instanceof DHPrivateKey)
        {
            algorithm = "DH";
        }
        else if (privateKey instanceof ECPrivateKey)
        {
            algorithm = "ECDH";
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: "
                + privateKey.getClass().getName());
        }
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public TlsSecret generateAgreement(TlsCertificate peerCertificate)
        throws IOException
    {
        try
        {
            KeyAgreement agreement = crypto.getHelper().createKeyAgreement(algorithm);

            agreement.init(privateKey);

            agreement.doPhase(JcaTlsCertificate.convert(peerCertificate, crypto.getHelper()).getPublicKey(), true);

        /*
         * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it is
         * used as the pre_master_secret. We use the convention established by the JSSE to signal this
         * by asking for "TlsPremasterSecret".
         */
            return new JceTlsSecret(crypto, agreement.generateSecret("TlsPremasterSecret").getEncoded());
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("unable to perform agreement: " + e.getMessage(), e);
        }
    }
}
