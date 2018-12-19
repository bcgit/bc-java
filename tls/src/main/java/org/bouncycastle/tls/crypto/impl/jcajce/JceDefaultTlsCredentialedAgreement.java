package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.interfaces.DHPrivateKey;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Credentialed class generating agreed secrets from a peer's public key for our end of the TLS connection using the JCE.
 */
public class JceDefaultTlsCredentialedAgreement
    implements TlsCredentialedAgreement
{
    public static String getAgreementAlgorithm(PrivateKey privateKey)
    {
        if (privateKey instanceof DHPrivateKey)
        {
            return "DH";
        }
        if (ECUtil.isECPrivateKey(privateKey))
        {
            return "ECDH";
        }

        throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
    }

    private final JcaTlsCrypto crypto;
    private final Certificate certificate;
    private final PrivateKey privateKey;
    private final String agreementAlgorithm;

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
        this.agreementAlgorithm = getAgreementAlgorithm(privateKey);
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
            /*
             * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
             * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length
             * for any given field; leading zeros found in this octet string MUST NOT be truncated.
             *
             * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it
             * is used as the pre_master_secret.
             * 
             * We use the convention established by the JSSE to signal these requirements by asking
             * for "TlsPremasterSecret".
             */
            PublicKey publicKey = JcaTlsCertificate.convert(crypto, peerCertificate).getPublicKey();

            byte[] secret = crypto.calculateKeyAgreement(agreementAlgorithm, privateKey, publicKey, "TlsPremasterSecret");

            return crypto.adoptLocalSecret(secret);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("unable to perform agreement", e);
        }
    }
}
