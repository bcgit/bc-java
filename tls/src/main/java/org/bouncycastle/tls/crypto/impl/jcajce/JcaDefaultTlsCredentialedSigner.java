package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

/**
 * Credentialed class for generating signatures based on the use of primitives from the JCA.
 */
public class JcaDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
    private static JcaTlsCertificate getEndEntity(JcaTlsCrypto crypto, Certificate certificate) throws IOException
    {
        if (certificate == null || certificate.isEmpty())
        {
            throw new IllegalArgumentException("No certificate");
        }

        return JcaTlsCertificate.convert(crypto, certificate.getCertificateAt(0));
    }

    private static TlsSigner makeSigner(JcaTlsCrypto crypto, PrivateKey privateKey, Certificate certificate,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        String algorithm = privateKey.getAlgorithm();

        TlsSigner signer;

        // TODO We probably want better distinction b/w the rsa_pss_pss and rsa_pss_rsae cases here
        if (privateKey instanceof RSAPrivateKey
            || "RSA".equalsIgnoreCase(algorithm)
            || "RSASSA-PSS".equalsIgnoreCase(algorithm))
        {
            if (signatureAndHashAlgorithm != null)
            {
                short signatureAlgorithm = signatureAndHashAlgorithm.getSignature();
                switch (signatureAlgorithm)
                {
                case SignatureAlgorithm.rsa_pss_pss_sha256:
                case SignatureAlgorithm.rsa_pss_pss_sha384:
                case SignatureAlgorithm.rsa_pss_pss_sha512:
                case SignatureAlgorithm.rsa_pss_rsae_sha256:
                case SignatureAlgorithm.rsa_pss_rsae_sha384:
                case SignatureAlgorithm.rsa_pss_rsae_sha512:
                    return new JcaTlsRSAPSSSigner(crypto, privateKey, signatureAlgorithm);
                }
            }

            PublicKey publicKey;
            try
            {
                publicKey = getEndEntity(crypto, certificate).getPubKeyRSA();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }

            signer = new JcaTlsRSASigner(crypto, privateKey, publicKey);
        }
        else if (privateKey instanceof DSAPrivateKey
            || "DSA".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsDSASigner(crypto, privateKey);
        }
        else if (ECUtil.isECPrivateKey(privateKey))
        {
            signer = new JcaTlsECDSASigner(crypto, privateKey);
        }
        else if ("Ed25519".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsEd25519Signer(crypto, privateKey);
        }
        else if ("Ed448".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsEd448Signer(crypto, privateKey);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public JcaDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, JcaTlsCrypto crypto, PrivateKey privateKey,
        Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate,
            signatureAndHashAlgorithm);
    }
}
