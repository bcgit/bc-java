package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

/**
 * Credentialed class for generating signatures based on the use of primitives from the JCA.
 */
public class JcaDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
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
                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isRSAPSS(signatureScheme))
                {
                    return new JcaTlsRSAPSSSigner(crypto, privateKey, signatureScheme);
                }
            }

            signer = new JcaTlsRSASigner(crypto, privateKey);
        }
        else if (privateKey instanceof DSAPrivateKey
            || "DSA".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsDSASigner(crypto, privateKey);
        }
        else if (ECUtil.isECPrivateKey(privateKey))
        {
            if (signatureAndHashAlgorithm != null)
            {
                int signatureScheme = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isECDSA(signatureScheme))
                {
                    return new JcaTlsECDSA13Signer(crypto, privateKey, signatureScheme);
                }
            }

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
