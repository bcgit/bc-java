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
        else if ("ML-DSA-44".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsMLDSASigner(crypto, privateKey, SignatureScheme.mldsa44);
        }
        else if ("ML-DSA-65".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsMLDSASigner(crypto, privateKey, SignatureScheme.mldsa65);
        }
        else if ("ML-DSA-87".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsMLDSASigner(crypto, privateKey, SignatureScheme.mldsa87);
        }
        else if ("SLH-DSA-SHA2-128S".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_sha2_128s);
        }
        else if ("SLH-DSA-SHA2-128F".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_sha2_128f);
        }
        else if ("SLH-DSA-SHA2-192S".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_sha2_192s);
        }
        else if ("SLH-DSA-SHA2-192F".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_sha2_192f);
        }
        else if ("SLH-DSA-SHA2-256S".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_sha2_256s);
        }
        else if ("SLH-DSA-SHA2-256F".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_sha2_256f);
        }
        else if ("SLH-DSA-SHAKE-128S".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_shake_128s);
        }
        else if ("SLH-DSA-SHAKE-128F".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_shake_128f);
        }
        else if ("SLH-DSA-SHAKE-192S".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_shake_192s);
        }
        else if ("SLH-DSA-SHAKE-192F".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_shake_192f);
        }
        else if ("SLH-DSA-SHAKE-256S".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_shake_256s);
        }
        else if ("SLH-DSA-SHAKE-256F".equalsIgnoreCase(algorithm))
        {
            signer = new JcaTlsSLHDSASigner(crypto, privateKey, SignatureScheme.DRAFT_slhdsa_shake_256f);
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
