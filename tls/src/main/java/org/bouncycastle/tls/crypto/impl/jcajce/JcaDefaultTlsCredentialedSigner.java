package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

/**
 * Credentialed class for generating signatures based on the use of primitives from the JCA.
 */
public class JcaDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
    private static TlsSigner makeSigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        String algorithm = privateKey.getAlgorithm();

        TlsSigner signer;
        if (privateKey instanceof RSAPrivateKey || "RSA".equals(algorithm))
        {
            signer = new JcaTlsRSASigner(crypto, privateKey);
        }
        else if (privateKey instanceof DSAPrivateKey || "DSA".equals(algorithm))
        {
            signer = new JcaTlsDSASigner(crypto, privateKey);
        }
        else if (privateKey instanceof ECPrivateKey || "EC".equals(algorithm))
        {
            signer = new JcaTlsECDSASigner(crypto, privateKey);
        }
        else if ("Ed25519".equals(algorithm))
        {
            // TODO[RFC 8422] Extract public key from certificate?
            signer = new JcaTlsEd25519Signer(crypto, privateKey);
        }
        else if ("Ed448".equals(algorithm))
        {
            // TODO[RFC 8422] Extract public key from certificate?
            signer = new JcaTlsEd448Signer(crypto, privateKey);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public JcaDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, JcaTlsCrypto crypto, PrivateKey privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(cryptoParams, makeSigner(crypto, privateKey), certificate, signatureAndHashAlgorithm);
    }
}
