package org.bouncycastle.tls.crypto.jcajce;

import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.crypto.TlsSigner;

public class JcaDefaultTlsSignerCredentials
    extends DefaultTlsSignerCredentials
{
    private static TlsSigner makeSigner(TlsContext context, PrivateKey privateKey)
    {
        TlsSigner signer;
        if (privateKey instanceof RSAPrivateKey)
        {
            signer = new JcaTlsRSASigner(context, (RSAPrivateKey)privateKey);
        }
        else if (privateKey instanceof DSAPrivateKey)
        {
            signer = new JcaTlsDSASigner(context, (DSAPrivateKey)privateKey);
        }
        else if (privateKey instanceof ECPrivateKey)
        {
            signer = new JcaTlsECDSASigner(context, (ECPrivateKey)privateKey);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public JcaDefaultTlsSignerCredentials(TlsContext context, PrivateKey privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(makeSigner(context, privateKey), certificate, signatureAndHashAlgorithm);
    }
}
