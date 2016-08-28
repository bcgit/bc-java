package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.crypto.TlsSigner;

public class BcDefaultTlsSignerCredentials
    extends DefaultTlsSignerCredentials
{
    private static TlsSigner makeSigner(TlsContext context, AsymmetricKeyParameter privateKey)
    {
        TlsSigner signer;
        if (privateKey instanceof RSAKeyParameters)
        {
            signer = new TlsRSASigner(context, privateKey);
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            signer = new BcTlsDSASigner(context, privateKey);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            signer = new BcTlsECDSASigner(context, privateKey);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public BcDefaultTlsSignerCredentials(TlsContext context, AsymmetricKeyParameter privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(makeSigner(context, privateKey), certificate, signatureAndHashAlgorithm);
    }
}
