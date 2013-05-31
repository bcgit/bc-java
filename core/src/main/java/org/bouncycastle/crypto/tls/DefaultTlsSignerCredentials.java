package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class DefaultTlsSignerCredentials
    implements TlsSignerCredentials
{
    protected TlsContext context;
    protected Certificate certificate;
    protected AsymmetricKeyParameter privateKey;

    protected TlsSigner signer;

    public DefaultTlsSignerCredentials(TlsContext context, Certificate certificate, AsymmetricKeyParameter privateKey)
    {

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
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        if (privateKey instanceof RSAKeyParameters)
        {
            this.signer = new TlsRSASigner();
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            this.signer = new TlsDSSSigner();
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            this.signer = new TlsECDSASigner();
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        this.signer.init(context);

        this.context = context;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public byte[] generateCertificateSignature(byte[] md5andsha1)
        throws IOException
    {
        try
        {
            return signer.generateRawSignature(privateKey, md5andsha1);
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
