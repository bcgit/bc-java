package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSignerCredentials;
import org.bouncycastle.tls.TlsUtils;

public class DefaultTlsSignerCredentials
    implements TlsSignerCredentials
{
    protected BcTlsCrypto crypto;
    protected Certificate certificate;
    protected AsymmetricKeyParameter privateKey;
    protected SignatureAndHashAlgorithm signatureAndHashAlgorithm;

    protected TlsSigner signer;

    public DefaultTlsSignerCredentials(BcTlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
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
            this.signer = new BcTlsDSSSigner();
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            this.signer = new BcTlsECDSASigner();
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        this.signer.init(crypto.getContext());

        this.crypto = crypto;
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public byte[] generateRawSignature(byte[] hash)
        throws IOException
    {
        try
        {
            SignatureAndHashAlgorithm algorithm = null;
            if (TlsUtils.isTLSv12(crypto.getContext()))
            {
                algorithm = getSignatureAndHashAlgorithm();
                if (algorithm == null)
                {
                    throw new IllegalStateException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
                }
            }

            return signer.generateRawSignature(algorithm, privateKey, hash);
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return signatureAndHashAlgorithm;
    }
}
