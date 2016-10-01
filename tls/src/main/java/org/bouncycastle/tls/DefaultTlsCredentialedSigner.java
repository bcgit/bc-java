package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsSigner;

public class DefaultTlsCredentialedSigner
    implements TlsCredentialedSigner
{
    protected TlsContext context;
    protected Certificate certificate;
    protected SignatureAndHashAlgorithm signatureAndHashAlgorithm;

    protected TlsSigner signer;

    public DefaultTlsCredentialedSigner(TlsSigner signer, Certificate certificate,
                                        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (signer == null)
        {
            throw new IllegalArgumentException("'signer' cannot be null");
        }

        this.signer = signer;

        this.context = signer.getContext();
        this.certificate = certificate;
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public byte[] generateRawSignature(byte[] hash)
        throws IOException
    {
        SignatureAndHashAlgorithm algorithm = null;
        if (TlsUtils.isTLSv12(context))
        {
            algorithm = getSignatureAndHashAlgorithm();
            if (algorithm == null)
            {
                throw new IllegalStateException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
            }
        }

        return signer.generateRawSignature(algorithm, hash);
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return signatureAndHashAlgorithm;
    }
}
