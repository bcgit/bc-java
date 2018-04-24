package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;

/**
 * Container class for generating signatures that carries the signature type, parameters, public key certificate and public key's associated signer object.
 */
public class DefaultTlsCredentialedSigner
    implements TlsCredentialedSigner
{
    protected TlsCryptoParameters cryptoParams;
    protected Certificate certificate;
    protected SignatureAndHashAlgorithm signatureAndHashAlgorithm;

    protected TlsSigner signer;

    public DefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, TlsSigner signer, Certificate certificate,
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

        this.cryptoParams = cryptoParams;
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
        return signer.generateRawSignature(getEffectiveAlgorithm(), hash);
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return signatureAndHashAlgorithm;
    }

    public TlsStreamSigner getStreamSigner() throws IOException
    {
        return signer.getStreamSigner(getEffectiveAlgorithm());
    }

    protected SignatureAndHashAlgorithm getEffectiveAlgorithm()
    {
        SignatureAndHashAlgorithm algorithm = null;
        if (TlsImplUtils.isTLSv12(cryptoParams))
        {
            algorithm = getSignatureAndHashAlgorithm();
            if (algorithm == null)
            {
                throw new IllegalStateException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
            }
        }
        return algorithm;
    }
}
