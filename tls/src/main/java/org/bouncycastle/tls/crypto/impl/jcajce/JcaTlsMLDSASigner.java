package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

public class JcaTlsMLDSASigner
    implements TlsSigner
{
    protected final JcaTlsCrypto crypto;
    protected final PrivateKey privateKey;

    public JcaTlsMLDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        if (algorithm == null)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        return crypto.createStreamSigner("ML-DSA", null, privateKey, false);
    }
}
