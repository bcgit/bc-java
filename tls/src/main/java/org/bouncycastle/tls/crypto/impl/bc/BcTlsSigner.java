package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

public abstract class BcTlsSigner
    implements TlsSigner
{
    protected final BcTlsCrypto crypto;
    protected final AsymmetricKeyParameter privateKey;

    protected BcTlsSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)
    {
        if (crypto == null)
        {
            throw new NullPointerException("'crypto' cannot be null");
        }
        if (privateKey == null)
        {
            throw new NullPointerException("'privateKey' cannot be null");
        }
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        return null;
    }
}
