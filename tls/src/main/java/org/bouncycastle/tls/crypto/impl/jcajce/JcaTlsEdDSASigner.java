package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

public abstract class JcaTlsEdDSASigner
    implements TlsSigner
{
    protected final JcaTlsCrypto crypto;
    protected final PrivateKey privateKey;
    protected final short algorithmType;
    protected final String algorithmName;

    public JcaTlsEdDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey, short algorithmType, String algorithmName)
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
        this.algorithmType = algorithmType;
        this.algorithmName = algorithmName;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        if (algorithm == null
            || algorithm.getSignature() != algorithmType
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        try
        {
            final Signature sig = crypto.getHelper().createSignature(algorithmName);

            sig.initSign(privateKey);

            final OutputStream stream = OutputStreamFactory.createStream(sig);

            return new TlsStreamSigner()
            {
                public OutputStream getOutputStream() throws IOException
                {
                    return stream;
                }

                public byte[] getSignature() throws IOException
                {
                    try
                    {
                        return sig.sign();
                    }
                    catch (SignatureException e)
                    {
                        throw new IOException(e.getMessage());
                    }
                }
            };
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException(algorithmName + " signature failed", e);
        }
    }
}
