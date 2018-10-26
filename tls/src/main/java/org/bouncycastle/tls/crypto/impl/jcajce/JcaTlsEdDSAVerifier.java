package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

public class JcaTlsEdDSAVerifier
    implements TlsVerifier
{
    protected final JcaTlsCrypto crypto;
    protected final PublicKey publicKey;
    protected final short algorithmType;
    protected final String algorithmName;

    public JcaTlsEdDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey, short algorithmType, String algorithmName)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.algorithmType = algorithmType;
        this.algorithmName = algorithmName;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null
            || algorithm.getSignature() != algorithmType
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        final byte[] sig = signature.getSignature();

        try
        {
            final Signature verifier = crypto.getHelper().createSignature(algorithmName);

            verifier.initVerify(publicKey);

            final OutputStream stream = OutputStreamFactory.createStream(verifier);

            return new TlsStreamVerifier()
            {
                public OutputStream getOutputStream() throws IOException
                {
                    return stream;
                }

                public boolean isVerified() throws IOException
                {
                    try
                    {
                        return verifier.verify(sig);
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
            throw new TlsCryptoException(algorithmName + " verification failed", e);
        }
    }
}
