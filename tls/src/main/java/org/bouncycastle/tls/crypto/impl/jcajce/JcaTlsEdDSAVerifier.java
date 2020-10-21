package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
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
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        return crypto.createStreamVerifier(algorithmName, null, signature.getSignature(), publicKey);
    }
}
