package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * JCA base class for the verifiers implementing the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class JcaTlsDSSVerifier
    implements TlsVerifier
{
    protected final JcaTlsCrypto crypto;
    protected final PublicKey publicKey;
    protected final short algorithmType;
    protected final String algorithmName;

    protected JcaTlsDSSVerifier(JcaTlsCrypto crypto, PublicKey publicKey, short algorithmType, String algorithmName)
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

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        return null;
    }

    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        if (algorithm != null && algorithm.getSignature() != algorithmType)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        try
        {
            Signature signer = crypto.getHelper().createSignature(algorithmName);

            signer.initVerify(publicKey);
            if (algorithm == null)
            {
                // Note: Only use the SHA1 part of the (MD5/SHA1) hash
                signer.update(hash, 16, 20);
            }
            else
            {
                signer.update(hash, 0, hash.length);
            }
            return signer.verify(signedParams.getSignature());
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
