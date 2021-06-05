package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * Implementation class for verification of ECDSA signatures in TLS 1.3+ using the JCA.
 */
public class JcaTlsECDSA13Verifier
    implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;

    public JcaTlsECDSA13Verifier(JcaTlsCrypto crypto, PublicKey publicKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }
        if (!SignatureScheme.isECDSA(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.signatureScheme = signatureScheme;
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        return null;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        try
        {
            Signature signer = crypto.getHelper().createSignature("NoneWithECDSA");
            signer.initVerify(publicKey);
            signer.update(hash, 0, hash.length);
            return signer.verify(signature.getSignature());
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
