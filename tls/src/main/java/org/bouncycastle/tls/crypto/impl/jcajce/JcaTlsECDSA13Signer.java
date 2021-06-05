package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/**
 * Implementation class for generation of ECDSA signatures in TLS 1.3+ using the JCA.
 */
public class JcaTlsECDSA13Signer
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final int signatureScheme;

    public JcaTlsECDSA13Signer(JcaTlsCrypto crypto, PrivateKey privateKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }
        if (!SignatureScheme.isECDSA(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.signatureScheme = signatureScheme;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        try
        {
            Signature signer = crypto.getHelper().createSignature("NoneWithECDSA");
            signer.initSign(privateKey, crypto.getSecureRandom());
            signer.update(hash, 0, hash.length);
            return signer.sign();
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
        throws IOException
    {
        return null;
    }
}
