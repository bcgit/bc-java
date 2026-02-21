package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Strings;

/**
 * JCA-based SM2 signer for TLS 1.3 (RFC 8998).
 */
public class JcaTlsSM2Signer
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final byte[] identifier;

    public JcaTlsSM2Signer(JcaTlsCrypto crypto, PrivateKey privateKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }
        if (signatureScheme != SignatureScheme.sm2sig_sm3)
        {
            throw new IllegalArgumentException("signatureScheme must be sm2sig_sm3");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.identifier = Strings.toByteArray("TLSv1.3+GM+Cipher+Suite");
    }

    @Override
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.sm2sig_sm3)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        try
        {
            Signature signer = crypto.getHelper().createSignature("SM3withSM2");
            AlgorithmParameterSpec paramSpec = new SM2ParameterSpec(identifier);
            signer.setParameter(paramSpec);
            signer.initSign((java.security.PrivateKey)privateKey, crypto.getSecureRandom());
            signer.update(hash, 0, hash.length);
            return signer.sign();
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    @Override
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        throw new UnsupportedOperationException();
    }
}