package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
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
    protected final ASN1ObjectIdentifier algorithmOID;

    public JcaTlsEdDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey, short algorithmType, ASN1ObjectIdentifier algorithmOID)
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
        this.algorithmOID = algorithmOID;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm != null)
        {
            if (algorithm.getSignature() != algorithmType
                || algorithm.getHash() != HashAlgorithm.Intrinsic)
            {
                throw new IllegalStateException();
            }
        }

        final byte[] sig = signature.getSignature();

        try
        {
            // TODO[RFC 8422] crypto.getHelper();
            ContentVerifierProvider cvp = new JcaContentVerifierProviderBuilder().build(publicKey);

            final ContentVerifier cv = cvp.get(new AlgorithmIdentifier(algorithmOID));

            return new TlsStreamVerifier()
            {
                public OutputStream getOutputStream() throws IOException
                {
                    return cv.getOutputStream();
                }

                public boolean isVerified() throws IOException
                {
                    return cv.verify(sig);
                }
            };
        }
        catch (OperatorCreationException e)
        {
            throw new TlsCryptoException(algorithmOID.getId() + " verification failed", e);
        }
    }
}
