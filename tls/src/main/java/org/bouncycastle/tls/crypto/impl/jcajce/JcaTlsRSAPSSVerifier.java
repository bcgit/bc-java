package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * Operator supporting the verification of RSASSA-PSS signatures.
 */
public class JcaTlsRSAPSSVerifier
    implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final short signatureAlgorithm;

    public JcaTlsRSAPSSVerifier(JcaTlsCrypto crypto, PublicKey publicKey, short signatureAlgorithm)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }
        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null
            || algorithm.getSignature() != signatureAlgorithm
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        final byte[] sig = signature.getSignature();

        short hash = SignatureAlgorithm.getRSAPSSHashAlgorithm(signatureAlgorithm);
        String digestName = crypto.getDigestName(hash);
        String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";

        try
        {
            final Signature verifier = crypto.getHelper().createSignature(sigName);

            AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(hash, digestName, crypto.getHelper());

            // NOTE: We explicitly set them even though they should be the defaults, because providers vary
            verifier.setParameter(pssSpec);

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
            throw new TlsCryptoException(sigName + " verification failed", e);
        }
    }
}
