package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/**
 * Operator supporting the generation of RSASSA-PSS signatures.
 */
public class JcaTlsRSAPSSSigner
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final short signatureAlgorithm;

    public JcaTlsRSAPSSSigner(JcaTlsCrypto crypto, PrivateKey privateKey, short signatureAlgorithm)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }
        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        if (algorithm == null
            || algorithm.getSignature() != signatureAlgorithm
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        short hash = SignatureAlgorithm.getRSAPSSHashAlgorithm(signatureAlgorithm);
        String digestName = crypto.getDigestName(hash);

        String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";

        try
        {
            AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(hash, digestName, crypto.getHelper());

            final Signature sig = crypto.getHelper().createSignature(sigName);

            // NOTE: We explicitly set them even though they should be the defaults, because providers vary
            sig.setParameter(pssSpec);

            sig.initSign(privateKey, crypto.getSecureRandom());

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
            throw new TlsCryptoException(sigName + " signature failed", e);
        }
    }
}
