package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.AbstractTlsSigner;

public class JcaTlsDSSSigner
    extends AbstractTlsSigner
{
    private final PrivateKey privateKey;
    private final short algorithmType;
    private final String algorithmName;

    public JcaTlsDSSSigner(TlsContext context, PrivateKey privateKey, short algorithmType, String algorithmName)
    {
        super(context);
        this.privateKey = privateKey;
        this.algorithmType = algorithmType;
        this.algorithmName = algorithmName;
    }

    @Override
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        throws IOException
    {
        if (algorithm != null && algorithm.getSignature() != algorithmType)
        {
            throw new IllegalStateException();
        }

        try
        {
            Signature signer = ((JcaTlsCrypto)context.getCrypto()).getHelper().createSignature(algorithmName);

            signer.initSign(privateKey);
            if (algorithm == null)
            {
                // Note: Only use the SHA1 part of the (MD5/SHA1) hash
                signer.update(hash, 16, 20);
            }
            else
            {
                signer.update(hash, 0, hash.length);
            }
            return signer.sign();
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
