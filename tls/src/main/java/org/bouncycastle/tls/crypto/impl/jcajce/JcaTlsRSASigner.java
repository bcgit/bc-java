package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSigner;

public class JcaTlsRSASigner
    extends AbstractTlsSigner
{
    private final PrivateKey privateKey;

    public JcaTlsRSASigner(TlsContext context, PrivateKey privateKey)
    {
        super(context);

        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }

        this.privateKey = privateKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm,
                                       byte[] hash) throws IOException
    {
        try
        {
            Signature signer = ((JcaTlsCrypto)context.getCrypto()).getHelper().createSignature("NoneWithRSA");
            signer.initSign(privateKey, context.getCrypto().getSecureRandom());
            if (algorithm != null)
            {
                if (algorithm.getSignature() != SignatureAlgorithm.rsa)
                {
                    throw new IllegalStateException();
                }

            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
                try
                {
                    byte[] digInfo = new DigestInfo(new AlgorithmIdentifier(TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()), DERNull.INSTANCE), hash).getEncoded();
                    signer.update(digInfo, 0, digInfo.length);
                }
                catch (IOException e)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
                }
            }
            else
            {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
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
