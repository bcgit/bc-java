package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * Operator supporting the verification of RSA signatures.
 */
public class JcaTlsRSAVerifier
    implements TlsVerifier
{
    private final JcaJceHelper helper;
    protected RSAPublicKey pubKeyRSA;

    public JcaTlsRSAVerifier(RSAPublicKey pubKeyRSA, JcaJceHelper helper)
    {
        if (pubKeyRSA == null)
        {
            throw new IllegalArgumentException("'pubKeyRSA' cannot be null");
        }

        this.pubKeyRSA = pubKeyRSA;
        this.helper = helper;
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        return null;
    }

    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();

        try
        {
            Signature signer = helper.createSignature("NoneWithRSA");
            signer.initVerify(pubKeyRSA);
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
                AlgorithmIdentifier algID = new AlgorithmIdentifier(TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()), DERNull.INSTANCE);
                byte[] digestInfo = new DigestInfo(algID, hash).getEncoded();
                signer.update(digestInfo, 0, digestInfo.length);
            }
            else
            {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
                signer.update(hash, 0, hash.length);
            }

            return signer.verify(signedParams.getSignature());
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
