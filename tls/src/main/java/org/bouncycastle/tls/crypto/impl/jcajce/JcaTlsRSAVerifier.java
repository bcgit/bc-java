package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * Operator supporting the verification of RSASSA-PKCS1-v1_5 signatures.
 */
public class JcaTlsRSAVerifier
    implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;

    private Signature rawVerifier = null;

    public JcaTlsRSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey)
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
    }

    public TlsStreamVerifier getStreamVerifier(final DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();

        /*
         * NOTE: The SunMSCAPI provider's "NoneWithRSA" can't produce/verify RSA signatures in the correct format for TLS 1.2
         */
        if (algorithm != null
            && algorithm.getSignature() == SignatureAlgorithm.rsa
            && JcaUtils.isSunMSCAPIProviderActive()
            && isSunMSCAPIRawVerifier())
        {
            return crypto.createStreamVerifier(signature, publicKey);
        }

        return null;
    }

    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();

        try
        {
            Signature verifier = getRawVerifier();

            if (algorithm != null)
            {
                if (algorithm.getSignature() != SignatureAlgorithm.rsa)
                {
                    throw new IllegalStateException("Invalid algorithm: " + algorithm);
                }

                /*
                 * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
                 * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
                 */
                AlgorithmIdentifier algID = new AlgorithmIdentifier(
                    TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()), DERNull.INSTANCE);
                byte[] digestInfo = new DigestInfo(algID, hash).getEncoded();
                verifier.update(digestInfo, 0, digestInfo.length);
            }
            else
            {
                /*
                 * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature
                 * scheme that did not include a DigestInfo encoding.
                 */
                verifier.update(hash, 0, hash.length);
            }

            return verifier.verify(signedParams.getSignature());
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }

    protected Signature getRawVerifier() throws GeneralSecurityException
    {
        if (rawVerifier == null)
        {
            rawVerifier = crypto.getHelper().createSignature("NoneWithRSA");
            rawVerifier.initVerify(publicKey);
        }
        return rawVerifier;
    }

    protected boolean isSunMSCAPIRawVerifier() throws IOException
    {
        try
        {
            Signature rawVerifier = getRawVerifier();

            return JcaUtils.isSunMSCAPIProvider(rawVerifier.getProvider());
        }
        catch (GeneralSecurityException e)
        {
            // Assume the worst!
            return true;
        }
    }
}
