package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
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

    private Signature rawVerifier = null;

    public JcaTlsRSAVerifier(RSAPublicKey pubKeyRSA, JcaJceHelper helper)
    {
        if (pubKeyRSA == null)
        {
            throw new IllegalArgumentException("'pubKeyRSA' cannot be null");
        }

        this.pubKeyRSA = pubKeyRSA;
        this.helper = helper;
    }

    public TlsStreamVerifier getStreamVerifier(final DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();

        /*
         * NOTE: The SunMSCAPI provider's "NoneWithRSA" can't produce/verify RSA signatures in the correct format for TLS 1.2
         */
        if (algorithm != null && algorithm.getSignature() == SignatureAlgorithm.rsa && JcaUtils.isSunMSCAPIProviderActive())
        {
            try
            {
                Signature rawVerifier = getRawVerifier();

                if (JcaUtils.isSunMSCAPIProvider(rawVerifier.getProvider()))
                {
                    String algorithmName = JcaUtils.getJcaAlgorithmName(algorithm);

                    final Signature verifier = helper.createSignature(algorithmName);
                    verifier.initVerify(pubKeyRSA);

                    return new TlsStreamVerifier()
                    {
                        public OutputStream getOutputStream()
                        {
                            return new SignatureOutputStream(verifier);
                        }

                        public boolean isVerified() throws IOException
                        {
                            try
                            {
                                return verifier.verify(signature.getSignature());
                            }
                            catch (SignatureException e)
                            {
                                throw new TlsFatalAlert(AlertDescription.internal_error, e);
                            }
                        }
                    };
                }
            }
            catch (GeneralSecurityException e)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
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
                    throw new IllegalStateException();
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
            throw new IllegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }

    protected Signature getRawVerifier() throws GeneralSecurityException
    {
        if (rawVerifier == null)
        {
            rawVerifier = helper.createSignature("NoneWithRSA");
            rawVerifier.initVerify(pubKeyRSA);
        }
        return rawVerifier;
    }
}
