package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/**
 * Operator supporting the generation of RSA signatures.
 */
public class JcaTlsRSASigner
    implements TlsSigner
{
    private final PrivateKey privateKey;
    private final JcaTlsCrypto crypto;

    private Signature rawSigner = null;

    public JcaTlsRSASigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        this.crypto = crypto;

        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }

        this.privateKey = privateKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        try
        {
            Signature signer = getRawSigner();

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
                signer.update(digestInfo, 0, digestInfo.length);
            }
            else
            {
                /*
                 * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature
                 * scheme that did not include a DigestInfo encoding.
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

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        /*
         * NOTE: The SunMSCAPI provider's "NoneWithRSA" can't produce/verify RSA signatures in the correct format for TLS 1.2
         */
        if (algorithm != null && algorithm.getSignature() == SignatureAlgorithm.rsa && JcaUtils.isSunMSCAPIProviderActive())
        {
            try
            {
                Signature rawSigner = getRawSigner();

                if (JcaUtils.isSunMSCAPIProvider(rawSigner.getProvider()))
                {
                    String algorithmName = JcaUtils.getJcaAlgorithmName(algorithm);

                    final Signature signer = crypto.getHelper().createSignature(algorithmName);
                    signer.initSign(privateKey, crypto.getSecureRandom());

                    return new TlsStreamSigner()
                    {
                        public OutputStream getOutputStream()
                        {
                            return new SignatureOutputStream(signer);
                        }

                        public byte[] getSignature() throws IOException
                        {
                            try
                            {
                                return signer.sign();
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

    protected Signature getRawSigner() throws GeneralSecurityException
    {
        if (rawSigner == null)
        {
            rawSigner = crypto.getHelper().createSignature("NoneWithRSA");
            rawSigner.initSign(privateKey, crypto.getSecureRandom());
        }
        return rawSigner;
    }
}
