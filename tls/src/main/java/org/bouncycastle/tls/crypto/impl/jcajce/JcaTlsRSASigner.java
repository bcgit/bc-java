package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

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
 * Operator supporting the generation of RSASSA-PKCS1-v1_5 signatures.
 */
public class JcaTlsRSASigner
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private Signature rawSigner = null;

    public JcaTlsRSASigner(JcaTlsCrypto crypto, PrivateKey privateKey, PublicKey publicKey)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        try
        {
            Signature signer = getRawSigner();

            byte[] input;
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
                input = new DigestInfo(algID, hash).getEncoded();
            }
            else
            {
                /*
                 * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature
                 * scheme that did not include a DigestInfo encoding.
                 */
                input = hash;
            }

            signer.update(input, 0, input.length);

            byte[] signature = signer.sign();

            signer.initVerify(publicKey);
            signer.update(input, 0, input.length);

            if (signer.verify(signature))
            {
                return signature;
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
        finally
        {
            this.rawSigner = null;
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        /*
         * NOTE: The SunMSCAPI provider's "NoneWithRSA" can't produce/verify RSA signatures in the correct format for TLS 1.2
         */
        if (algorithm != null
            && SignatureAlgorithm.rsa == algorithm.getSignature()
            && JcaUtils.isSunMSCAPIProviderActive()
            && isSunMSCAPIRawSigner())
        {
            return crypto.createVerifyingStreamSigner(algorithm, privateKey, true, publicKey);
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

    protected boolean isSunMSCAPIRawSigner() throws IOException
    {
        try
        {
            Signature rawSigner = getRawSigner();

            return JcaUtils.isSunMSCAPIProvider(rawSigner.getProvider());
        }
        catch (GeneralSecurityException e)
        {
            // Assume the worst!
            return true;
        }
    }
}
