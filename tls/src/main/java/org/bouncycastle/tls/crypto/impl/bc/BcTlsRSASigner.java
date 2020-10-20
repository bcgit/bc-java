package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;

/**
 * Operator supporting the generation of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
 */
public class BcTlsRSASigner
    extends BcTlsSigner
{
    private final RSAKeyParameters publicKey;

    public BcTlsRSASigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, RSAKeyParameters publicKey)
    {
        super(crypto, privateKey);

        this.publicKey = publicKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        Digest nullDigest = crypto.createDigest(HashAlgorithm.none);

        Signer signer;
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
            signer = new RSADigestSigner(nullDigest, TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
            signer = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), nullDigest);
        }
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        try
        {
            byte[] signature = signer.generateSignature();

            signer.init(false, publicKey);
            signer.update(hash, 0, hash.length);

            if (signer.verifySignature(signature))
            {
                return signature;
            }
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
