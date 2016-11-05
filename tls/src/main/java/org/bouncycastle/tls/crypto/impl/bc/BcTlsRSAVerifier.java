package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * Operator supporting the verification of RSA signatures using the BC light-weight API.
 */
public class BcTlsRSAVerifier
    implements TlsVerifier
{
    protected RSAKeyParameters pubKeyRSA;

    public BcTlsRSAVerifier(RSAKeyParameters pubKeyRSA)
    {
        if (pubKeyRSA == null)
        {
            throw new IllegalArgumentException("'pubKeyRSA' cannot be null");
        }
        if (pubKeyRSA.isPrivate())
        {
            throw new IllegalArgumentException("'pubKeyRSA' must be a public key");
        }

        this.pubKeyRSA = pubKeyRSA;
    }

    public boolean verifySignature(DigitallySigned signedParams, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        Signer signer;
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
            signer = new RSADigestSigner(new NullDigest(), TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()));
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
            signer = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), new NullDigest());
        }
        signer.init(false, pubKeyRSA);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(signedParams.getSignature());
    }
}
