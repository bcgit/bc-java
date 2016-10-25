package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * BC light-weight base class for the verifiers supporting the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class BcTlsDSSVerifier
    implements TlsVerifier
{
    protected final AsymmetricKeyParameter pubKey;
    protected final BcTlsCrypto crypto;

    protected BcTlsDSSVerifier(BcTlsCrypto crypto, AsymmetricKeyParameter pubKey)
    {
        if (pubKey == null)
        {
            throw new IllegalArgumentException("'pubKey' cannot be null");
        }
        if (pubKey.isPrivate())
        {
            throw new IllegalArgumentException("'pubKey' must be a public key");
        }

        this.crypto = crypto;
        this.pubKey = pubKey;
    }

    protected abstract DSA createDSAImpl(short hashAlgorithm);

    protected abstract short getSignatureAlgorithm();

    public boolean verifySignature(DigitallySigned signedParams, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();
        if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
        {
            throw new IllegalStateException();
        }

        short hashAlgorithm = algorithm == null ? HashAlgorithm.sha1 : algorithm.getHash();

        Signer signer = new DSADigestSigner(createDSAImpl(hashAlgorithm), new NullDigest());
        signer.init(false, pubKey);
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        return signer.verifySignature(signedParams.getSignature());
    }
}
