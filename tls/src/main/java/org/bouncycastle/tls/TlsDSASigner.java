package org.bouncycastle.tls;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;

public abstract class TlsDSASigner
    extends AbstractTlsSigner
{
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey,
        byte[] hash) throws CryptoException
    {
        Signer signer = makeSigner(algorithm, true,
            new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        return signer.generateSignature();
    }

    public boolean verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes,
        AsymmetricKeyParameter publicKey, byte[] hash) throws CryptoException
    {
        Signer signer = makeSigner(algorithm, false, publicKey);
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        return signer.verifySignature(sigBytes);
    }

    protected CipherParameters makeInitParameters(boolean forSigning, CipherParameters cp)
    {
        return cp;
    }

    protected Signer makeSigner(SignatureAndHashAlgorithm algorithm, boolean forSigning, CipherParameters cp)
    {
        if ((algorithm != null) != TlsUtils.isTLSv12(context))
        {
            throw new IllegalStateException();
        }

        if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
        {
            throw new IllegalStateException();
        }

        short hashAlgorithm = algorithm == null ? HashAlgorithm.sha1 : algorithm.getHash();

        Signer s = new DSADigestSigner(createDSAImpl(hashAlgorithm), new NullDigest());
        s.init(forSigning, makeInitParameters(forSigning, cp));
        return s;
    }

    protected abstract short getSignatureAlgorithm();

    protected abstract DSA createDSAImpl(short hashAlgorithm);
}
