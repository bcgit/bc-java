package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;

public abstract class TlsDSASigner
    extends AbstractTlsSigner
{
    public byte[] generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1)
        throws CryptoException
    {
        // Note: Only use the SHA1 part of the hash
        Signer signer = makeSigner(new NullDigest(), true,
            new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
        signer.update(md5AndSha1, 16, 20);
        return signer.generateSignature();
    }

    public boolean verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1)
        throws CryptoException
    {
        // Note: Only use the SHA1 part of the hash
        Signer signer = makeSigner(new NullDigest(), false, publicKey);
        signer.update(md5AndSha1, 16, 20);
        return signer.verifySignature(sigBytes);
    }

    public Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey)
    {
        return makeSigner(algorithm, true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
    }

    public Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey)
    {
        return makeSigner(algorithm, false, publicKey);
    }

    protected Signer makeSigner(SignatureAndHashAlgorithm algorithm, boolean forSigning, CipherParameters cp)
    {
        if (algorithm != null
            && (algorithm.getHash() != HashAlgorithm.sha1 || algorithm.getSignature() != getSignatureAlgorithm()))
        {
            throw new IllegalStateException();
        }

        return makeSigner(TlsUtils.createHash(HashAlgorithm.sha1), forSigning, cp);
    }

    protected Signer makeSigner(Digest d, boolean forSigning, CipherParameters cp)
    {
        Signer s = new DSADigestSigner(createDSAImpl(), d);
        s.init(forSigning, cp);
        return s;
    }

    protected abstract short getSignatureAlgorithm();

    protected abstract DSA createDSAImpl();
}
