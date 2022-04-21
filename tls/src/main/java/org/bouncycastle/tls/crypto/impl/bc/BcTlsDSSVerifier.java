package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

/**
 * BC light-weight base class for the verifiers supporting the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class BcTlsDSSVerifier
    extends BcTlsVerifier
{
    protected BcTlsDSSVerifier(BcTlsCrypto crypto, AsymmetricKeyParameter publicKey)
    {
        super(crypto, publicKey);
    }

    protected abstract DSA createDSAImpl();

    protected abstract short getSignatureAlgorithm();

    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        Signer signer = new DSADigestSigner(createDSAImpl(), new NullDigest());
        signer.init(false, publicKey);
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        return signer.verifySignature(digitallySigned.getSignature());
    }
}
