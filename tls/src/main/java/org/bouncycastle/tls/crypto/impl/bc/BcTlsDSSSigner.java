package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;

/**
 * BC light-weight base class for the signers implementing the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class BcTlsDSSSigner
    extends BcTlsSigner
{
    protected BcTlsDSSSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)
    {
        super(crypto, privateKey);
    }

    protected abstract DSA createDSAImpl(int cryptoHashAlgorithm);

    protected abstract short getSignatureAlgorithm();

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = (null == algorithm)
            ? CryptoHashAlgorithm.sha1
            : TlsCryptoUtils.getHash(algorithm.getHash());

        Signer signer = new DSADigestSigner(createDSAImpl(cryptoHashAlgorithm), new NullDigest());
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
