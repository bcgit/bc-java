package org.bouncycastle.pqc.jcajce.provider.picnic;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.picnic.PicnicSigner;

public class SignatureSpi
    extends java.security.Signature
{
    private SecureRandom random;
    private Digest digest;
    private PicnicSigner signer;

    protected SignatureSpi(Digest digest, PicnicSigner signer)
    {
        super("Picnic");

        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCPicnicPublicKey)
        {
            BCPicnicPublicKey key = (BCPicnicPublicKey)publicKey;
            CipherParameters param = key.getKeyParams();

            digest.reset();
            signer.init(false, param);
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to Picnic");
        }
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (privateKey instanceof BCPicnicPrivateKey)
        {
            BCPicnicPrivateKey key = (BCPicnicPrivateKey)privateKey;
            CipherParameters param = key.getKeyParams();
            digest.reset();
            signer.init(true, param);
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to Picnic");
        }
    }

    protected void engineUpdate(byte b)
            throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException
    {
        digest.update(b, off, len);
    }


    protected byte[] engineSign()
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try
        {
            byte[] detachedSig = signer.generateSignature(hash);

            return detachedSig;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return signer.verifySignature(hash, sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
    {
        // TODO
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    public static class Base
            extends SignatureSpi
    {
        public Base()
        {
            super(new NullDigest(), new PicnicSigner());
        }
    }
    public static class withShake256
            extends SignatureSpi
    {
        public withShake256()
        {
            super(new SHAKEDigest(256), new PicnicSigner());
        }
    }
    public static class withSha512
            extends SignatureSpi
    {
        public withSha512()
        {
            super(new SHA512Digest(), new PicnicSigner());
        }
    }
    public static class withSha3512
            extends SignatureSpi
    {
        public withSha3512()
        {
            super(new SHA3Digest(512), new PicnicSigner());
        }
    }

}
