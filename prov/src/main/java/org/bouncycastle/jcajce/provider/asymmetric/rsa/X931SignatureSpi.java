package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.signers.X931Signer;
import org.bouncycastle.crypto.util.DigestFactory;

public class X931SignatureSpi
    extends SignatureSpi
{
    private X931Signer signer;

    protected X931SignatureSpi(
        Digest digest,
        AsymmetricBlockCipher cipher)
    {
        signer = new X931Signer(cipher, digest);
    }

    protected void engineInitVerify(
        PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey);

        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        CipherParameters param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey);

        signer.init(true, param);
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        signer.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        signer.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            byte[]  sig = signer.generateSignature();

            return sig;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        boolean yes = signer.verifySignature(sigBytes);

        return yes;
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
     */
    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    static public class RIPEMD128WithRSAEncryption
        extends X931SignatureSpi
    {
        public RIPEMD128WithRSAEncryption()
        {
            super(new RIPEMD128Digest(), new RSABlindedEngine());
        }
    }

    static public class RIPEMD160WithRSAEncryption
        extends X931SignatureSpi
    {
        public RIPEMD160WithRSAEncryption()
        {
            super(new RIPEMD160Digest(), new RSABlindedEngine());
        }
    }

    static public class SHA1WithRSAEncryption
        extends X931SignatureSpi
    {
        public SHA1WithRSAEncryption()
        {
            super(DigestFactory.createSHA1(), new RSABlindedEngine());
        }
    }

    static public class SHA224WithRSAEncryption
        extends X931SignatureSpi
    {
        public SHA224WithRSAEncryption()
        {
            super(DigestFactory.createSHA224(), new RSABlindedEngine());
        }
    }

    static public class SHA256WithRSAEncryption
        extends X931SignatureSpi
    {
        public SHA256WithRSAEncryption()
        {
            super(DigestFactory.createSHA256(), new RSABlindedEngine());
        }
    }

    static public class SHA384WithRSAEncryption
        extends X931SignatureSpi
    {
        public SHA384WithRSAEncryption()
        {
            super(DigestFactory.createSHA384(), new RSABlindedEngine());
        }
    }

    static public class SHA512WithRSAEncryption
        extends X931SignatureSpi
    {
        public SHA512WithRSAEncryption()
        {
            super(DigestFactory.createSHA512(), new RSABlindedEngine());
        }
    }

    static public class SHA512_224WithRSAEncryption
        extends X931SignatureSpi
    {
        public SHA512_224WithRSAEncryption()
        {
            super(DigestFactory.createSHA512_224(), new RSABlindedEngine());
        }
    }

    static public class SHA512_256WithRSAEncryption
        extends X931SignatureSpi
    {
        public SHA512_256WithRSAEncryption()
        {
            super(DigestFactory.createSHA512_256(), new RSABlindedEngine());
        }
    }

    static public class WhirlpoolWithRSAEncryption
        extends X931SignatureSpi
    {
        public WhirlpoolWithRSAEncryption()
        {
            super(new WhirlpoolDigest(), new RSABlindedEngine());
        }
    }
}
