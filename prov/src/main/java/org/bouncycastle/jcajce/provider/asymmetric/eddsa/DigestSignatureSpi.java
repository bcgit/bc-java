package org.bouncycastle.jcajce.provider.asymmetric.eddsa;


import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;


public class DigestSignatureSpi
    extends SignatureSpi
{
    private Digest digest;
    private EdDSAEngine engine;

    private DigestSignatureSpi(
            Digest digest)
    {
        this.engine = new EdDSAEngine();
        this.digest = digest;
    }

    protected void engineInitVerify(
        PublicKey publicKey)
        throws InvalidKeyException
    {
        engine.initVerify(publicKey);

        digest.reset();
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        engine.initSign(privateKey);

        digest.reset();
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len)
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        engine.update(hash);
        return engine.sign();
    }

    protected boolean engineVerify(
        byte[]  sigBytes)
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        engine.update(hash);
        return engine.verify(sigBytes);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
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
        return null;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    static public class SHA1
        extends DigestSignatureSpi
    {
        public SHA1()
        {
            super(new SHA1Digest());
        }
    }

    static public class SHA224
        extends DigestSignatureSpi
    {
        public SHA224()
        {
            super(new SHA224Digest());
        }
    }

    static public class SHA256
        extends DigestSignatureSpi
    {
        public SHA256()
        {
            super(new SHA256Digest());
        }
    }

    static public class SHA384
        extends DigestSignatureSpi
    {
        public SHA384()
        {
            super(new SHA384Digest());
        }
    }

    static public class SHA512
        extends DigestSignatureSpi
    {
        public SHA512()
        {
            super(new SHA512Digest());
        }
    }

    static public class SHA512_224
        extends DigestSignatureSpi
    {
        public SHA512_224()
        {
            super(new SHA512tDigest(224));
        }
    }

    static public class SHA512_256
        extends DigestSignatureSpi
    {
        public SHA512_256()
        {
            super(new SHA512tDigest(256));
        }
    }

    static public class MD2
        extends DigestSignatureSpi
    {
        public MD2()
        {
            super(new MD2Digest());
        }
    }

    static public class MD4
        extends DigestSignatureSpi
    {
        public MD4()
        {
            super(new MD4Digest());
        }
    }

    static public class MD5
        extends DigestSignatureSpi
    {
        public MD5()
        {
            super(new MD5Digest());
        }
    }

    static public class RIPEMD160
        extends DigestSignatureSpi
    {
        public RIPEMD160()
        {
            super(new RIPEMD160Digest());
        }
    }

    static public class RIPEMD128
        extends DigestSignatureSpi
    {
        public RIPEMD128()
        {
            super(new RIPEMD128Digest());
        }
    }

    static public class RIPEMD256
        extends DigestSignatureSpi
    {
        public RIPEMD256()
        {
            super(new RIPEMD256Digest());
        }
    }
}
