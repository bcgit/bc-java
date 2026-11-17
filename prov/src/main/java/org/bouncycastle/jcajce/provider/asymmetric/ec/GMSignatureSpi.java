package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseInitRandomSignatureSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;

public class GMSignatureSpi
    extends BaseInitRandomSignatureSpi
{
    private SM2ParameterSpec paramSpec;
    private CipherParameters keyParam;
    private boolean forSigning;

    private final SM2Signer signer;

    protected GMSignatureSpi(SM2Signer signer)
    {
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        keyParam = ECUtils.generatePublicKeyParameter(publicKey);
        forSigning = false;

        initSigner();
    }

    protected void signInit(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);

        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }

        keyParam = param;
        forSigning = true;

        initSigner();
    }

    // the ID is part of the init, so a setParameter() after initSign/initVerify has to initialise again
    private void initSigner()
    {
        if (paramSpec != null)
        {
            signer.init(forSigning, new ParametersWithID(keyParam, paramSpec.getID()));
        }
        else
        {
            signer.init(forSigning, keyParam);
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        signer.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int length)
        throws SignatureException
    {
        signer.update(bytes, off, length);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new SignatureException("unable to create signature: " + e.getMessage());
        }
    }

    protected boolean engineVerify(byte[] bytes)
        throws SignatureException
    {
        return signer.verifySignature(bytes);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof SM2ParameterSpec)
        {
            paramSpec = (SM2ParameterSpec)params;

            if (keyParam != null)
            {
                initSigner();
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("only SM2ParameterSpec supported");
        }
    }

    /**
     * SM2 has no AlgorithmParameters encoding for its user ID, so there are none to return.
     */
    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

//    static public class blake2b512WithSM2
//        extends GMSignatureSpi
//    {
//        public blake2b512WithSM2()
//        {
//            super(new SM2Signer(new Blake2bDigest(512)));
//        }
//    }

//    static public class blake2s256WithSM2
//        extends GMSignatureSpi
//    {
//        public blake2s256WithSM2()
//        {
//            super(new SM2Signer(new Blake2sDigest(256)));
//        }
//    }

//    static public class ripemd160WithSM2
//        extends GMSignatureSpi
//    {
//        public ripemd160WithSM2()
//        {
//            super(new SM2Signer(new RIPEMD160Digest()));
//        }
//    }

//    static public class sha1WithSM2
//        extends GMSignatureSpi
//    {
//        public sha1WithSM2()
//        {
//            super(new SM2Signer(new SHA1Digest()));
//        }
//    }

//    static public class sha224WithSM2
//        extends GMSignatureSpi
//    {
//        public sha224WithSM2()
//        {
//            super(new SM2Signer(new SHA224Digest()));
//        }
//    }

    static public class sha256WithSM2
        extends GMSignatureSpi
    {
        public sha256WithSM2()
        {
            super(new SM2Signer(SHA256Digest.newInstance()));
        }
    }

//    static public class sha384WithSM2
//        extends GMSignatureSpi
//    {
//        public sha384WithSM2()
//        {
//            super(new SM2Signer(new SHA384Digest()));
//        }
//    }

//    static public class sha512WithSM2
//        extends GMSignatureSpi
//    {
//        public sha512WithSM2()
//        {
//            super(new SM2Signer(new SHA512Digest()));
//        }
//    }

    static public class sm3WithSM2
        extends GMSignatureSpi
    {
        public sm3WithSM2()
        {
            super(new SM2Signer());
        }
    }

//    static public class whirlpoolWithSM2
//        extends GMSignatureSpi
//    {
//        public whirlpoolWithSM2()
//        {
//            super(new SM2Signer(new WhirlpoolDigest()));
//        }
//    }
}
