package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

public class PSSSignatureSpi
    extends Signature
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private AlgorithmParameters engineParams;
    private PSSParamSpec paramSpec;
    private AsymmetricBlockCipher signer;
    private Digest contentDigest;
    private Digest mgfDigest;
    private int saltLength;
    private byte trailer;
    private boolean isRaw;

    private org.bouncycastle.crypto.signers.PSSSigner pss;

    private byte getTrailer(
        int trailerField)
    {
        if (trailerField == 1)
        {
            return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
        }
        
        throw new IllegalArgumentException("unknown trailer field");
    }

    private void setupContentDigest()
    {
        if (isRaw)
        {
            this.contentDigest = new NullPssDigest(mgfDigest);
        }
        else
        {
            this.contentDigest = mgfDigest;
        }
    }

    protected PSSSignatureSpi(
        String name,
        AsymmetricBlockCipher signer,
        Digest digest)
    {
        super(name);

        this.signer = signer;

        if (digest != null)
        {
            this.saltLength = digest.getDigestSize();
            this.mgfDigest = digest;
        }
        else
        {
            this.saltLength = 20;
        }

        if (paramSpec != null)
        {
            this.saltLength = paramSpec.getSaltLength();
        }
        this.isRaw = false;

        setupContentDigest();
    }

    // care - this constructor is actually used by outside organisations
    protected PSSSignatureSpi(
        String name,
        AsymmetricBlockCipher signer,
        Digest digest,
        boolean isRaw)
    {
        super(name);

        this.signer = signer;

        if (digest != null)
        {
            this.saltLength = digest.getDigestSize();
            this.mgfDigest = digest;
        }
        else
        {
            this.saltLength = 20;
        }

        if (paramSpec != null)
        {
            this.saltLength = paramSpec.getSaltLength();
        }

        this.isRaw = isRaw;

        setupContentDigest();
    }
    
    protected void engineInitVerify(
        PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof RSAPublicKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance");
        }

        if (mgfDigest == null)
        {
            mgfDigest = new SHA1Digest();
            setupContentDigest();
        }

        pss = new org.bouncycastle.crypto.signers.PSSSigner(signer, contentDigest, mgfDigest, saltLength);
        pss.init(false,
            RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey));
    }

    protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof RSAPrivateKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
        }

        if (mgfDigest == null)
        {
            mgfDigest = new SHA1Digest();
            setupContentDigest();
        }

        pss = new org.bouncycastle.crypto.signers.PSSSigner(signer, contentDigest, mgfDigest, saltLength);
        pss.init(true, new ParametersWithRandom(RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey), random));
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof RSAPrivateKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
        }

        if (mgfDigest == null)
        {
            mgfDigest = new SHA1Digest();
            setupContentDigest();
        }
        
        pss = new org.bouncycastle.crypto.signers.PSSSigner(signer, contentDigest, mgfDigest, saltLength);
        pss.init(true, RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey));
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        pss.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        pss.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return pss.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        return pss.verifySignature(sigBytes);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidParameterException
    {
        if (params instanceof PSSParamSpec)
        {
            PSSParamSpec newParamSpec = (PSSParamSpec)params;

            this.engineParams = null;
            this.paramSpec = newParamSpec;
            this.saltLength = paramSpec.getSaltLength();

            boolean isSha3 = false;
            if (paramSpec instanceof PSSParamSpec)
            {
                 isSha3 = ((PSSParamSpec)paramSpec).getDigestName().startsWith("SHA3");
            }

            if (mgfDigest == null)
            {
                switch (saltLength)
                {
                case 20:
                    this.mgfDigest = new SHA1Digest();
                    break;
                case 28:
                    if (isSha3)
                    {
                        this.mgfDigest = new SHA3Digest(224);
                    }
                    else
                    {
                        this.mgfDigest = new SHA224Digest();
                    }
                    break;
                case 32:
                    if (isSha3)
                    {
                        this.mgfDigest = new SHA3Digest(256);
                    }
                    else
                    {
                        this.mgfDigest = new SHA256Digest();
                    }
                    break;
                case 48:
                    if (isSha3)
                    {
                        this.mgfDigest = new SHA3Digest(384);
                    }
                    else
                    {
                        this.mgfDigest = new SHA384Digest();
                    }
                    break;
                case 64:
                    if (isSha3)
                    {
                        this.mgfDigest = new SHA3Digest(512);
                    }
                    else
                    {
                        this.mgfDigest = new SHA512Digest();
                    }
                    break;
                default:
                    if (saltLength <= 20)
                    {
                        this.mgfDigest = new SHA1Digest();
                    }
                    else if (saltLength <= 28)
                    {
                        this.mgfDigest = new SHA224Digest();
                    }
                    else if (saltLength <= 32)
                    {
                         this.mgfDigest = new SHA256Digest();
                    }
                }
                setupContentDigest();
            }
        }
        else
        {
            throw new InvalidParameterException("Only PSSParamSpec supported");
        }
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            try
            {
                engineParams = helper.createAlgorithmParameters("PSS");
                engineParams.init(new PSSParamSpec(saltLength, mgfDigest.getAlgorithmName()));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.toString());
            }
        }

        return engineParams;
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
    
    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    static public class nonePSS
        extends PSSSignatureSpi
    {
        public nonePSS()
        {
            super("NONEwithRSAandMGF1", new RSABlindedEngine(), null, true);
        }
    }

    static public class PSSwithRSA
        extends PSSSignatureSpi
    {
        public PSSwithRSA()
        {
            super("SHA1withRSAandMGF1", new RSABlindedEngine(), null);
        }
    }

    static public class SHA1withRSA
        extends PSSSignatureSpi
    {
        public SHA1withRSA()
        {
            super("SHA1withRSAandMGF1", new RSABlindedEngine(), new SHA1Digest());
        }
    }

    static public class SHA224withRSA
        extends PSSSignatureSpi
    {
        public SHA224withRSA()
        {
            super("SHA224withRSAandMGF1", new RSABlindedEngine(), new SHA224Digest());
        }
    }

    static public class SHA256withRSA
        extends PSSSignatureSpi
    {
        public SHA256withRSA()
        {
            super("SHA256withRSAandMGF1", new RSABlindedEngine(), new SHA256Digest());
        }
    }

    static public class SHA384withRSA
        extends PSSSignatureSpi
    {
        public SHA384withRSA()
        {
            super("SHA384withRSAandMGF1", new RSABlindedEngine(), new SHA384Digest());
        }
    }

    static public class SHA512withRSA
        extends PSSSignatureSpi
    {
        public SHA512withRSA()
        {
            super("SHA512withRSAandMGF1", new RSABlindedEngine(), new SHA512Digest());
        }
    }

    static public class SHA512_224withRSA
        extends PSSSignatureSpi
    {
        public SHA512_224withRSA()
        {
            super("SHA512(224)withRSAandMGF1", new RSABlindedEngine(), new SHA512tDigest(224));
        }
    }

    static public class SHA512_256withRSA
        extends PSSSignatureSpi
    {
        public SHA512_256withRSA()
        {
            super("SHA512(256)withRSAandMGF1", new RSABlindedEngine(), new SHA512tDigest(256));
        }
    }

    static public class SHA3_224withRSA
        extends PSSSignatureSpi
    {
        public SHA3_224withRSA()
        {
            super("SHA3-224withRSAandMGF1", new RSABlindedEngine(), new SHA3Digest(224));
        }
    }

    static public class SHA3_256withRSA
        extends PSSSignatureSpi
    {
        public SHA3_256withRSA()
        {
            super("SHA3-256withRSAandMGF1", new RSABlindedEngine(), new SHA3Digest(256));
        }
    }

    static public class SHA3_384withRSA
        extends PSSSignatureSpi
    {
        public SHA3_384withRSA()
        {
            super("SHA3-384withRSAandMGF1", new RSABlindedEngine(), new SHA3Digest(384));
        }
    }

    static public class SHA3_512withRSA
        extends PSSSignatureSpi
    {
        public SHA3_512withRSA()
        {
            super("SHA3-512withRSAandMGF1", new RSABlindedEngine(), new SHA3Digest(512));
        }
    }

    private class NullPssDigest
        implements Digest
    {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        private Digest baseDigest;
        private boolean oddTime = true;

        public NullPssDigest(Digest mgfDigest)
        {
            this.baseDigest = mgfDigest;
        }

        public String getAlgorithmName()
        {
            return "NULL";
        }

        public int getDigestSize()
        {
            return baseDigest.getDigestSize();
        }

        public void update(byte in)
        {
            bOut.write(in);
        }

        public void update(byte[] in, int inOff, int len)
        {
            bOut.write(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff)
        {
            byte[] res = bOut.toByteArray();

            if (oddTime)
            {
                System.arraycopy(res, 0, out, outOff, res.length);
            }
            else
            {
                baseDigest.update(res, 0, res.length);

                baseDigest.doFinal(out, outOff);
            }

            reset();

            oddTime = !oddTime;

            return res.length;
        }

        public void reset()
        {
            bOut.reset();
            baseDigest.reset();
        }

        public int getByteLength()
        {
            return 0;
        }
    }
}
