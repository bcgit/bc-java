package org.bouncycastle.pqc.jcajce.provider.sdith;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sdith.SDitHParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final SDitHSigner signer;
    private SecureRandom random;
    private final SDitHParameters parameters;

    protected SignatureSpi(SDitHSigner signer)
    {
        super("SDitH");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(SDitHSigner signer, SDitHParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCSDitHPublicKey))
        {
            try
            {
                publicKey = new BCSDitHPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to SDitH: " + e.getMessage());
            }
        }

        BCSDitHPublicKey key = (BCSDitHPublicKey) publicKey;

        if (parameters != null)
        {
            String canonicalAlg = Strings.toUpperCase(parameters.getName());
            if (!canonicalAlg.equals(key.getAlgorithm()))
            {
                throw new InvalidKeyException("signature configured for " + canonicalAlg);
            }
        }

        signer.init(false, key.getKeyParams());
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
        if (privateKey instanceof BCSDitHPrivateKey)
        {
            BCSDitHPrivateKey key = (BCSDitHPrivateKey) privateKey;
            CipherParameters param = key.getKeyParams();

            if (parameters != null)
            {
                String canonicalAlg = Strings.toUpperCase(parameters.getName());
                if (!canonicalAlg.equals(key.getAlgorithm()))
                {
                    throw new InvalidKeyException("signature configured for " + canonicalAlg);
                }
            }

            if (random != null)
            {
                signer.init(true, new ParametersWithRandom(param, random));
            }
            else
            {
                signer.init(true, param);
            }
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to SDitH");
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        bOut.write(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        bOut.write(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            byte[] message = bOut.toByteArray();
            bOut.reset();
            return signer.generateSignature(message);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        byte[] message = bOut.toByteArray();
        bOut.reset();
        return signer.verifySignature(message, sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
    {
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
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    public static class Base
        extends SignatureSpi
    {
        public Base()
        {
            super(new SDitHSigner());
        }
    }

    public static class HypercubeCat1Gf256 extends SignatureSpi
    {
        public HypercubeCat1Gf256()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_hypercube_cat1_gf256);
        }
    }

    public static class HypercubeCat3Gf256 extends SignatureSpi
    {
        public HypercubeCat3Gf256()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_hypercube_cat3_gf256);
        }
    }

    public static class HypercubeCat5Gf256 extends SignatureSpi
    {
        public HypercubeCat5Gf256()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_hypercube_cat5_gf256);
        }
    }

    public static class HypercubeCat1P251 extends SignatureSpi
    {
        public HypercubeCat1P251()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_hypercube_cat1_p251);
        }
    }

    public static class HypercubeCat3P251 extends SignatureSpi
    {
        public HypercubeCat3P251()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_hypercube_cat3_p251);
        }
    }

    public static class HypercubeCat5P251 extends SignatureSpi
    {
        public HypercubeCat5P251()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_hypercube_cat5_p251);
        }
    }

    public static class ThresholdCat1Gf256 extends SignatureSpi
    {
        public ThresholdCat1Gf256()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_threshold_cat1_gf256);
        }
    }

    public static class ThresholdCat3Gf256 extends SignatureSpi
    {
        public ThresholdCat3Gf256()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_threshold_cat3_gf256);
        }
    }

    public static class ThresholdCat5Gf256 extends SignatureSpi
    {
        public ThresholdCat5Gf256()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_threshold_cat5_gf256);
        }
    }

    public static class ThresholdCat1P251 extends SignatureSpi
    {
        public ThresholdCat1P251()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_threshold_cat1_p251);
        }
    }

    public static class ThresholdCat3P251 extends SignatureSpi
    {
        public ThresholdCat3P251()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_threshold_cat3_p251);
        }
    }

    public static class ThresholdCat5P251 extends SignatureSpi
    {
        public ThresholdCat5P251()
        {
            super(new SDitHSigner(), SDitHParameters.sdith_threshold_cat5_p251);
        }
    }
}
