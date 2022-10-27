package org.bouncycastle.pqc.jcajce.provider.rainbow;

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
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private ByteArrayOutputStream bOut;
    private RainbowSigner signer;
    private SecureRandom random;
    private RainbowParameters parameters;

    protected SignatureSpi(RainbowSigner signer)
    {
        super("RAINBOW");
        
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(RainbowSigner signer, RainbowParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCRainbowPublicKey))
        {
            try
            {
                publicKey = new BCRainbowPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Rainbow: " + e.getMessage(), e);
            }
        }

        BCRainbowPublicKey key = (BCRainbowPublicKey)publicKey;

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
        if (privateKey instanceof BCRainbowPrivateKey)
        {
            BCRainbowPrivateKey key = (BCRainbowPrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to Rainbow");
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
            super(new RainbowSigner());
        }
    }

    public static class RainbowIIIclassic
        extends SignatureSpi
    {
        public RainbowIIIclassic()
        {
            super(new RainbowSigner(), RainbowParameters.rainbowIIIclassic);
        }
    }

    public static class RainbowIIIcircum
        extends SignatureSpi
    {
        public RainbowIIIcircum()
        {
            super(new RainbowSigner(), RainbowParameters.rainbowIIIcircumzenithal);
        }
    }

    public static class RainbowIIIcomp
        extends SignatureSpi
    {
        public RainbowIIIcomp()
        {
            super(new RainbowSigner(), RainbowParameters.rainbowIIIcompressed);
        }
    }

    public static class RainbowVclassic
        extends SignatureSpi
    {
        public RainbowVclassic()
        {
            super(new RainbowSigner(), RainbowParameters.rainbowVclassic);
        }
    }

    public static class RainbowVcircum
        extends SignatureSpi
    {
        public RainbowVcircum()
        {
            super(new RainbowSigner(), RainbowParameters.rainbowVcircumzenithal);
        }
    }

    public static class RainbowVcomp
        extends SignatureSpi
    {
        public RainbowVcomp()
        {
            super(new RainbowSigner(), RainbowParameters.rainbowVcompressed);
        }
    }
}
