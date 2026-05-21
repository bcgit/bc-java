package org.bouncycastle.pqc.jcajce.provider.faest;

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
import org.bouncycastle.pqc.crypto.faest.FaestParameters;
import org.bouncycastle.pqc.crypto.faest.FaestSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final FaestSigner signer;
    private SecureRandom random;
    private final FaestParameters parameters;

    protected SignatureSpi(FaestSigner signer)
    {
        super("Faest");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(FaestSigner signer, FaestParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCFaestPublicKey))
        {
            try
            {
                publicKey = new BCFaestPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Faest: " + e.getMessage());
            }
        }

        BCFaestPublicKey key = (BCFaestPublicKey)publicKey;

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
        if (privateKey instanceof BCFaestPrivateKey)
        {
            BCFaestPrivateKey key = (BCFaestPrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to Faest");
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
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    public static class Base
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public Base()
        {
            super(new FaestSigner());
        }
    }

    public static class FAEST_128S
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_128S()
        {
            super(new FaestSigner(), FaestParameters.faest_128s);
        }
    }

    public static class FAEST_128F
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_128F()
        {
            super(new FaestSigner(), FaestParameters.faest_128f);
        }
    }

    public static class FAEST_192S
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_192S()
        {
            super(new FaestSigner(), FaestParameters.faest_192s);
        }
    }

    public static class FAEST_192F
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_192F()
        {
            super(new FaestSigner(), FaestParameters.faest_192f);
        }
    }

    public static class FAEST_256S
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_256S()
        {
            super(new FaestSigner(), FaestParameters.faest_256s);
        }
    }

    public static class FAEST_256F
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_256F()
        {
            super(new FaestSigner(), FaestParameters.faest_256f);
        }
    }

    public static class FAEST_EM_128S
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_EM_128S()
        {
            super(new FaestSigner(), FaestParameters.faest_em_128s);
        }
    }

    public static class FAEST_EM_128F
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_EM_128F()
        {
            super(new FaestSigner(), FaestParameters.faest_em_128f);
        }
    }

    public static class FAEST_EM_192S
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_EM_192S()
        {
            super(new FaestSigner(), FaestParameters.faest_em_192s);
        }
    }

    public static class FAEST_EM_192F
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_EM_192F()
        {
            super(new FaestSigner(), FaestParameters.faest_em_192f);
        }
    }

    public static class FAEST_EM_256S
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_EM_256S()
        {
            super(new FaestSigner(), FaestParameters.faest_em_256s);
        }
    }

    public static class FAEST_EM_256F
        extends org.bouncycastle.pqc.jcajce.provider.faest.SignatureSpi
    {
        public FAEST_EM_256F()
        {
            super(new FaestSigner(), FaestParameters.faest_em_256f);
        }
    }
}
