package org.bouncycastle.pqc.jcajce.provider.aimer;

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
import org.bouncycastle.pqc.crypto.aimer.AIMerParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final AIMerSigner signer;
    private SecureRandom random;
    private final AIMerParameters parameters;

    protected SignatureSpi(AIMerSigner signer)
    {
        super("AIMer");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(AIMerSigner signer, AIMerParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCAIMerPublicKey))
        {
            try
            {
                publicKey = new BCAIMerPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to AIMer: " + e.getMessage());
            }
        }

        BCAIMerPublicKey key = (BCAIMerPublicKey)publicKey;

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
        if (privateKey instanceof BCAIMerPrivateKey)
        {
            BCAIMerPrivateKey key = (BCAIMerPrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to AIMer");
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
        extends org.bouncycastle.pqc.jcajce.provider.aimer.SignatureSpi
    {
        public Base()
        {
            super(new AIMerSigner());
        }
    }

    public static class AIMer_128f
        extends org.bouncycastle.pqc.jcajce.provider.aimer.SignatureSpi
    {
        public AIMer_128f()
        {
            super(new AIMerSigner(), AIMerParameters.aimer128f);
        }
    }

    public static class AIMer_128s
        extends org.bouncycastle.pqc.jcajce.provider.aimer.SignatureSpi
    {
        public AIMer_128s()
        {
            super(new AIMerSigner(), AIMerParameters.aimer128s);
        }
    }

    public static class AIMer_192f
        extends org.bouncycastle.pqc.jcajce.provider.aimer.SignatureSpi
    {
        public AIMer_192f()
        {
            super(new AIMerSigner(), AIMerParameters.aimer192f);
        }
    }

    public static class AIMer_192s
        extends org.bouncycastle.pqc.jcajce.provider.aimer.SignatureSpi
    {
        public AIMer_192s()
        {
            super(new AIMerSigner(), AIMerParameters.aimer192s);
        }
    }

    public static class AIMer_256f
        extends org.bouncycastle.pqc.jcajce.provider.aimer.SignatureSpi
    {
        public AIMer_256f()
        {
            super(new AIMerSigner(), AIMerParameters.aimer256f);
        }
    }

    public static class AIMer_256s
        extends org.bouncycastle.pqc.jcajce.provider.aimer.SignatureSpi
    {
        public AIMer_256s()
        {
            super(new AIMerSigner(), AIMerParameters.aimer256s);
        }
    }
}

