package org.bouncycastle.pqc.jcajce.provider.dilithium;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private ByteArrayOutputStream bOut;
    private DilithiumSigner signer;
    private SecureRandom random;
    private DilithiumParameters parameters;

    protected SignatureSpi(DilithiumSigner signer)
    {
        super("Dilithium");
        
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(DilithiumSigner signer, DilithiumParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = parameters;
    }


    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCDilithiumPublicKey))
        {
            try
            {
                publicKey = new BCDilithiumPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Dilithium: " + e.getMessage());
            }
        }

        BCDilithiumPublicKey key = (BCDilithiumPublicKey)publicKey;

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
        if (privateKey instanceof BCDilithiumPrivateKey)
        {
            BCDilithiumPrivateKey key = (BCDilithiumPrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to Dilithium");
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
            super(new DilithiumSigner());
        }
    }

    public static class Base2
        extends SignatureSpi
    {
        public Base2()
        {
            super(new DilithiumSigner(), DilithiumParameters.dilithium2);
        }
    }

    public static class Base3
        extends SignatureSpi
    {
        public Base3()
        {
            super(new DilithiumSigner(), DilithiumParameters.dilithium3);
        }
    }

    public static class Base5
        extends SignatureSpi
    {
        public Base5()
            throws NoSuchAlgorithmException
        {
            super(new DilithiumSigner(), DilithiumParameters.dilithium5);
        }
    }

    public static class Base2_AES
        extends SignatureSpi
    {
        public Base2_AES()
            throws NoSuchAlgorithmException
        {
            super(new DilithiumSigner(), DilithiumParameters.dilithium2_aes);
        }
    }

    public static class Base3_AES
        extends SignatureSpi
    {
        public Base3_AES()
            throws NoSuchAlgorithmException
        {
            super(new DilithiumSigner(), DilithiumParameters.dilithium3_aes);
        }
    }

    public static class Base5_AES
        extends SignatureSpi
    {
        public Base5_AES()
            throws NoSuchAlgorithmException
        {
            super(new DilithiumSigner(), DilithiumParameters.dilithium5_aes);
        }
    }
}
