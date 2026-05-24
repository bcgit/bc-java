package org.bouncycastle.pqc.jcajce.provider.haetae;

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
import org.bouncycastle.pqc.crypto.haetae.HAETAEParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAESigner;
import org.bouncycastle.util.Strings;

/**
 * {@link java.security.Signature} SPI for HAETAE. The unparameterised
 * {@link Base} form accepts any {@link BCHaetaePublicKey} /
 * {@link BCHaetaePrivateKey} and verifies / signs against whatever parameter
 * set the key carries; the nested {@link HAETAE2} / {@link HAETAE3} /
 * {@link HAETAE5} subclasses pin the SPI to one parameter set and reject keys
 * for a different variant with
 * {@code "signature configured for " + canonicalName}.
 */
public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final HAETAESigner signer;
    private SecureRandom random;
    private final HAETAEParameters parameters;

    protected SignatureSpi(HAETAESigner signer)
    {
        super("Haetae");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(HAETAESigner signer, HAETAEParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCHaetaePublicKey))
        {
            try
            {
                publicKey = new BCHaetaePublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Haetae: " + e.getMessage());
            }
        }

        BCHaetaePublicKey key = (BCHaetaePublicKey)publicKey;

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
        if (privateKey instanceof BCHaetaePrivateKey)
        {
            BCHaetaePrivateKey key = (BCHaetaePrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to Haetae");
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
        extends org.bouncycastle.pqc.jcajce.provider.haetae.SignatureSpi
    {
        public Base()
        {
            super(new HAETAESigner());
        }
    }

    public static class HAETAE2
        extends org.bouncycastle.pqc.jcajce.provider.haetae.SignatureSpi
    {
        public HAETAE2()
        {
            super(new HAETAESigner(), HAETAEParameters.haetae2);
        }
    }

    public static class HAETAE3
        extends org.bouncycastle.pqc.jcajce.provider.haetae.SignatureSpi
    {
        public HAETAE3()
        {
            super(new HAETAESigner(), HAETAEParameters.haetae3);
        }
    }

    public static class HAETAE5
        extends org.bouncycastle.pqc.jcajce.provider.haetae.SignatureSpi
    {
        public HAETAE5()
        {
            super(new HAETAESigner(), HAETAEParameters.haetae5);
        }
    }
}
