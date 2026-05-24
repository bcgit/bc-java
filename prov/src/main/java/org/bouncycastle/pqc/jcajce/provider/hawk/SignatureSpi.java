package org.bouncycastle.pqc.jcajce.provider.hawk;

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
import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;
import org.bouncycastle.util.Strings;

/**
 * {@link java.security.Signature} SPI for Hawk. The unparameterised
 * {@link Base} form accepts any {@link BCHawkPublicKey} /
 * {@link BCHawkPrivateKey} and verifies / signs against whatever parameter set
 * the key carries; the nested {@link HAWK_256} / {@link HAWK_512} /
 * {@link HAWK_1024} subclasses pin the SPI to one parameter set and reject
 * keys for a different variant with
 * {@code "signature configured for " + canonicalName}.
 */
public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final HawkSigner signer;
    private SecureRandom random;
    private final HawkParameters parameters;

    protected SignatureSpi(HawkSigner signer)
    {
        super("Hawk");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(HawkSigner signer, HawkParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCHawkPublicKey))
        {
            try
            {
                publicKey = new BCHawkPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Hawk: " + e.getMessage());
            }
        }

        BCHawkPublicKey key = (BCHawkPublicKey)publicKey;

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
        if (privateKey instanceof BCHawkPrivateKey)
        {
            BCHawkPrivateKey key = (BCHawkPrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to Hawk");
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
        extends org.bouncycastle.pqc.jcajce.provider.hawk.SignatureSpi
    {
        public Base()
        {
            super(new HawkSigner());
        }
    }

    public static class HAWK_256
        extends org.bouncycastle.pqc.jcajce.provider.hawk.SignatureSpi
    {
        public HAWK_256()
        {
            super(new HawkSigner(), HawkParameters.Hawk_256);
        }
    }

    public static class HAWK_512
        extends org.bouncycastle.pqc.jcajce.provider.hawk.SignatureSpi
    {
        public HAWK_512()
        {
            super(new HawkSigner(), HawkParameters.Hawk_512);
        }
    }

    public static class HAWK_1024
        extends org.bouncycastle.pqc.jcajce.provider.hawk.SignatureSpi
    {
        public HAWK_1024()
        {
            super(new HawkSigner(), HawkParameters.Hawk_1024);
        }
    }
}
