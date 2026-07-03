package org.bouncycastle.pqc.jcajce.provider.sqisign;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignSigner;

public class SignatureSpi
    extends java.security.SignatureSpi
{
    private final ByteArrayOutputStream bOut;
    private final SQIsignSigner signer;
    private SecureRandom random;
    private final SQIsignParameters parameters;

    protected SignatureSpi(SQIsignSigner signer)
    {
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(SQIsignSigner signer, SQIsignParameters parameters)
    {
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = parameters;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCSQIsignPublicKey))
        {
            try
            {
                publicKey = new BCSQIsignPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw SecurityExceptions.invalidKeyException("unknown public key passed to SQIsign", e);
            }
        }

        BCSQIsignPublicKey key = (BCSQIsignPublicKey)publicKey;

        if (parameters != null)
        {
            String canonicalAlg = parameters.getName();
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
        if (privateKey instanceof BCSQIsignPrivateKey)
        {
            BCSQIsignPrivateKey key = (BCSQIsignPrivateKey)privateKey;
            CipherParameters param = key.getKeyParams();

            if (parameters != null)
            {
                String canonicalAlg = parameters.getName();
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
            throw new InvalidKeyException("unknown private key passed to SQIsign");
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
            throw SecurityExceptions.signatureException(e.getMessage(), e);
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
        extends SignatureSpi
    {
        public Base()
        {
            super(new SQIsignSigner());
        }
    }

    public static class SQIsign_lvl1
        extends SignatureSpi
    {
        public SQIsign_lvl1()
        {
            super(new SQIsignSigner(), SQIsignParameters.sqisign_lvl1);
        }
    }

    public static class SQIsign_lvl3
        extends SignatureSpi
    {
        public SQIsign_lvl3()
        {
            super(new SQIsignSigner(), SQIsignParameters.sqisign_lvl3);
        }
    }

    public static class SQIsign_lvl5
        extends SignatureSpi
    {
        public SQIsign_lvl5()
        {
            super(new SQIsignSigner(), SQIsignParameters.sqisign_lvl5);
        }
    }
}
