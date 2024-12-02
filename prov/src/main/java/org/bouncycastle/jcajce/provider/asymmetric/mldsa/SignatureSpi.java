package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

public class SignatureSpi
    extends BaseDeterministicOrRandomSignature
{
    private MLDSASigner signer;
    private MLDSAParameters parameters;

    protected SignatureSpi(MLDSASigner signer)
    {
        super("MLDSA");

        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(MLDSASigner signer, MLDSAParameters parameters)
    {
        super(MLDSAParameterSpec.fromName(parameters.getName()).getName());

        this.signer = signer;
        this.parameters = parameters;
    }

    protected void verifyInit(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCMLDSAPublicKey)
        {
            BCMLDSAPublicKey key = (BCMLDSAPublicKey)publicKey;

            this.keyParams = key.getKeyParams();

            if (parameters != null)
            {
                String canonicalAlg = MLDSAParameterSpec.fromName(parameters.getName()).getName();
                if (!canonicalAlg.equals(key.getAlgorithm()))
                {
                    throw new InvalidKeyException("signature configured for " + canonicalAlg);
                }
            }
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to ML-DSA");
        }
    }

    protected void signInit(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        this.appRandom = random;
        if (privateKey instanceof BCMLDSAPrivateKey)
        {
            BCMLDSAPrivateKey key = (BCMLDSAPrivateKey)privateKey;

            this.keyParams = key.getKeyParams();

            if (parameters != null)
            {
                String canonicalAlg = MLDSAParameterSpec.fromName(parameters.getName()).getName();
                if (!canonicalAlg.equals(key.getAlgorithm()))
                {
                    throw new InvalidKeyException("signature configured for " + canonicalAlg);
                }
            }
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to ML-DSA");
        }
    }

    protected void updateEngine(byte b)
        throws SignatureException
    {
        signer.update(b);
    }

    protected void updateEngine(byte[] b, int off, int len)
        throws SignatureException
    {
        signer.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return signer.generateSignature();
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        return signer.verifySignature(sigBytes);
    }

    protected void reInitialize(boolean forSigning, CipherParameters params)
    {
        signer.init(forSigning, params);
    }

    public static class MLDSA
            extends SignatureSpi
    {
        public MLDSA()
        {
            super(new MLDSASigner());
        }
    }

    public static class MLDSA44
            extends SignatureSpi
    {
        public MLDSA44()
        {
            super(new MLDSASigner(), MLDSAParameters.ml_dsa_44);
        }
    }

    public static class MLDSA65
            extends SignatureSpi
    {
        public MLDSA65()
        {
            super(new MLDSASigner(), MLDSAParameters.ml_dsa_65);
        }
    }

    public static class MLDSA87
            extends SignatureSpi
    {
        public MLDSA87()
                throws NoSuchAlgorithmException
        {
            super(new MLDSASigner(), MLDSAParameters.ml_dsa_87);
        }
    }
}
