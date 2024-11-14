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
import org.bouncycastle.pqc.crypto.mldsa.HashMLDSASigner;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;

public class HashSignatureSpi
    extends BaseDeterministicOrRandomSignature
{
    private HashMLDSASigner signer;
    private MLDSAParameters parameters;

    protected HashSignatureSpi(HashMLDSASigner signer)
    {
        super("HashMLDSA");
        
        this.signer = signer;
        this.parameters = null;
    }

    protected HashSignatureSpi(HashMLDSASigner signer, MLDSAParameters parameters)
    {
        super(MLDSAParameterSpec.fromName(parameters.getName()).getName());

        this.signer = signer;
        this.parameters = parameters;
    }

    @Override
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

    @Override
    protected void updateEngine(byte b)
        throws SignatureException
    {
        signer.update(b);
    }
    
    @Override
    protected void updateEngine(byte[] buf, int off, int len)
        throws SignatureException
    {
        signer.update(buf, off, len);
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

    @Override
    protected void reInitialize(boolean forSigning, CipherParameters params)
    {
        signer.init(forSigning, params);
    }

    public static class MLDSA
            extends HashSignatureSpi
    {
        public MLDSA()
        {
            super(new HashMLDSASigner());
        }
    }
    public static class MLDSA44
            extends HashSignatureSpi
    {
        public MLDSA44()
        {
            super(new HashMLDSASigner(), MLDSAParameters.ml_dsa_44_with_sha512);
        }
    }

    public static class MLDSA65
            extends HashSignatureSpi
    {
        public MLDSA65()
        {
            super(new HashMLDSASigner(), MLDSAParameters.ml_dsa_65_with_sha512);
        }
    }

    public static class MLDSA87
            extends HashSignatureSpi
    {
        public MLDSA87()
                throws NoSuchAlgorithmException
        {
            super(new HashMLDSASigner(), MLDSAParameters.ml_dsa_87_with_sha512);
        }
    }
}
