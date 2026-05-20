package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.signers.HashMLDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

public class HashSignatureSpi
    extends BaseDeterministicOrRandomSignature
{
    protected final HashMLDSASigner signer;
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

    /**
     * External-hash form of HashML-DSA: bytes passed to Signature.update(...) are
     * treated as the pre-computed message digest, dispatched to
     * {@link HashMLDSASigner#generateSignature(byte[])} /
     * {@link HashMLDSASigner#verifySignature(byte[], byte[])}. Counterpart to
     * SignatureSpi.MLDSAExtMu (see github #2198).
     */
    public static class MLDSAExtHash
        extends HashSignatureSpi
    {
        private final ByteArrayOutputStream bOut = new ByteArrayOutputStream(64);

        public MLDSAExtHash()
        {
            super(new HashMLDSASigner());
        }

        protected MLDSAExtHash(MLDSAParameters parameters)
        {
            super(new HashMLDSASigner(), parameters);
        }

        @Override
        protected void updateEngine(byte b)
        {
            bOut.write(b);
        }

        @Override
        protected void updateEngine(byte[] buf, int off, int len)
        {
            bOut.write(buf, off, len);
        }

        @Override
        protected byte[] engineSign()
            throws SignatureException
        {
            byte[] hash = bOut.toByteArray();
            bOut.reset();
            try
            {
                return signer.generateSignature(hash);
            }
            catch (IllegalArgumentException e)
            {
                throw new SignatureException(e.getMessage());
            }
            catch (Exception e)
            {
                throw new SignatureException(e.toString());
            }
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException
        {
            byte[] hash = bOut.toByteArray();
            bOut.reset();
            try
            {
                return signer.verifySignature(hash, sigBytes);
            }
            catch (IllegalArgumentException e)
            {
                throw new SignatureException(e.getMessage());
            }
        }
    }

    public static class MLDSA44ExtHash
        extends MLDSAExtHash
    {
        public MLDSA44ExtHash()
        {
            super(MLDSAParameters.ml_dsa_44_with_sha512);
        }
    }

    public static class MLDSA65ExtHash
        extends MLDSAExtHash
    {
        public MLDSA65ExtHash()
        {
            super(MLDSAParameters.ml_dsa_65_with_sha512);
        }
    }

    public static class MLDSA87ExtHash
        extends MLDSAExtHash
    {
        public MLDSA87ExtHash()
        {
            super(MLDSAParameters.ml_dsa_87_with_sha512);
        }
    }

}
