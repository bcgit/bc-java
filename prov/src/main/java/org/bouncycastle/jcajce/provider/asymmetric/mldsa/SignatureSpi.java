package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.MLDSAProxyPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

/**
 * JCA Signature SPI for ML-DSA (FIPS 204) and its context/pre-hash variants.
 * <p>
 * {@link #engineVerify(byte[])} returns <code>false</code> for a signature that is
 * cryptographically wrong <em>and</em> for one that is structurally malformed per FIPS 204
 * Algorithm 8 (wrong length, an out-of-order or duplicate hint index, or a hint weight exceeding
 * the parameter set's omega) - the two cases are not distinguished. This differs from some other
 * providers (e.g. the JDK's own SUN ML-DSA implementation), which throw
 * {@link java.security.SignatureException} for a decode failure and reserve <code>false</code>
 * for a well-formed-but-wrong signature; see
 * <a href="https://github.com/bcgit/bc-java/issues/2367">github #2367</a>. Code that needs to
 * distinguish "malformed" from "wrong" cannot rely on {@link java.security.Signature#verify(byte[])}
 * alone against this provider.
 * </p>
 */
public class SignatureSpi
    extends BaseDeterministicOrRandomSignature
{
    protected MLDSASigner signer;
    protected MLDSAParameters parameters;

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
        }
        else
        {
            try
            {
                SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
                this.keyParams = PublicKeyFactory.createKey(pubKeyInfo);
                publicKey = new BCMLDSAPublicKey((MLDSAPublicKeyParameters)this.keyParams);
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to ML-DSA");
            }
        }

        if (parameters != null)
        {
            String canonicalAlg = MLDSAParameterSpec.fromName(parameters.getName()).getName();
            if (!canonicalAlg.equals(publicKey.getAlgorithm()))
            {
                throw new InvalidKeyException("signature configured for " + canonicalAlg);
            }
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
        else if (privateKey instanceof MLDSAProxyPrivateKey && this instanceof MLDSACalcMu)
        {
            MLDSAProxyPrivateKey pKey = (MLDSAProxyPrivateKey)privateKey;
            MLDSAPublicKey key = pKey.getPublicKey();

            try
            {
                this.keyParams = PublicKeyFactory.createKey(key.getEncoded());
            }
            catch (IOException e)
            {
                throw new InvalidKeyException(e.getMessage());
            }

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

    public static class MLDSAExtMu
        extends SignatureSpi
    {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream(64);

        public MLDSAExtMu()
        {
            super(new MLDSASigner());
        }

        protected void updateEngine(byte b)
            throws SignatureException
        {
            bOut.write(b);
        }

        protected void updateEngine(byte[] b, int off, int len)
            throws SignatureException
        {
            bOut.write(b, off, len);
        }

        protected byte[] engineSign()
            throws SignatureException
        {
            try
            {
                byte[] mu = bOut.toByteArray();

                bOut.reset();

                return signer.generateMuSignature(mu);
            }
            catch (DataLengthException e)
            {
                throw new SignatureException(e.getMessage());
            }
            catch (Exception e)
            {
                throw new SignatureException(e.toString());
            }
        }

        protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException
        {
            byte[] mu = bOut.toByteArray();

            bOut.reset();

            try
            {
                return signer.verifyMuSignature(mu, sigBytes);
            }
            catch (DataLengthException e)
            {
                throw new SignatureException(e.getMessage());
            }
        }
    }

    public static class MLDSACalcMu
        extends SignatureSpi
    {
        public MLDSACalcMu()
        {
            super(new MLDSASigner());
        }

        protected byte[] engineSign()
            throws SignatureException
        {
            try
            {
                return signer.generateMu();
            }
            catch (Exception e)
            {
                throw new SignatureException(e.toString());
            }
        }

        protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException
        {
            return signer.verifyMu(sigBytes);
        }
    }
}
