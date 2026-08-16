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

/**
 * JCA Signature SPI for the pre-hash ("ExtHash") ML-DSA (FIPS 204) variants.
 * <p>
 * As with the plain {@link SignatureSpi}, a structurally malformed signature (wrong length, or a
 * FIPS 204 Algorithm 8 hint-decode failure) and a well-formed-but-cryptographically-wrong
 * signature both make {@code engineVerify(byte[])} return <code>false</code>; only an invalid
 * caller-supplied external-digest length throws {@link java.security.SignatureException}. See
 * <a href="https://github.com/bcgit/bc-java/issues/2367">github #2367</a>.
 * </p>
 */
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

            checkKeyParameters(parameters, key.getKeyParams().getParameters());
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to ML-DSA");
        }
    }

    /**
     * FIPS 204 sec. 5 defines one key generation algorithm per parameter set, and a key it produces
     * carries no commitment to pure ML-DSA over HashML-DSA, so a <b>pure</b> key of the matching
     * parameter set is admissible on this pre-hash path. That matters in practice because a key
     * recovered from an X.509 certificate carries the pure OID (RFC 9881), and was previously
     * refused by these SPIs (see <a href="https://github.com/bcgit/bc-java/issues/2397">github
     * #2397</a>).
     * <p>
     * The tolerance is deliberately one way only. A key that already names a HashML-DSA parameter
     * set has been narrowed to the pre-hash mode, so it stays refused by the pure
     * {@link SignatureSpi} and is accepted here only when it names this SPI's own pre-hash variant.
     * A key of a different parameter set is refused either way, which is the check worth having.
     * </p>
     */
    static void checkKeyParameters(MLDSAParameters parameters, MLDSAParameters keyParameters)
        throws InvalidKeyException
    {
        if (parameters == null)
        {
            return;
        }

        if (parameters.getK() != keyParameters.getK()
            || (keyParameters.isPreHash() && keyParameters.getType() != parameters.getType()))
        {
            throw new InvalidKeyException("signature configured for "
                + MLDSAParameterSpec.fromName(parameters.getName()).getName());
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

            checkKeyParameters(parameters, key.getKeyParams().getParameters());
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
