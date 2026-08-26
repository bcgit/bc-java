package org.bouncycastle.pqc.jcajce.provider.lms;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.crypto.signers.lms.LMSContext;
import org.bouncycastle.crypto.signers.LMSContextBasedSigner;
import org.bouncycastle.crypto.signers.LMSContextBasedVerifier;

public class LMSSignatureSpi
    extends Signature
{
    protected LMSSignatureSpi(String algorithm)
    {
        super(algorithm);
    }

    private Digest digest;
    private MessageSigner signer;
    private SecureRandom random;

    private LMSContextBasedSigner lmOtsSigner;
    private LMSContextBasedVerifier lmOtsVerifier;

    protected LMSSignatureSpi(String sigName, Digest digest)
    {
        super(sigName);

        this.digest = digest;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCLMSPublicKey)
        {
            digest = new NullDigest();
            
            digest.reset();
            lmOtsVerifier = (LMSContextBasedVerifier)((BCLMSPublicKey)publicKey).getKeyParams();
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to LMS");
        }
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
        if (privateKey instanceof BCLMSPrivateKey)
        {
            lmOtsSigner = (LMSContextBasedSigner)((BCLMSPrivateKey)privateKey).getKeyParams();
            if (lmOtsSigner.getUsagesRemaining() == 0)
            {
                throw new InvalidKeyException("private key exhausted");
            }
            digest = null;
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to LMS");
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        if (digest == null)
        {
            digest = getSigner();
        }
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        if (digest == null)
        {
            digest = getSigner();
        }
        digest.update(b, off, len);
    }

    private Digest getSigner()
        throws SignatureException
    {
        try
        {
            return lmOtsSigner.generateLMSContext();
        }
        catch (ExhaustedPrivateKeyException e)
        {
            throw SecurityExceptions.signatureException(e.getMessage(), e);
        }
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        if (digest == null)
        {
            digest = getSigner();
        }

        try
        {
            byte[] sig = lmOtsSigner.generateSignature((LMSContext)digest);

            digest = null;
            
            return sig;
        }
        catch (Exception e)
        {
            if (e instanceof IllegalStateException)
            {
                throw SecurityExceptions.signatureException(e.getMessage(), e);
            }
            throw SecurityExceptions.signatureException(e.toString(), e);
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        try
        {
            LMSContext context;

            // only the decode is guarded: past it the engine reports an inconsistent signature by
            // returning false rather than by throwing, so a wider catch would swallow genuine
            // internal errors without covering anything the narrow one misses.
            try
            {
                context = lmOtsVerifier.generateLMSContext(sigBytes);
            }
            catch (IllegalArgumentException e)
            {
                // the signature decoded, but names an OTS type other than the one the key was
                // generated for: this engine cannot process it, which the JCA reports as a
                // SignatureException rather than as a verification failure.
                throw SecurityExceptions.signatureException(e.getMessage(), e);
            }
            catch (RuntimeException e)
            {
                // a signature that will not decode at all is simply not a valid signature - the
                // JCA contract is to say so rather than to let the lightweight API's unchecked
                // exception escape (see ML-DSA, SLH-DSA, XMSS).
                return false;
            }

            byte[] hash = DigestUtil.getDigestResult(digest);

            context.update(hash, 0, hash.length);

            return lmOtsVerifier.verify(context);
        }
        finally
        {
            // however this method leaves, the accumulated message is consumed and the signature
            // object goes back to the state initVerify left it in, ready for fresh data. On the
            // success path getDigestResult() has already reset it, so this is then a no-op.
            digest.reset();
        }
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

    static public class generic
        extends LMSSignatureSpi
    {
        public generic()
        {
            super("LMS", new NullDigest());
        }
    }
}
