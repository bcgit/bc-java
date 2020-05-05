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
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.lms.LMOtsContextBasedSigner;
import org.bouncycastle.pqc.crypto.lms.LMOtsContextBasedVerifier;
import org.bouncycastle.pqc.crypto.lms.LMSContext;

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

    private LMOtsContextBasedSigner lmOtsSigner;
    private LMOtsContextBasedVerifier lmOtsVerifier;

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
            lmOtsVerifier = (LMOtsContextBasedVerifier)((BCLMSPublicKey)publicKey).getKeyParams();
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to XMSS");
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
            lmOtsSigner = (LMOtsContextBasedSigner)((BCLMSPrivateKey)privateKey).getKeyParams();
            digest = null;
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to XMSS");
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        if (digest == null)
        {
            digest = lmOtsSigner.generateLMSContext();
        }
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        if (digest == null)
        {
            digest = lmOtsSigner.generateLMSContext();
        }
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        if (digest == null)
        {
            digest = lmOtsSigner.generateLMSContext();
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
                throw new SignatureException(e.getMessage(), e);
            }
            throw new SignatureException(e.toString(), e);
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        LMSContext context = lmOtsVerifier.generateLMSContext(sigBytes);

        byte[] hash = DigestUtil.getDigestResult(digest);

        context.update(hash, 0, hash.length);

        return lmOtsVerifier.verify(context);
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
