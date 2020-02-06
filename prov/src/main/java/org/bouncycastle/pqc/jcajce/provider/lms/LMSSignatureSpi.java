package org.bouncycastle.pqc.jcajce.provider.lms;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSSigner;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;

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
            CipherParameters param = ((BCLMSPublicKey)publicKey).getKeyParams();

            digest.reset();

            if (param instanceof LMSPublicKeyParameters)
            {
                signer = new LMSSigner();
            }
            else
            {
                signer = new HSSSigner();
            }

            signer.init(false, param);
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
            CipherParameters param = ((BCLMSPrivateKey)privateKey).getKeyParams();

            if (param instanceof HSSPrivateKeyParameters)
            {
                if (random != null)
                {
                    param = new ParametersWithRandom(param, random);
                }
                signer = new HSSSigner();
            }
            else
            {
                signer = new LMSSigner();
            }

            digest.reset();
            signer.init(true, param);
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to XMSS");
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[] hash = DigestUtil.getDigestResult(digest);

        try
        {
            byte[] sig = signer.generateSignature(hash);

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
        byte[] hash = DigestUtil.getDigestResult(digest);

        return signer.verifySignature(hash, sigBytes);
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
