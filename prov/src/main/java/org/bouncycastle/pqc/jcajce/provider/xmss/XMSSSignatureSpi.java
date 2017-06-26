package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.jcajce.interfaces.StatefulSignature;

public class XMSSSignatureSpi
    extends Signature
    implements StatefulSignature
{
    protected XMSSSignatureSpi(String algorithm)
    {
        super(algorithm);
    }

    private Digest digest;
    private XMSSSigner signer;
    private SecureRandom random;

    protected XMSSSignatureSpi(String sigName, Digest digest, XMSSSigner signer)
    {
        super(sigName);

        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCXMSSPublicKey)
        {
            CipherParameters param = ((BCXMSSPublicKey)publicKey).getKeyParams();

            digest.reset();
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
        if (privateKey instanceof BCXMSSPrivateKey)
        {
            CipherParameters param = ((BCXMSSPrivateKey)privateKey).getKeyParams();

            if (random != null)
            {
                param = new ParametersWithRandom(param, random);
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
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        try
        {
            byte[] sig = signer.generateSignature(hash);

            return sig;
        }
        catch (Exception e)
        {
            if (e instanceof IllegalStateException)
            {
                throw new SignatureException(e.getMessage());
            }
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return signer.verifySignature(hash, sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
    {
        // TODO
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href =
     * "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)"
     * >
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

    public PrivateKey getUpdatedPrivateKey()
    {
        return new BCXMSSPrivateKey((XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey());
    }

    static public class withSha256
        extends XMSSSignatureSpi
    {
        public withSha256()
        {
            super("SHA256withXMSS", new SHA256Digest(), new XMSSSigner());
        }
    }

    static public class withSha3_256
        extends XMSSSignatureSpi
    {
        public withSha3_256()
        {
            super("SHA256withXMSS", new SHA3Digest(256), new XMSSSigner());
        }
    }

    static public class withSha512
        extends XMSSSignatureSpi
    {
        public withSha512()
        {
            super("SHA256withXMSS", new SHA512Digest(), new XMSSSigner());
        }
    }

    static public class withSha3_512
        extends XMSSSignatureSpi
    {
        public withSha3_512()
        {
            super("SHA256withXMSS", new SHA3Digest(512), new XMSSSigner());
        }
    }
}
