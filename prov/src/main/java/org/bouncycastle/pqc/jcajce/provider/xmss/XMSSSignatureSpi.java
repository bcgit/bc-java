package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;

public class XMSSSignatureSpi
    extends Signature
    implements StateAwareSignature
{
    protected XMSSSignatureSpi(String algorithm)
    {
        super(algorithm);
    }

    private Digest digest;
    private XMSSSigner signer;
    private SecureRandom random;
    private ASN1ObjectIdentifier treeDigest;

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

            treeDigest = null;
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

            treeDigest = ((BCXMSSPrivateKey)privateKey).getTreeDigestOID();
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

    public boolean isSigningCapable()
    {
        return treeDigest != null && signer.getUsagesRemaining() != 0;
    }

    public PrivateKey getUpdatedPrivateKey()
    {
        if (treeDigest == null)
        {
            throw new IllegalStateException("signature object not in a signing state");
        }
        PrivateKey rKey = new BCXMSSPrivateKey(treeDigest, (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey());

        treeDigest = null;

        return rKey;
    }

    static public class generic
        extends XMSSSignatureSpi
    {
        public generic()
        {
            super("XMSS", new NullDigest(), new XMSSSigner());
        }
    }

    static public class withSha256
        extends XMSSSignatureSpi
    {
        public withSha256()
        {
            super("XMSS-SHA256", new NullDigest(), new XMSSSigner());
        }
    }

    static public class withShake128
        extends XMSSSignatureSpi
    {
        public withShake128()
        {
            super("XMSS-SHAKE128", new NullDigest(), new XMSSSigner());
        }
    }

    static public class withSha512
        extends XMSSSignatureSpi
    {
        public withSha512()
        {
            super("XMSS-SHA512", new NullDigest(), new XMSSSigner());
        }
    }

    static public class withShake256
        extends XMSSSignatureSpi
    {
        public withShake256()
        {
            super("XMSS-SHAKE256", new NullDigest(), new XMSSSigner());
        }
    }

    static public class withSha256andPrehash
        extends XMSSSignatureSpi
    {
        public withSha256andPrehash()
        {
            super("SHA256withXMSS-SHA256", new SHA256Digest(), new XMSSSigner());
        }
    }

    static public class withShake128andPrehash
        extends XMSSSignatureSpi
    {
        public withShake128andPrehash()
        {
            super("SHAKE128withXMSSMT-SHAKE128", new SHAKEDigest(128), new XMSSSigner());
        }
    }

    static public class withSha512andPrehash
        extends XMSSSignatureSpi
    {
        public withSha512andPrehash()
        {
            super("SHA512withXMSS-SHA512", new SHA512Digest(), new XMSSSigner());
        }
    }

    static public class withShake256andPrehash
        extends XMSSSignatureSpi
    {
        public withShake256andPrehash()
        {
            super("SHAKE256withXMSS-SHAKE256", new SHAKEDigest(256), new XMSSSigner());
        }
    }
}
