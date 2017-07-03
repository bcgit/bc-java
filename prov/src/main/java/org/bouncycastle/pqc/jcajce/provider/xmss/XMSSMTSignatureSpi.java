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
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
import org.bouncycastle.pqc.jcajce.interfaces.StatefulSignature;

public class XMSSMTSignatureSpi
    extends Signature
    implements StatefulSignature
{
    protected XMSSMTSignatureSpi(String algorithm)
    {
        super(algorithm);
    }

    private Digest digest;
    private XMSSMTSigner signer;
    private ASN1ObjectIdentifier treeDigest;
    private SecureRandom random;

    protected XMSSMTSignatureSpi(String sigName, Digest digest, XMSSMTSigner signer)
    {
        super(sigName);

        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCXMSSMTPublicKey)
        {
            CipherParameters param = ((BCXMSSMTPublicKey)publicKey).getKeyParams();

            treeDigest = null;
            digest.reset();
            signer.init(false, param);
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to XMSSMT");
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
        if (privateKey instanceof BCXMSSMTPrivateKey)
        {
            CipherParameters param = ((BCXMSSMTPrivateKey)privateKey).getKeyParams();

            treeDigest = ((BCXMSSMTPrivateKey)privateKey).getTreeDigestOID();
            if (random != null)
            {
                param = new ParametersWithRandom(param, random);
            }

            digest.reset();
            signer.init(true, param);
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to XMSSMT");
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
        if (treeDigest == null)
        {
            throw new IllegalStateException("signature object not in a signing state");
        }
        PrivateKey rKey = new BCXMSSMTPrivateKey(treeDigest, (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey());

        treeDigest = null;

        return rKey;
    }

    static public class withSha256
        extends XMSSMTSignatureSpi
    {
        public withSha256()
        {
            super("SHA256withXMSSMT", new SHA256Digest(), new XMSSMTSigner());
        }
    }

    static public class withSha3_256
        extends XMSSMTSignatureSpi
    {
        public withSha3_256()
        {
            super("SHA256withXMSSMT", new SHA3Digest(256), new XMSSMTSigner());
        }
    }

    static public class withSha512
        extends XMSSMTSignatureSpi
    {
        public withSha512()
        {
            super("SHA256withXMSSMT", new SHA512Digest(), new XMSSMTSigner());
        }
    }

    static public class withSha3_512
        extends XMSSMTSignatureSpi
    {
        public withSha3_512()
        {
            super("SHA256withXMSSMT", new SHA3Digest(512), new XMSSMTSigner());
        }
    }
}
