package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
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
    private ASN1ObjectIdentifier[] treeDigests;

    protected XMSSSignatureSpi(String sigName, Digest digest, XMSSSigner signer)
    {
        this(sigName, digest, signer, null);
    }

    protected XMSSSignatureSpi(String sigName, Digest digest, XMSSSigner signer, ASN1ObjectIdentifier[] treeDigests)
    {
        super(sigName);

        this.digest = digest;
        this.signer = signer;
        this.treeDigests = treeDigests;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCXMSSPublicKey)
        {
            checkTreeDigest(((BCXMSSPublicKey)publicKey).getTreeDigestOID());

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

    // Only the tree-digest-named signers (XMSS-SHA256, XMSS-SHAKE256, ...) constrain the key: they
    // supply a treeDigests allowlist and reject a key whose tree digest is outside it. SHAKE256-LEN
    // (the SP 800-208 SHAKE256/256 and SHAKE256/192 sets) is part of the SHAKE256 family and
    // SHA-256/192 shares id-sha256 with SHA-256/256, so both are accepted by their respective named
    // signers. The generic "XMSS" signer and the "...withXMSS-..." prehash signers pass null (any
    // key accepted) - for the prehash variants the leading digest names the message pre-hash, which
    // is independent of the key's tree digest.
    private void checkTreeDigest(ASN1ObjectIdentifier keyTreeDigest)
        throws InvalidKeyException
    {
        if (treeDigests == null)
        {
            return;
        }
        for (int i = 0; i != treeDigests.length; i++)
        {
            if (treeDigests[i].equals(keyTreeDigest))
            {
                return;
            }
        }
        throw new InvalidKeyException("key with tree digest " + keyTreeDigest + " not valid for " + getAlgorithm());
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
            checkTreeDigest(((BCXMSSPrivateKey)privateKey).getTreeDigestOID());

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
            super("XMSS-SHA256", new NullDigest(), new XMSSSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_sha256 });
        }
    }

    static public class withShake128
        extends XMSSSignatureSpi
    {
        public withShake128()
        {
            super("XMSS-SHAKE128", new NullDigest(), new XMSSSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_shake128 });
        }
    }

    static public class withSha512
        extends XMSSSignatureSpi
    {
        public withSha512()
        {
            super("XMSS-SHA512", new NullDigest(), new XMSSSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_sha512 });
        }
    }

    static public class withShake256
        extends XMSSSignatureSpi
    {
        public withShake256()
        {
            super("XMSS-SHAKE256", new NullDigest(), new XMSSSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_shake256, NISTObjectIdentifiers.id_shake256_len });
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
            super("SHAKE128withXMSS-SHAKE128", new SHAKEDigest(128), new XMSSSigner());
        }
    }

    static public class withShake128_512andPrehash
        extends XMSSSignatureSpi
    {
        public withShake128_512andPrehash()
        {
            super("SHAKE128(512)withXMSS-SHAKE128", new DigestUtil.DoubleDigest(new SHAKEDigest(128)), new XMSSSigner());
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

    static public class withShake256_1024andPrehash
        extends XMSSSignatureSpi
    {
        public withShake256_1024andPrehash()
        {
            super("SHAKE256(1024)withXMSS-SHAKE256", new DigestUtil.DoubleDigest(new SHAKEDigest(256)), new XMSSSigner());
        }
    }
}
