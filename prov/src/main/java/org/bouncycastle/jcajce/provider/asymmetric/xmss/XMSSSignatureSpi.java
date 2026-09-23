package org.bouncycastle.jcajce.provider.asymmetric.xmss;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
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
    private ASN1ObjectIdentifier treeDigest;
    // the attributes of the key engineInitSign was given, so the key getUpdatedPrivateKey()
    // hands back is the same key rather than one stripped of them
    private ASN1Set attributes;
    private ASN1ObjectIdentifier[] treeDigests;
    // whether the last init was for signing. treeDigest says this object has been given a private
    // key at some point, which a verification init does not take back: the signer keeps the key
    // across one so that sign, verify, then collect the advanced state is a sequence a caller can
    // drive, and this is what stops isSigningCapable() answering true while it is verifying.
    private boolean signing;

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
        BCXMSSPublicKey xmssKey;

        if (publicKey instanceof BCXMSSPublicKey)
        {
            xmssKey = (BCXMSSPublicKey)publicKey;
        }
        else
        {
            // a key from elsewhere - the deprecated org.bouncycastle.pqc.jcajce.provider.xmss copy, or another provider - is taken through its encoding; verification is stateless, so unlike a private key it can be rebuilt here.
            try
            {
                xmssKey = new BCXMSSPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to XMSS");
            }
        }

        checkTreeDigest(xmssKey.getTreeDigestOID());

        CipherParameters param = xmssKey.getKeyParams();

        signing = false;
        digest.reset();
        signer.init(false, param);
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
        initSigning(privateKey, random);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        initSigning(privateKey, null);
    }

    // the random travels as an argument rather than in a field: held in one, a random supplied to
    // an earlier initSign(key, random) on this object would still be wrapping the key on a later
    // initSign(key) that named none
    private void initSigning(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        if (privateKey instanceof BCXMSSPrivateKey)
        {
            if (((BCXMSSPrivateKey)privateKey).isDestroyed())
            {
                throw new InvalidKeyException("key destroyed");
            }

            checkTreeDigest(((BCXMSSPrivateKey)privateKey).getTreeDigestOID());

            CipherParameters param = ((BCXMSSPrivateKey)privateKey).getKeyParams();

            treeDigest = ((BCXMSSPrivateKey)privateKey).getTreeDigestOID();
            attributes = ((BCXMSSPrivateKey)privateKey).getAttributes();
            if (random != null)
            {
                param = new ParametersWithRandom(param, random);
            }

            signing = true;
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
            signer.update(hash, 0, hash.length);

            byte[] sig = signer.generateSignature();

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
        byte[] hash = DigestUtil.getDigestResult(digest);

        try
        {
            signer.update(hash, 0, hash.length);

            return signer.verifySignature(sigBytes);
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
        return signing && signer.getUsagesRemaining() != 0;
    }

    public PrivateKey getUpdatedPrivateKey()
    {
        // the signer is asked rather than a field of this object being read: what it hands back is
        // null exactly when there is nothing left to hand back - never initialised for signing, or
        // a signature made and its key already collected. Clearing treeDigest here made a collection
        // that followed no signature look like an exhausted object, when what the signer keeps in
        // that case is a one-usage shard of the leaf the collected key has been advanced past.
        //
        // That is a different question from the one isSigningCapable() answers, and the two do part
        // company: it asks the signer for a count, this asks whether it holds a key at all, and a
        // signer initialised on a spent key holds one. Measured, that signer answers false to
        // isSigningCapable() and hands a key back from here - deliberately, because a spent key is
        // still state its caller has to store. So a key from here is not a statement that anything
        // is left to sign with; only isSigningCapable() says that.
        XMSSPrivateKeyParameters updated = (treeDigest == null)
            ? null : (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

        if (updated == null)
        {
            throw new IllegalStateException("signature object not in a signing state");
        }

        return new BCXMSSPrivateKey(treeDigest, updated, attributes);
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
