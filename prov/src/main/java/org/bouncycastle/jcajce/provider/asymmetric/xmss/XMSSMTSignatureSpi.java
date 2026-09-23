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
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;

public class XMSSMTSignatureSpi
    extends Signature
    implements StateAwareSignature
{
    protected XMSSMTSignatureSpi(String algorithm)
    {
        super(algorithm);
    }

    private Digest digest;
    private XMSSMTSigner signer;
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

    protected XMSSMTSignatureSpi(String sigName, Digest digest, XMSSMTSigner signer)
    {
        this(sigName, digest, signer, null);
    }

    protected XMSSMTSignatureSpi(String sigName, Digest digest, XMSSMTSigner signer, ASN1ObjectIdentifier[] treeDigests)
    {
        super(sigName);

        this.digest = digest;
        this.signer = signer;
        this.treeDigests = treeDigests;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        BCXMSSMTPublicKey xmssKey;

        if (publicKey instanceof BCXMSSMTPublicKey)
        {
            xmssKey = (BCXMSSMTPublicKey)publicKey;
        }
        else
        {
            // a key from elsewhere - the deprecated org.bouncycastle.pqc.jcajce.provider.xmss copy, or another provider - is taken through its encoding; verification is stateless, so unlike a private key it can be rebuilt here.
            try
            {
                xmssKey = new BCXMSSMTPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to XMSSMT");
            }
        }

        checkTreeDigest(xmssKey.getTreeDigestOID());

        CipherParameters param = xmssKey.getKeyParams();

        signing = false;
        digest.reset();
        signer.init(false, param);
    }

    // Only the tree-digest-named signers (XMSSMT-SHA256, XMSSMT-SHAKE256, ...) constrain the key:
    // they supply a treeDigests allowlist and reject a key whose tree digest is outside it.
    // SHAKE256-LEN (the SP 800-208 SHAKE256/256 and SHAKE256/192 sets) is part of the SHAKE256 family
    // and SHA-256/192 shares id-sha256 with SHA-256/256, so both are accepted by their respective
    // named signers. The generic "XMSSMT" signer and the "...withXMSSMT-..." prehash signers pass
    // null (any key accepted) - for the prehash variants the leading digest names the message
    // pre-hash, which is independent of the key's tree digest.
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
        if (privateKey instanceof BCXMSSMTPrivateKey)
        {
            if (((BCXMSSMTPrivateKey)privateKey).isDestroyed())
            {
                throw new InvalidKeyException("key destroyed");
            }

            checkTreeDigest(((BCXMSSMTPrivateKey)privateKey).getTreeDigestOID());

            CipherParameters param = ((BCXMSSMTPrivateKey)privateKey).getKeyParams();

            treeDigest = ((BCXMSSMTPrivateKey)privateKey).getTreeDigestOID();
            attributes = ((BCXMSSMTPrivateKey)privateKey).getAttributes();
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
        XMSSMTPrivateKeyParameters updated = (treeDigest == null)
            ? null : (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

        if (updated == null)
        {
            throw new IllegalStateException("signature object not in a signing state");
        }

        return new BCXMSSMTPrivateKey(treeDigest, updated, attributes);
    }

    static public class generic
        extends XMSSMTSignatureSpi
    {
        public generic()
        {
            super("XMSSMT", new NullDigest(), new XMSSMTSigner());
        }
    }
    
    static public class withSha256
        extends XMSSMTSignatureSpi
    {
        public withSha256()
        {
            super("XMSSMT-SHA256", new NullDigest(), new XMSSMTSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_sha256 });
        }
    }

    static public class withShake128
        extends XMSSMTSignatureSpi
    {
        public withShake128()
        {
            super("XMSSMT-SHAKE128", new NullDigest(), new XMSSMTSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_shake128 });
        }
    }

    static public class withSha512
        extends XMSSMTSignatureSpi
    {
        public withSha512()
        {
            super("XMSSMT-SHA512", new NullDigest(), new XMSSMTSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_sha512 });
        }
    }

    static public class withShake256
        extends XMSSMTSignatureSpi
    {
        public withShake256()
        {
            super("XMSSMT-SHAKE256", new NullDigest(), new XMSSMTSigner(), new ASN1ObjectIdentifier[]{ NISTObjectIdentifiers.id_shake256, NISTObjectIdentifiers.id_shake256_len });
        }
    }

    static public class withSha256andPrehash
        extends XMSSMTSignatureSpi
    {
        public withSha256andPrehash()
        {
            super("SHA256withXMSSMT-SHA256", new SHA256Digest(), new XMSSMTSigner());
        }
    }

    static public class withShake128andPrehash
        extends XMSSMTSignatureSpi
    {
        public withShake128andPrehash()
        {
            super("SHAKE128withXMSSMT-SHAKE128", new SHAKEDigest(128), new XMSSMTSigner());
        }
    }

    static public class withShake128_512andPrehash
        extends XMSSMTSignatureSpi
    {
        public withShake128_512andPrehash()
        {
            super("SHAKE128(512)withXMSSMT-SHAKE128", new DigestUtil.DoubleDigest(new SHAKEDigest(128)), new XMSSMTSigner());
        }
    }

    static public class withSha512andPrehash
        extends XMSSMTSignatureSpi
    {
        public withSha512andPrehash()
        {
            super("SHA512withXMSSMT-SHA512", new SHA512Digest(), new XMSSMTSigner());
        }
    }

    static public class withShake256andPrehash
        extends XMSSMTSignatureSpi
    {
        public withShake256andPrehash()
        {
            super("SHAKE256withXMSSMT-SHAKE256", new SHAKEDigest(256), new XMSSMTSigner());
        }
    }

    static public class withShake256_1024andPrehash
        extends XMSSMTSignatureSpi
    {
        public withShake256_1024andPrehash()
        {
            super("SHAKE256(1024)withXMSSMT-SHAKE256", new DigestUtil.DoubleDigest(new SHAKEDigest(256)), new XMSSMTSigner());
        }
    }
}
