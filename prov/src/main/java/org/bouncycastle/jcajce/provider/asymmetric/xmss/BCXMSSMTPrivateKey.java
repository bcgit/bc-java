package org.bouncycastle.jcajce.provider.asymmetric.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import org.bouncycastle.util.Exceptions;

public class BCXMSSMTPrivateKey
    implements PrivateKey, XMSSMTPrivateKey, Destroyable
{
    private static final long serialVersionUID = 7682140473044521395L;

    private transient ASN1ObjectIdentifier treeDigest;
    private transient XMSSMTPrivateKeyParameters keyParams;
    private transient ASN1Set attributes;

    public BCXMSSMTPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSMTPrivateKeyParameters keyParams)
    {
        this(treeDigest, keyParams, null);
    }

    /**
     * As above, carrying the PKCS#8 attributes of the key this one was derived from.
     * <p>
     * The two-argument form is for a key that has no such origin - key pair generation - and the
     * attributes it leaves null are what {@link #getEncoded()} writes. Every other caller is
     * re-wrapping a key that already exists, and had been reaching this class through that form:
     * {@code extractKeyShard} below and the {@code getUpdatedPrivateKey()} of the signature SPI,
     * which is the StateAwareSignature contract's own way of taking the key back after signing.
     * So a key loaded from a PKCS#8 carrying attributes lost them on being signed with once, or
     * on being sharded once, with nothing to say so.
     * </p>
     */
    BCXMSSMTPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSMTPrivateKeyParameters keyParams,
        ASN1Set attributes)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
        this.attributes = attributes;
    }

    public BCXMSSMTPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        // Derive the tree digest from the recovered key rather than the AlgorithmIdentifier
        // parameters: the RFC 9802 form (id-alg-xmssmt-hashsig) carries no XMSSMTKeyParams, so
        // reading them would NPE. Mirrors BCXMSSMTPublicKey.init.
        this.keyParams = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.treeDigest = DigestUtil.getDigestOID(keyParams.getTreeDigest());
    }

    public long getIndex()
    {
        // both reads under the key's own monitor, so a signature in between cannot split them
        synchronized (keyParams)
        {
            if (keyParams.getUsagesRemaining() == 0)
            {
                throw new IllegalStateException("key exhausted");
            }

            return keyParams.getIndex();
        }
    }

    public long getUsagesRemaining()
    {
        return keyParams.getUsagesRemaining();
    }

    public XMSSMTPrivateKey extractKeyShard(int usageCount)
    {
        return new BCXMSSMTPrivateKey(this.treeDigest, keyParams.extractKeyShard(usageCount), this.attributes);
    }

    public String getAlgorithm()
    {
        return "XMSSMT";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * The PKCS#8 attributes this key carries, for the signature SPI to put on the key it hands
     * back from getUpdatedPrivateKey().
     */
    ASN1Set getAttributes()
    {
        return attributes;
    }

    public byte[] getEncoded()
    {
        if (keyParams.isDestroyed())
        {
            throw new IllegalStateException("key destroyed");
        }

        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParams, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    /**
     * Whether these are the same key at the same position, which for a stateful key means the same
     * traversal state too - the whole of which {@link XMSSMTPrivateKeyParameters#equals(Object)}
     * decides, this being the line that asks it.
     * <p>
     * It was written out here, over the accessors, and none of it belonged here: the fields it
     * reads are the key parameters' own, the monitor a signature is taken under is the key
     * parameters' own, and each accessor hands out a clone rather than a value that could be held
     * still beside another key's. {@code BCLMSPrivateKey} is this same line over
     * {@code HSSPrivateKeyParameters}, which is where the other stateful family in this provider
     * keeps the same reasoning.
     * </p><p>
     * The tree digest this class carries alongside the key parameters is not compared, because
     * comparing it decides nothing: it is {@code keyParams.getParameters().getTreeDigestOID()} at
     * every route a key here is constructed by, and that is the OID the key parameters compare.
     * </p><p>
     * The PKCS#8 attributes are not compared either, and that one does change what {@code equals}
     * says about two keys {@link #getEncoded()} writes differently: attributes travel into the
     * encoding, so one key loaded from a PKCS#8 carrying a friendlyName and one built from the
     * same secret without it are equal here and encode to different bytes. That is the answer this
     * class wants. What a stateful key is asked here is whether this is the same key at the same
     * position - the question a one-time key signing twice is the failure of, RFC 8391 sec. 1.1 -
     * and a label a caller attached on the way through a keystore moves neither the secret nor the
     * index. {@code BCLMSPrivateKey}, which carries attributes the same way and is where this
     * comparison came from, leaves them out for the same reason, as does {@code BCMLDSAPrivateKey}
     * over its own parameters' encoding. A caller that does need the encodings to agree should
     * compare the encodings.
     * </p>
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSMTPrivateKey)
        {
            BCXMSSMTPrivateKey otherKey = (BCXMSSMTPrivateKey)o;

            // a destroyed key no longer exposes its value, so it is only equal to itself. Ahead of
            // the delegation because the key parameters' own equals() reads the secret arrays as
            // fields rather than through the checked accessors, so it would find two destroyed keys
            // equal on their zeroized copies.
            if (isDestroyed() || otherKey.isDestroyed())
            {
                return false;
            }

            return keyParams.equals(otherKey.keyParams);
        }

        return false;
    }

    public int hashCode()
    {
        return keyParams.hashCode();
    }

    ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigest;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public int getLayers()
    {
        return keyParams.getParameters().getLayers();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest, keyParams.getParameters().getTreeDigestSize());
    }

    /**
     * Destroy this key, zeroizing the secret key material it holds.
     * <p>
     * The secret key seed, the PRF key and the WOTS+ secrets retained by the per-layer BDS
     * traversal states are zeroized; the public seed, root, index and tree nodes are retained, so
     * {@link #getIndex()}, {@link #getUsagesRemaining()}, {@link #getHeight()},
     * {@link #getLayers()} and {@link #getTreeDigest()} keep working and {@link #hashCode()} is
     * stable. After destruction {@link #isDestroyed()} returns true, {@link #getEncoded()} and
     * {@link #extractKeyShard(int)} throw {@link IllegalStateException}, the key can no longer be
     * serialized, and a Signature refuses it at initSign. Shards extracted before destruction hold
     * their own copies of the seeds and are unaffected. As the underlying
     * {@link XMSSMTPrivateKeyParameters} object is destroyed, keys sharing it are invalidated too.
     */
    public synchronized void destroy()
    {
        keyParams.destroy();
    }

    public boolean isDestroyed()
    {
        return keyParams.isDestroyed();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        try
        {
            out.writeObject(this.getEncoded());
        }
        catch (IllegalStateException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }
}
