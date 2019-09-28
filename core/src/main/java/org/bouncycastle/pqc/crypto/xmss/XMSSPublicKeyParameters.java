package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;

import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS Public Key.
 */
public final class XMSSPublicKeyParameters
    extends XMSSKeyParameters
    implements XMSSStoreableObjectInterface, Encodable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    private final int oid;
    private final byte[] root;
    private final byte[] publicSeed;

    private XMSSPublicKeyParameters(Builder builder)
    {
        super(false, builder.params.getTreeDigest());
        params = builder.params;
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        int n = params.getTreeDigestSize();
        byte[] publicKey = builder.publicKey;
        if (publicKey != null)
        {
            /* import */
            int oidSize = 4;
            int rootSize = n;
            int publicSeedSize = n;
            // updated key
            int position = 0;
            // pre-rfc final key without OID.
            if (publicKey.length == rootSize + publicSeedSize)
            {
                oid = 0;
                root = XMSSUtil.extractBytesAtOffset(publicKey, position, rootSize);
                position += rootSize;
                publicSeed = XMSSUtil.extractBytesAtOffset(publicKey, position, publicSeedSize);
            }
            else if (publicKey.length == oidSize + rootSize + publicSeedSize)
            {
                oid = Pack.bigEndianToInt(publicKey, 0);
                position += oidSize;
                root = XMSSUtil.extractBytesAtOffset(publicKey, position, rootSize);
                position += rootSize;
                publicSeed = XMSSUtil.extractBytesAtOffset(publicKey, position, publicSeedSize);
            }
            else
            {
                throw new IllegalArgumentException("public key has wrong size");
            }
        }
        else
        {
            /* set */
            if (params.getOid() != null)
            {
                this.oid = params.getOid().getOid();
            }
            else
            {
                this.oid = 0;
            }
            byte[] tmpRoot = builder.root;
            if (tmpRoot != null)
            {
                if (tmpRoot.length != n)
                {
                    throw new IllegalArgumentException("length of root must be equal to length of digest");
                }
                root = tmpRoot;
            }
            else
            {
                root = new byte[n];
            }
            byte[] tmpPublicSeed = builder.publicSeed;
            if (tmpPublicSeed != null)
            {
                if (tmpPublicSeed.length != n)
                {
                    throw new IllegalArgumentException("length of publicSeed must be equal to length of digest");
                }
                publicSeed = tmpPublicSeed;
            }
            else
            {
                publicSeed = new byte[n];
            }
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        return toByteArray();
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private byte[] root = null;
        private byte[] publicSeed = null;
        private byte[] publicKey = null;

        public Builder(XMSSParameters params)
        {
            super();
            this.params = params;
        }

        public Builder withRoot(byte[] val)
        {
            root = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicKey(byte[] val)
        {
            publicKey = XMSSUtil.cloneArray(val);
            return this;
        }

        public XMSSPublicKeyParameters build()
        {
            return new XMSSPublicKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    public byte[] toByteArray()
    {
        /* oid || root || seed */
        int n = params.getTreeDigestSize();
        int oidSize = 4;
        int rootSize = n;
        int publicSeedSize = n;

        byte[] out;
        int position = 0;
        /* copy oid */
        if (oid != 0)
        {
            out = new byte[oidSize + rootSize + publicSeedSize];
            Pack.intToBigEndian(oid, out, position);
            position += oidSize;
        }
        else
        {
            out = new byte[rootSize + publicSeedSize];
        }
        /* copy root */
        XMSSUtil.copyBytesAtOffset(out, root, position);
        position += rootSize;
        /* copy public seed */
        XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
        return out;
    }

    public byte[] getRoot()
    {
        return XMSSUtil.cloneArray(root);
    }

    public byte[] getPublicSeed()
    {
        return XMSSUtil.cloneArray(publicSeed);
    }

    public XMSSParameters getParameters()
    {
        return params;
    }
}
