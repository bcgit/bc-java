package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;

/**
 * XMSS^MT Private Key.
 */
public final class XMSSMTPrivateKeyParameters
    extends XMSSMTKeyParameters
    implements XMSSStoreableObjectInterface, Encodable
{
    private final XMSSMTParameters params;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;

    private volatile long index;
    private volatile BDSStateMap bdsState;
    private volatile boolean used;

    private XMSSMTPrivateKeyParameters(Builder builder)
    {
        super(true, builder.params.getTreeDigest());
        params = builder.params;

        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        int n = params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey != null)
        {
            if (builder.xmss == null)
            {
                throw new NullPointerException("xmss == null");
            }
            /* import */
            int totalHeight = params.getHeight();
            int indexSize = (totalHeight + 7) / 8;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            /*
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
			if (privateKey.length != totalSize) {
				throw new ParseException("private key has wrong size", 0);
			}
			*/
            int position = 0;
            index = XMSSUtil.bytesToXBigEndian(privateKey, position, indexSize);
            if (!XMSSUtil.isIndexValid(totalHeight, index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += indexSize;
            secretKeySeed = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeySize);
            position += secretKeySize;
            secretKeyPRF = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeyPRFSize);
            position += secretKeyPRFSize;
            publicSeed = XMSSUtil.extractBytesAtOffset(privateKey, position, publicSeedSize);
            position += publicSeedSize;
            root = XMSSUtil.extractBytesAtOffset(privateKey, position, rootSize);
            position += rootSize;
			/* import BDS state */
            byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(privateKey, position, privateKey.length - position);

            try
            {
                BDSStateMap bdsImport = (BDSStateMap)XMSSUtil.deserialize(bdsStateBinary, BDSStateMap.class);

                bdsState = bdsImport.withWOTSDigest(builder.xmss.getTreeDigestOID());
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
            catch (ClassNotFoundException e)
            {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
        else
        {
            /* set */
            index = builder.index;
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            if (tmpSecretKeySeed != null)
            {
                if (tmpSecretKeySeed.length != n)
                {
                    throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest");
                }
                secretKeySeed = tmpSecretKeySeed;
            }
            else
            {
                secretKeySeed = new byte[n];
            }
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            if (tmpSecretKeyPRF != null)
            {
                if (tmpSecretKeyPRF.length != n)
                {
                    throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest");
                }
                secretKeyPRF = tmpSecretKeyPRF;
            }
            else
            {
                secretKeyPRF = new byte[n];
            }
            byte[] tmpPublicSeed = builder.publicSeed;
            if (tmpPublicSeed != null)
            {
                if (tmpPublicSeed.length != n)
                {
                    throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest");
                }
                publicSeed = tmpPublicSeed;
            }
            else
            {
                publicSeed = new byte[n];
            }
            byte[] tmpRoot = builder.root;
            if (tmpRoot != null)
            {
                if (tmpRoot.length != n)
                {
                    throw new IllegalArgumentException("size of root needs to be equal size of digest");
                }
                root = tmpRoot;
            }
            else
            {
                root = new byte[n];
            }
            BDSStateMap tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                long globalIndex = builder.index;
                int totalHeight = params.getHeight();

                if (XMSSUtil.isIndexValid(totalHeight, globalIndex) && tmpPublicSeed != null && tmpSecretKeySeed != null)
                {
                    bdsState = new BDSStateMap(params, builder.index, tmpPublicSeed, tmpSecretKeySeed);
                }
                else
                {
                    bdsState = new BDSStateMap(builder.maxIndex + 1);
                }
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != bdsState.getMaxIndex())
            {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        synchronized (this)
        {
            return toByteArray();
        }
    }

    public static class Builder
    {
        /* mandatory */
        private final XMSSMTParameters params;
        /* optional */
        private long index = 0L;
        private long maxIndex = -1L;
        private byte[] secretKeySeed = null;
        private byte[] secretKeyPRF = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private BDSStateMap bdsState = null;
        private byte[] privateKey = null;
        private XMSSParameters xmss = null;

        public Builder(XMSSMTParameters params)
        {
            super();
            this.params = params;
        }

        public Builder withIndex(long val)
        {
            index = val;
            return this;
        }

        public Builder withMaxIndex(long val)
        {
            maxIndex = val;
            return this;
        }

        public Builder withSecretKeySeed(byte[] val)
        {
            secretKeySeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val)
        {
            secretKeyPRF = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withRoot(byte[] val)
        {
            root = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withBDSState(BDSStateMap val)
        {
            if (val.getMaxIndex() == 0)   // check for legacy state maps
            {
                bdsState = new BDSStateMap(val, (1L << params.getHeight()) - 1);
            }
            else
            {
                bdsState = val;
            }
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = XMSSUtil.cloneArray(privateKeyVal);
            xmss = params.getXMSSParameters();
            return this;
        }

        public XMSSMTPrivateKeyParameters build()
        {
            return new XMSSMTPrivateKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    public byte[] toByteArray()
    {
        synchronized (this)
        {
            /* index || secretKeySeed || secretKeyPRF || publicSeed || root */
            int n = params.getTreeDigestSize();
            int indexSize = (params.getHeight() + 7) / 8;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
            byte[] out = new byte[totalSize];
            int position = 0;
            /* copy index */
            byte[] indexBytes = XMSSUtil.toBytesBigEndian(index, indexSize);
            XMSSUtil.copyBytesAtOffset(out, indexBytes, position);
            position += indexSize;
            /* copy secretKeySeed */
            XMSSUtil.copyBytesAtOffset(out, secretKeySeed, position);
            position += secretKeySize;
            /* copy secretKeyPRF */
            XMSSUtil.copyBytesAtOffset(out, secretKeyPRF, position);
            position += secretKeyPRFSize;
            /* copy publicSeed */
            XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
            position += publicSeedSize;
            /* copy root */
            XMSSUtil.copyBytesAtOffset(out, root, position);
            /* concatenate bdsState */
            try
            {
                return Arrays.concatenate(out, XMSSUtil.serialize(bdsState));
            }
            catch (IOException e)
            {
                throw new IllegalStateException("error serializing bds state: " + e.getMessage(), e);
            }
        }
    }

    public long getIndex()
    {
        return index;
    }

    public long getUsagesRemaining()
    {
        synchronized (this)
        {
            return this.bdsState.getMaxIndex() - this.getIndex() + 1;
        }
    }

    public byte[] getSecretKeySeed()
    {
        return XMSSUtil.cloneArray(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return XMSSUtil.cloneArray(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return XMSSUtil.cloneArray(publicSeed);
    }

    public byte[] getRoot()
    {
        return XMSSUtil.cloneArray(root);
    }

    BDSStateMap getBDSState()
    {
        return bdsState;
    }

    public XMSSMTParameters getParameters()
    {
        return params;
    }

    public XMSSMTPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            return this.extractKeyShard(1);
        }
    }

    XMSSMTPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            if (this.getIndex() < bdsState.getMaxIndex())
            {
                bdsState.updateState(params, index, publicSeed, secretKeySeed);
                index = index + 1;
                used = false;
            }
            else
            {
                index = bdsState.getMaxIndex() + 1;
                bdsState = new BDSStateMap(bdsState.getMaxIndex());
                used = false;
            }

            return this;
        }
    }

    /**
     * Return a key that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    public XMSSMTPrivateKeyParameters extractKeyShard(int usageCount)
    {
        if (usageCount < 1)
        {
            throw new IllegalArgumentException("cannot ask for a shard with 0 keys");
        }
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (usageCount <= this.getUsagesRemaining())
            {
                XMSSMTPrivateKeyParameters keyParams = new XMSSMTPrivateKeyParameters.Builder(params)
                                    .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                                    .withPublicSeed(publicSeed).withRoot(root)
                                    .withIndex(getIndex())
                                    .withBDSState(new BDSStateMap(this.bdsState, getIndex() + usageCount - 1)).build();

                for (int i = 0; i != usageCount; i++)
                {
                    this.rollKey();
                }

                return keyParams;
            }
            else
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
    }
}
