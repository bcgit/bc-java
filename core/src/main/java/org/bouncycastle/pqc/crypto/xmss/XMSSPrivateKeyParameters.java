package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS Private Key.
 */
public final class XMSSPrivateKeyParameters
    extends XMSSKeyParameters
    implements XMSSStoreableObjectInterface, Encodable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    /**
     * Secret for the derivation of WOTS+ secret keys.
     */
    private final byte[] secretKeySeed;
    /**
     * Secret for the randomization of message digests during signature
     * creation.
     */
    private final byte[] secretKeyPRF;
    /**
     * Public seed for the randomization of hashes.
     */
    private final byte[] publicSeed;
    /**
     * Public root of binary tree.
     */
    private final byte[] root;
    /**
     * BDS state.
     */
    private volatile BDS bdsState;

    private XMSSPrivateKeyParameters(Builder builder)
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
            /* import */
            int height = params.getHeight();
            int indexSize = 4;
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
            int index = Pack.bigEndianToInt(privateKey, position);
            if (!XMSSUtil.isIndexValid(height, index))
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
                BDS bdsImport = (BDS)XMSSUtil.deserialize(bdsStateBinary, BDS.class);
                if (bdsImport.getIndex() != index)
                {
                    throw new IllegalStateException("serialized BDS has wrong index");
                }
                bdsState = bdsImport.withWOTSDigest(builder.params.getTreeDigestOID());
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
            BDS tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                if (builder.index < ((1 << params.getHeight()) - 2) && tmpPublicSeed != null && tmpSecretKeySeed != null)
                {
                    bdsState = new BDS(params, tmpPublicSeed, tmpSecretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build(), builder.index);
                }
                else
                {
                    bdsState = new BDS(params, (1 << params.getHeight()) - 1, builder.index);
                }
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != bdsState.getMaxIndex())
            {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
        }
    }

    public long getUsagesRemaining()
    {
        synchronized (this)
        {
            return this.bdsState.getMaxIndex() - this.getIndex() + 1;
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

    XMSSPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (bdsState.getIndex() < bdsState.getMaxIndex())
            {
                bdsState = bdsState.getNextState(publicSeed, secretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build());
            }
            else
            {
                bdsState = new BDS(params, bdsState.getMaxIndex(), bdsState.getMaxIndex() + 1); // no more nodes left.
            }

            return this;
        }
    }

    public XMSSPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            XMSSPrivateKeyParameters keyParameters = this.extractKeyShard(1);

            return keyParameters;
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
    public XMSSPrivateKeyParameters extractKeyShard(int usageCount)
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
                XMSSPrivateKeyParameters keyParams = new XMSSPrivateKeyParameters.Builder(params)
                    .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                    .withPublicSeed(publicSeed).withRoot(root)
                    .withIndex(getIndex())
                    .withBDSState(bdsState.withMaxIndex(bdsState.getIndex() + usageCount - 1,
                        params.getTreeDigestOID())).build();

                if (usageCount == this.getUsagesRemaining())
                {
                    this.bdsState = new BDS(params, bdsState.getMaxIndex(), getIndex() + usageCount);   // we're finished.
                }
                else
                {
                    // update the tree to the new index.
                    OTSHashAddress hashAddress = (OTSHashAddress)new OTSHashAddress.Builder().build();
                    for (int i = 0; i != usageCount; i++)
                    {
                        this.bdsState = bdsState.getNextState(publicSeed, secretKeySeed, hashAddress);
                    }
                }

                return keyParams;
            }
            else
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private int maxIndex = -1;
        private byte[] secretKeySeed = null;
        private byte[] secretKeyPRF = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private BDS bdsState = null;
        private byte[] privateKey = null;

        public Builder(XMSSParameters params)
        {
            super();
            this.params = params;
        }

        public Builder withIndex(int val)
        {
            index = val;
            return this;
        }

        public Builder withMaxIndex(int val)
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

        public Builder withBDSState(BDS valBDS)
        {
            bdsState = valBDS;
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = XMSSUtil.cloneArray(privateKeyVal);
            return this;
        }

        public XMSSPrivateKeyParameters build()
        {
            return new XMSSPrivateKeyParameters(this);
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
            int indexSize = 4;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
            byte[] out = new byte[totalSize];
            int position = 0;
            /* copy index */
            Pack.intToBigEndian(bdsState.getIndex(), out, position);
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
            byte[] bdsStateOut = null;
            try
            {
                bdsStateOut = XMSSUtil.serialize(bdsState);
            }
            catch (IOException e)
            {
                throw new RuntimeException("error serializing bds state: " + e.getMessage());
            }

            return Arrays.concatenate(out, bdsStateOut);
        }
    }

    public int getIndex()
    {
        return bdsState.getIndex();
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

    BDS getBDSState()
    {
        return bdsState;
    }

    public XMSSParameters getParameters()
    {
        return params;
    }
}
