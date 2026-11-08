package org.bouncycastle.crypto.params;

import java.io.IOException;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.signers.xmss.BDSStateMap;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;

/**
 * XMSS^MT Private Key.
 */
public final class XMSSMTPrivateKeyParameters
    extends XMSSMTKeyParameters
    implements Encodable, Destroyable
{
    private final XMSSMTParameters params;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;

    private volatile long index;
    private volatile BDSStateMap bdsState;

    private volatile boolean destroyed;

    private XMSSMTPrivateKeyParameters(Builder builder)
    {
        super(true, builder.params.getTreeDigest());
        params = builder.params;

        int n = params.getTreeDigestSize();
        byte[] privateKey = builder.privateKey;
        if (privateKey != null)
        {
            /* import */
            int totalHeight = params.getHeight();
            XMSSPrivateKeyCodec codec = XMSSPrivateKeyCodec.decode(privateKey,
                XMSSPrivateKeyCodec.mtIndexSize(totalHeight), totalHeight, n);

            index = codec.getIndex();
            secretKeySeed = codec.getSecretKeySeed();
            secretKeyPRF = codec.getSecretKeyPRF();
            publicSeed = codec.getPublicSeed();
            root = codec.getRoot();
            byte[] bdsStateBinary = codec.getBDSState();

            try
            {
                BDSStateMap bdsImport = XMSSEngine.getBDSStateMapFromEncoding(bdsStateBinary, publicSeed);

                // a state map written before the maximum index was recorded marks it with a value
                // no state map can carry, having no tree height of its own to resolve it against;
                // here the parameter set is known
                long stateMaxIndex = (bdsImport.getMaxIndex() < 0)
                    ? (1L << totalHeight) - 1 : bdsImport.getMaxIndex();

                // the WOTS+ parameters are not part of what was serialized, so the digest goes back
                // on - in the same copy that carries the maximum index, which used to be a second
                // one taken afterwards because copying a state before naming its digest threw
                // the single-tree parameters off this key's own parameter set. The builder used
                // to carry them in a field of its own, assigned by withPrivateKey from exactly this
                // expression and guarded above by a null check that nothing could reach - the field
                // is written where the branch is chosen, so being inside the branch is already the
                // proof it was written.
                XMSSParameters xmss = params.getXMSSParameters();

                bdsState = bdsImport.withMaxIndex(stateMaxIndex, xmss.getTreeDigestOID(),
                    xmss.getTreeDigestSize());
                bdsState.validate(params, index, publicSeed, secretKeySeed);
                bdsState.validateRoot(params, root);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (ClassNotFoundException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
            }
        }
        else
        {
            /* set */
            index = builder.index;
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            secretKeySeed = XMSSEngine.validateOrAllocate(tmpSecretKeySeed, n, "secretKeySeed");
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            secretKeyPRF = XMSSEngine.validateOrAllocate(tmpSecretKeyPRF, n, "secretKeyPRF");
            byte[] tmpPublicSeed = builder.publicSeed;
            publicSeed = XMSSEngine.validateOrAllocate(tmpPublicSeed, n, "publicSeed");
            byte[] tmpRoot = builder.root;
            root = XMSSEngine.validateOrAllocate(tmpRoot, n, "root");
            BDSStateMap tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                bdsState = XMSSEngine.createBDSStateMap(params, tmpPublicSeed, tmpSecretKeySeed, builder.index);
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != bdsState.getMaxIndex())
            {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
            try
            {
                bdsState.validate(params, builder.index, publicSeed, secretKeySeed);
                if (builder.bdsState != null)
                {
                    // only a restored state carries a root worth comparing: one built here is
                    // computed from the seeds, and a key built without a root carries zeros
                    bdsState.validateRoot(params, builder.root);
                }
            }
            catch (IllegalStateException e)
            {
                throw Exceptions.illegalArgumentException(e.getMessage(), e);
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

        public Builder(XMSSMTParameters params)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
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
            secretKeySeed = Arrays.clone(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val)
        {
            secretKeyPRF = Arrays.clone(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = Arrays.clone(val);
            return this;
        }

        public Builder withRoot(byte[] val)
        {
            root = Arrays.clone(val);
            return this;
        }

        public Builder withBDSState(BDSStateMap val)
        {
            //
            // Copy, do not adopt. Rolling the key replaces its state map rather than advancing the
            // one it holds, but signing still installs subtree states into that map as it descends
            // the layers, so a caller that keeps the map it passed - or passes one it took off
            // another key with getBDSState() - leaves two keys reading authentication paths out of
            // one map while each sits at its own index. The XMSS side copies for a narrower reason
            // of its own, given on its withBDSState: no layer states are installed into a single
            // BDS, but a signature still marks it.
            //
            // The copy names this key's tree digest, as the XMSS side's does. A state map's WOTS+
            // parameters are not part of what it is serialized as, so one that has just been
            // decoded carries none until a digest is named, and copying it any other way used to
            // be a NullPointerException out of the BDS copy constructor - an ordering this class
            // required of every caller and enforced on none. Naming it here also means a state map
            // installed in a key is always one this key's own parameter set built the WOTS+
            // parameters for, rather than whatever the caller had named them with.
            //
            bdsState = val.withMaxIndex(maxIndexFor(val), params.getTreeDigestOID(),
                params.getTreeDigestSize());
            return this;
        }

        /**
         * As {@link #withBDSState(BDSStateMap)}, for a state map the caller has just built and
         * shares with nothing: it is adopted rather than copied a second time.
         * <p>
         * Package private, and deliberately: the copy the public setter makes is what stops a
         * caller keeping the map it handed over, and a way of asking the key to adopt one is the
         * same defect offered as an option. The callers that can use this are the ones inside the
         * class, where the map being handed over was built by the expression handing it over and
         * is provably shared with nothing. Key generation and the two key decode factories build
         * an exclusive map too, but they are in other packages and so go on paying for the copy -
         * once per key pair and once per key read, against a shard that can be taken once per
         * signature.
         * </p><p>
         * The maximum index arrives with the map rather than being resolved here the way the
         * public setter resolves a legacy one: a caller that built the map built it with the
         * maximum index it is to have.
         * </p>
         */
        Builder withOwnedBDSState(BDSStateMap val)
        {
            bdsState = val;
            return this;
        }

        /**
         * The maximum index a state map handed to this builder should end up with: its own, or -
         * for one written before the maximum index was recorded, which marks itself with a
         * negative value it cannot resolve for itself - the last leaf of the key's own tree.
         */
        private long maxIndexFor(BDSStateMap val)
        {
            return (val.getMaxIndex() < 0) ? (1L << params.getHeight()) - 1 : val.getMaxIndex();
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = Arrays.clone(privateKeyVal);
            return this;
        }

        public XMSSMTPrivateKeyParameters build()
        {
            if (!((privateKey != null) || (publicSeed != null && secretKeySeed != null)))
            {
                throw new IllegalStateException("publicSeed or secretKeySeed is null");
            }
            return new XMSSMTPrivateKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Deprecated
    public byte[] toByteArray()
    {
        synchronized (this)
        {
            checkDestroyed();

            // the two records of the position are about to be written out beside each other, and a
            // stored key that disagrees with itself is refused on the way back in, so say so here
            // rather than persisting one that cannot be read
            bdsState.validateIndex(params, index, publicSeed, secretKeySeed);

            XMSSPrivateKeyCodec.State state = state();

            return XMSSPrivateKeyCodec.encode(state.getIndex(), XMSSPrivateKeyCodec.mtIndexSize(params.getHeight()),
                secretKeySeed, secretKeyPRF, publicSeed, root, state.getEncoded());
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
        return cloneWithCheck(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return cloneWithCheck(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    public BDSStateMap getBDSState()
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

    public XMSSMTPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            checkDestroyed();

            if (this.getIndex() < bdsState.getMaxIndex())
            {
                // the advanced state comes back rather than being applied to the one held, so the
                // index and the state move together: nothing is assigned unless the walk completed,
                // where advancing in place left a state part way to the next leaf under an index
                // that had not moved. XMSSPrivateKeyParameters.rollKey does the same with its BDS.
                bdsState = XMSSEngine.getNextBDSStateMap(bdsState, params, index, publicSeed, secretKeySeed);
                index = index + 1;
            }
            else
            {
                index = bdsState.getMaxIndex() + 1;
                bdsState = new BDSStateMap(bdsState.getMaxIndex());
            }

            //
            // The key's position is recorded twice - here and in each layer's traversal state - and
            // the two are carried by separate statements, so nothing but the author of those
            // statements holds them together. The constructor compares them, which covers a key
            // arriving desynchronised; this covers one going that way while it is held, so a roll
            // that advanced one record and not the other is refused here rather than surfacing as
            // a one-time key signing twice. It is the walk down the layers and d integer
            // comparisons, not the structural check the constructor also runs.
            //
            bdsState.validateIndex(params, index, publicSeed, secretKeySeed);

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
        synchronized (this)
        {
            checkDestroyed();

            // as XMSSPrivateKeyParameters.extractKeyShard: both refusals through the one check,
            // and inside the monitor because the count is this key's.
            XMSSEngine.validateShardSize(usageCount, getUsagesRemaining());

            /* prepare authentication path for next leaf */
            XMSSMTPrivateKeyParameters keyParams = new XMSSMTPrivateKeyParameters.Builder(params)
                                .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                                .withPublicSeed(publicSeed).withRoot(root)
                                .withIndex(getIndex())
                                .withOwnedBDSState(new BDSStateMap(this.bdsState,
                                    getIndex() + usageCount - 1)).build();

            for (int i = 0; i != usageCount; i++)
            {
                this.rollKey();
            }

            return keyParams;
        }
    }

    /**
     * Whether these are the same key at the same position, which for a stateful key means the same
     * traversal state too.
     * <p>
     * Both halves of that are {@code XMSSPrivateKeyCodec}'s, beside the layout they are over:
     * {@code Fields} is the seven things decided ahead of the state and {@code State} is the
     * state, each taken from one key under that key's own monitor and never both at once, and
     * {@code fieldsEqual} and {@code stateEqual} compare them. {@code XMSSPrivateKeyParameters}
     * held a line for line copy of all of it. What is left here is a snapshot per key and the two
     * calls over them, joined with {@code &&} because what the fields decide is whether the state
     * is compared at all - the codec says why the short circuit goes there and nowhere inside.
     * </p><p>
     * The comparison belongs on this class rather than on the provider key that wraps it because
     * every part of it does: the monitor a signature is taken under is this object's, the fields
     * are this object's, and a caller reaching in through the accessors gets a clone of each array
     * and no way to hold any two of them still. {@code HSSPrivateKeyParameters} does the same for
     * the other stateful family in this package, leaving {@code BCLMSPrivateKey.equals()} a single
     * delegating line, and {@code BCXMSSMTPrivateKey} is now that line as well. It carries the
     * tree digest a second time, as the OID it was constructed with, and no longer compares it:
     * that OID is {@code params.getTreeDigestOID()} at every route a key is built by - generation,
     * a PKCS#8 round trip, extractKeyShard, and the key a signature hands back - so the first
     * comparison the codec makes is the comparison it was making.
     * </p>
     */
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        XMSSMTPrivateKeyParameters that = (XMSSMTPrivateKeyParameters)o;

        return XMSSPrivateKeyCodec.fieldsEqual(this.fields(), that.fields())
            && XMSSPrivateKeyCodec.stateEqual(this.state(), that.state());
    }

    /**
     * The values {@code XMSSPrivateKeyCodec.fieldsEqual} decides on, read from this key under its
     * own monitor. The index and the usages remaining are both taken from state a signature
     * replaces - the index field and the state map beside it - so they are read in one block; the
     * four arrays are final and are never written after construction, so the references are as
     * good as the values.
     */
    private XMSSPrivateKeyCodec.Fields fields()
    {
        synchronized (this)
        {
            return new XMSSPrivateKeyCodec.Fields(params.getTreeDigestOID(), this.getIndex(),
                this.getUsagesRemaining(), publicSeed, root, secretKeySeed, secretKeyPRF);
        }
    }

    /**
     * This key's traversal state, encoded, beside the index it is the state for - the pair
     * {@code toByteArray()} writes out and the pair equals() ends on.
     * <p>
     * This is where the two families genuinely differ: the type each holds decides which
     * {@code XMSSEngine.getEncodedBDSState} it reaches, a BDSStateMap against a BDS, and which of
     * the two messages a failure to encode carries. {@code XMSSPrivateKeyCodec.State} says what
     * the pair is for and why this family is the one that needs the index in it.
     * </p>
     */
    private XMSSPrivateKeyCodec.State state()
    {
        synchronized (this)
        {
            try
            {
                return new XMSSPrivateKeyCodec.State(this.index,
                    XMSSEngine.getEncodedBDSState(bdsState, publicSeed));
            }
            catch (IOException e)
            {
                throw Exceptions.illegalStateException("error encoding BDS state map", e);
            }
        }
    }

    /**
     * The fields that do not move as this key signs, hashed as
     * {@code XMSSPrivateKeyCodec.hashCode} hashes them: the tree digest, the root and the public
     * seed.
     */
    public int hashCode()
    {
        return XMSSPrivateKeyCodec.hashCode(params.getTreeDigestOID(), root, publicSeed);
    }

    /**
     * Destroy this key, zeroizing the secret key material it holds: the seed the WOTS+ secret
     * keys are derived from, the PRF key that randomizes message digests, and the WOTS+ secret
     * keys the per-layer BDS traversal states retain for the leaves they last processed.
     * <p>
     * The public seed, the root, the index and the traversal states' tree nodes are retained -
     * none of them is secret. After destruction {@link #isDestroyed()} returns true and
     * {@link #getSecretKeySeed()}, {@link #getSecretKeyPRF()}, {@link #getEncoded()},
     * {@link #getNextKey()} and {@link #extractKeyShard(int)} throw
     * {@link IllegalStateException}; a signature attempt fails before the index is advanced.
     * Keys previously split off this one hold their own copies of the seeds and are unaffected.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            Arrays.clear(secretKeySeed);
            Arrays.clear(secretKeyPRF);
            XMSSEngine.clearSecrets(bdsState);
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private byte[] cloneWithCheck(byte[] fieldValue)
    {
        byte[] rv = Arrays.clone(fieldValue);

        // clone first, check second: a destroy() that lands in between has set the flag before
        // it clears the array, so a stale copy is never handed out.
        checkDestroyed();

        return rv;
    }

    private void checkDestroyed()
    {
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }
    }
}
