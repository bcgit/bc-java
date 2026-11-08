package org.bouncycastle.crypto.signers.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * The per-layer BDS traversal states of one XMSS^MT key, keyed by layer.
 * <p>
 * Every read and every write of the map below is taken on this object's own monitor, and one fact
 * is behind all of them: {@code XMSSMTPrivateKeyParameters.getBDSState()} hands this object out
 * live, and a signature descends the layers installing the states it builds lazily into the map it
 * is signing with. An insertion rebalances the {@code TreeMap} underneath, so anything walking or
 * looking up outside the monitor reads a tree part way through being restructured - a
 * {@code ConcurrentModificationException} at best, and at worst a lookup that answers with a null
 * or with another layer's state. Holding the monitor for the whole of an operation, rather than
 * once per lookup, is also what makes an answer coherent rather than merely intact: the signer
 * holds this same monitor for its whole descent, so what an operation here sees is every layer
 * from before that signature or every layer from after it, never a mixture.
 * </p><p>
 * What each method does with that is on the method. None of them repeats this.
 * </p>
 */
public class BDSStateMap
    implements Serializable
{
    private static final long serialVersionUID = -3464451825208522308L;
    
    private final Map<Integer, BDS> bdsState = new TreeMap<Integer, BDS>();

    private transient long maxIndex;

    public BDSStateMap(long maxIndex)
    {
        this.maxIndex = maxIndex;
    }

    /**
     * Copy the states of another map, on that map's own monitor for the whole walk - which is what
     * makes this safe to run against a map a key is signing with, for the reason on the class.
     * <p>
     * Each layer is copied rather than shared, and the copy is not incidental. A {@code BDS} is
     * filled at construction and never written afterwards - the block above {@code BDS}'s getLive
     * accessors says so, and advancing a layer builds its successor and {@code put}s it here - with
     * one exception: {@code markUsed()} writes the used mark in place. This constructor has two
     * callers, {@link #getNextState} and {@code XMSSMTPrivateKeyParameters.extractKeyShard}, and it
     * is the second that leaves two live keys holding maps built from one map. A shared layer zero
     * would be those two keys sharing one record of whether the one-time key at that leaf has been
     * spent - the mark one of them made becoming the refusal the other gets, and the mark it did
     * not make becoming the refusal it does not get, which is the direction RFC 8391 sec. 1.1 is
     * about. Only layer zero is ever marked, so sharing the layers above it would be safe as
     * {@code markUsed()} is written today; that is a fact about that method rather than about this
     * one, and it would buy the copy on {@code getNextState}'s roll path alone.
     * </p><p>
     * The two key builders' {@code withBDSState} leave two live keys the same way and reach the
     * same guarantee, but not through here: they go through {@link #withMaxIndex}, which builds an
     * empty map and fills it a layer at a time out of {@link BDS#withWOTSDigest}, itself a copy.
     * So there are two ways a state map is copied per layer in this package rather than one, and a
     * change to the copying here covers neither builder.
     * </p>
     */
    public BDSStateMap(BDSStateMap stateMap, long maxIndex)
    {
        synchronized (stateMap)
        {
            for (Iterator it = stateMap.bdsState.keySet().iterator(); it.hasNext();)
            {
                Integer key = (Integer)it.next();

                bdsState.put(key, new BDS(stateMap.bdsState.get(key)));
            }
        }
        this.maxIndex = maxIndex;
    }

    public BDSStateMap(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        this.maxIndex = (1L << params.getHeight()) - 1;
        for (long index = 0; index < globalIndex; index++)
        {
            updateState(params, index, publicSeed, secretKeySeed);
        }
    }

    public long getMaxIndex()
    {
        return maxIndex;
    }

    /**
     * Zeroize the secret material retained by every layer's state; see {@link BDS#clearSecrets()}.
     * On this object's monitor, as every other traversal of the map below is.
     */
    void clearSecrets()
    {
        synchronized (this)
        {
            for (Iterator<BDS> it = bdsState.values().iterator(); it.hasNext();)
            {
                it.next().clearSecrets();
            }
        }
    }

    /**
     * The traversal state for the leaf after {@code globalIndex}, as a new state map: the one this
     * is called on is left where it is. This is the multi-tree counterpart of
     * {@link BDS#getNextState(byte[], byte[], byte[])}, and advancing by replacement rather
     * than in place is what lets the owning key move its index and its state as one - see
     * {@link XMSSEngine#getNextBDSStateMap}.
     */
    BDSStateMap getNextState(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        BDSStateMap next = new BDSStateMap(this, maxIndex);

        next.updateState(params, globalIndex, publicSeed, secretKeySeed);

        return next;
    }

    /**
     * Advance this state map in place. Package-private, and for a map that is not yet anyone's: the
     * constructor building a state up to an index, and the copy {@link #getNextState} has just
     * taken. The state a key holds is advanced by being replaced, never through here.
     * <p>
     * That both callers hand it a map nobody else can see is what makes the monitor unnecessary
     * here, not a reason to reach past it: the layers are read and written through this object's
     * own accessors, the way layer zero below already was and every other method here is, so the
     * one thing that would have to change for this to matter - a third caller, or one of these two
     * publishing its map earlier - does not also have to be noticed here. The layer loop used to
     * name the field directly, three lines under a layer zero that did not, which read as a
     * distinction being drawn rather than as the accident it was.
     * </p>
     */
    void updateState(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        XMSSParameters xmssParams = params.getXMSSParameters();
        int xmssHeight = xmssParams.getHeight();

        //
        // set up state for next signature
        //
        long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
        int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);

        byte[] otsAddress = XMSSAddress.otsHashAddress(0, indexTree, indexLeaf);

        /* prepare authentication path for next leaf */
        if (indexLeaf < ((1 << xmssHeight) - 1))
        {
            if (this.get(0) == null || indexLeaf == 0)
            {
                this.put(0, new BDS(xmssParams, publicSeed, secretKeySeed, otsAddress));
            }

            this.update(0, publicSeed, secretKeySeed, otsAddress);
        }

        /* loop over remaining layers */
        for (int layer = 1; layer < params.getLayers(); layer++)
        {
                /* get root of layer - 1 */
            indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
            indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
                /* adjust addresses */
            otsAddress = XMSSAddress.otsHashAddress(layer, indexTree, indexLeaf);

                /* prepare authentication path for next leaf */
            if (this.get(layer) == null || XMSSUtil.isNewBDSInitNeeded(globalIndex, xmssHeight, layer))
            {
                this.put(layer, new BDS(xmssParams, publicSeed, secretKeySeed, otsAddress));
            }

            if (indexLeaf < ((1 << xmssHeight) - 1)
                && XMSSUtil.isNewAuthenticationPathNeeded(globalIndex, xmssHeight, layer))
            {
                this.update(layer, publicSeed, secretKeySeed, otsAddress);
            }
        }
    }

    boolean isEmpty()
    {
        synchronized (this)
        {
            return bdsState.isEmpty();
        }
    }

    /**
     * The layer to state mapping, as a snapshot rather than the map itself: the encoder walks what
     * it is given, and the map this is taken from can be one a key is signing with.
     */
    Map<Integer, BDS> getStateMap()
    {
        synchronized (this)
        {
            return new TreeMap<Integer, BDS>(bdsState);
        }
    }

    public void validate(XMSSMTParameters params)
    {
        synchronized (this)
        {
            long maxIndexLimit = (1L << params.getHeight()) - 1;
            if (maxIndex < 0 || maxIndex > maxIndexLimit || bdsState.size() > params.getLayers())
            {
                throw new IllegalStateException("BDS state map does not match XMSSMT parameters");
            }

            XMSSParameters xmssParams = params.getXMSSParameters();
            for (Iterator<Integer> it = bdsState.keySet().iterator(); it.hasNext();)
            {
                Integer layer = it.next();
                if (layer.intValue() < 0 || layer.intValue() >= params.getLayers())
                {
                    throw new IllegalStateException("BDS state map has invalid layer");
                }
                BDS state = bdsState.get(layer);
                if (state == null)
                {
                    throw new IllegalStateException("BDS state map has null state");
                }
                state.validate(xmssParams);
            }
        }
    }

    /**
     * Confirm the top layer's root is the one the enclosing private key declares - the top tree's
     * root is the public root. A layer with no state yet is built lazily at signing time and so is
     * not compared (github #2414).
     *
     * @param params       the parameters of the enclosing key.
     * @param expectedRoot the root the private key declares.
     */
    public void validateRoot(XMSSMTParameters params, byte[] expectedRoot)
    {
        // on this map's own monitor, as every other read of bdsState here is: this is the check
        // that decides whether a key is built around the map at all, so a lookup answering with a
        // null or with another layer's state is what would decide it. The comparison is kept
        // inside, as validate(XMSSMTParameters) keeps its own, so the state compared is the state
        // found.
        synchronized (this)
        {
            BDS top = bdsState.get(Integers.valueOf(params.getLayers() - 1));

            if (top != null)
            {
                top.validateRoot(expectedRoot);
            }
        }
    }

    /**
     * Validate as validate(XMSSMTParameters) and additionally tie each layer's traversal state to
     * the enclosing private key's index. RFC 8391 sec. 1.1 requires each one-time key to be used
     * once, and the global index and the per-layer BDS states are two records of the same position,
     * so a stored key whose index has been rolled back while its state stayed advanced - a partial
     * write, a restore from backup, a buggy storage layer - is detectable and must be refused: it
     * would otherwise sign a second message under a one-time key already used, and the signature
     * would verify. The XMSS side has done this since its own state was tied to its index; this is
     * the multi-tree counterpart.
     *
     * @param params      the parameters of the enclosing key.
     * @param globalIndex the index the enclosing key declares.
     * @deprecated use validate(XMSSMTParameters, long, byte[], byte[]): without the key's seeds the
     * state carried over at the start of a tree cannot be tied to the tree it came from, see
     * validateIndex(XMSSMTParameters, long, byte[], byte[]).
     */
    public void validate(XMSSMTParameters params, long globalIndex)
    {
        validate(params);
        validateIndex(params, globalIndex);
    }

    /**
     * Validate as validate(XMSSMTParameters) and then as
     * validateIndex(XMSSMTParameters, long, byte[], byte[]).
     *
     * @param params        the parameters of the enclosing key.
     * @param globalIndex   the index the enclosing key declares.
     * @param publicSeed    the public seed of the enclosing key.
     * @param secretKeySeed the secret key seed of the enclosing key.
     */
    public void validate(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        validate(params);
        validateIndex(params, globalIndex, publicSeed, secretKeySeed);
    }

    /**
     * The index half of validate(XMSSMTParameters, long) on its own: tie each layer's traversal
     * state to the index its enclosing key declares, without re-walking the structure of every
     * state.
     * <p>
     * Separate because the two halves answer at different times. The structure of a state can only
     * be wrong on the way in, so the constructor is where it is checked; the index pair can go
     * wrong every time the key moves, because the two records are advanced by two statements and
     * only the author of those statements keeps them together. So this half runs on every roll and
     * before every encoding, where the full check would be re-walking authentication paths, stacks
     * and tree hashes once per signature to learn nothing new.
     * </p>
     *
     * @param params      the parameters of the enclosing key.
     * @param globalIndex the index the enclosing key declares.
     * @deprecated use validateIndex(XMSSMTParameters, long, byte[], byte[]). This form accepts a
     * state on the last leaf of any tree wherever a layer's expected leaf is 0, having no seeds to
     * tell which tree the state came from, so a key saved on the last leaf of a tree and then moved
     * back to the first leaf of that same tree passes it.
     */
    public void validateIndex(XMSSMTParameters params, long globalIndex)
    {
        validateIndex(params, globalIndex, null, null);
    }

    /**
     * The index half of validate(XMSSMTParameters, long, byte[], byte[]) on its own, as
     * validateIndex(XMSSMTParameters, long) describes, but with the carried-over state tied to the
     * tree it came from.
     * <p>
     * Where a layer's expected leaf is 0 its state may still stand on the last leaf of the
     * previous tree of that layer - see below - and that allowance is only sound for that one
     * tree. A state on the last leaf of the expected tree itself, or of any other, is a key whose
     * index was moved back behind its state: accepting it would sign again under a one-time key
     * already used. The previous tree is checked by recomputing the leaf before its last one from
     * the seeds and comparing it with the first node of the state's authentication path, which
     * costs one leaf, and only at those positions.
     * </p>
     *
     * @param params        the parameters of the enclosing key.
     * @param globalIndex   the index the enclosing key declares.
     * @param publicSeed    the public seed of the enclosing key.
     * @param secretKeySeed the secret key seed of the enclosing key.
     */
    public void validateIndex(XMSSMTParameters params, long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
    {
        if ((publicSeed == null) != (secretKeySeed == null))
        {
            throw new IllegalArgumentException("publicSeed and secretKeySeed must both be given");
        }

        // On this map's own monitor, for the whole walk, as validate(XMSSMTParameters) and
        // getStateMap() beside it are - taking it once per layer instead, which is what a bare
        // get(layer) does, would let a signature land in the middle and leave this comparing some
        // layers from before it against others from after it, reporting on a state map no instant
        // produced. Every caller in this tree arrives already holding the enclosing key's monitor,
        // which the signer holds for a whole descent, so none of them can reach that; it is a fact
        // about today's callers rather than about this method, which is public and hands its answer
        // to whoever asks.
        synchronized (this)
        {
            int xmssHeight = params.getXMSSParameters().getHeight();
            int lastLeaf = (1 << xmssHeight) - 1;
            long treeIndex = globalIndex;

            for (int layer = 0; layer < params.getLayers(); layer++)
            {
                // the same walk down the layers the signer and updateState perform
                int expectedLeaf = XMSSUtil.getLeafIndex(treeIndex, xmssHeight);
                treeIndex = XMSSUtil.getTreeIndex(treeIndex, xmssHeight);

                BDS state = bdsState.get(Integers.valueOf(layer));
                if (state == null)
                {
                    // a layer's state is built lazily, on the first signature that needs it
                    continue;
                }

                //
                // At a leaf index of 0 the layer has just moved into a new subtree and its state has
                // not been advanced into it: updateState skips the advance on the last leaf of a
                // subtree and the signer rebuilds the state when it next signs there, so the
                // carried-over final index of the previous subtree is legitimate at that one
                // position - and only if it is the previous subtree's, which the seeds, when
                // given, establish: treeIndex is already the expected tree of this layer here.
                // Every other position must agree exactly. Enumerating every index of the
                // h=4/d=2, h=6/d=2, h=6/d=3, h=9/d=3 and h=8/d=4 parameter sets produces no other
                // divergence.
                //
                int actual = state.getIndex();
                boolean ok = (actual == expectedLeaf)
                    || (expectedLeaf == 0 && actual == lastLeaf && (secretKeySeed == null
                        || state.isLastLeafOfTree(publicSeed, secretKeySeed, layer, treeIndex - 1)));

                if (!ok)
                {
                    throw new IllegalStateException(
                        "BDS state has wrong index for layer " + layer + ": expected " + expectedLeaf
                            + " but state is at " + actual);
                }
            }
        }
    }

    public BDS get(int index)
    {
        synchronized (this)
        {
            return bdsState.get(Integers.valueOf(index));
        }
    }

    /**
     * Record that the one-time key this state is sitting on has signed, as the XMSS path does.
     * <p>
     * Only the layer zero state is marked. Its leaf signs the message digest, so it is the one
     * one-time key a second signature must never reuse - the leaves above it sign the root of the
     * subtree below, which does not change while that subtree is being signed through, so those
     * layers legitimately produce the same signature again and are not used up by it.
     * </p><p>
     * The mark is written inside this object's monitor, not merely the lookup that finds the state
     * carrying it. {@code BDS.used} is a plain field, and this and {@link #isUsed()} are the only
     * mutation a published state map undergoes after construction, so a mark left by a holder that
     * reached the map through {@code getBDSState()} on another thread would otherwise have no
     * happens-before with the gate that reads it - and that gate is the RFC 8391 sec. 1.1 reuse
     * refusal. Every caller in this tree also holds the owning key's monitor, which supplies the
     * ordering; taking this one means the guarantee comes from the class rather than from them.
     * </p>
     */
    void markUsed()
    {
        synchronized (this)
        {
            BDS layerZero = get(0);

            // the state is put in place before the signature is built, but the signature can fail
            // before that happens and this runs from the finally that covers it
            if (layerZero != null)
            {
                layerZero.markUsed();
            }
        }
    }

    /**
     * Whether the layer zero state is sitting on a one-time key it has already signed with, the
     * record {@link #markUsed()} leaves. Read by {@link XMSSEngine#generateMTSignature} before it
     * commits to an existing layer zero state; a state map whose layer zero is absent has nothing
     * to answer for, since the signer builds that layer fresh.
     * <p>
     * On this object's monitor, for the reason {@link #markUsed()} gives: it is the read half of
     * the same field.
     * </p>
     */
    boolean isUsed()
    {
        synchronized (this)
        {
            BDS layerZero = get(0);

            return layerZero != null && layerZero.isUsed();
        }
    }

    BDS update(int index, byte[] publicSeed, byte[] secretKeySeed, byte[] otsAddress)
    {
        synchronized (this)
        {
            return bdsState.put(Integers.valueOf(index),
                bdsState.get(Integers.valueOf(index)).getNextState(publicSeed, secretKeySeed, otsAddress));
        }
    }

    void put(int index, BDS bds)
    {
        synchronized (this)
        {
            bdsState.put(Integers.valueOf(index), bds);
        }
    }

    public BDSStateMap withWOTSDigest(ASN1ObjectIdentifier digestName)
    {
        return withWOTSDigest(digestName, -1);
    }

    public BDSStateMap withWOTSDigest(ASN1ObjectIdentifier digestName, int digestSize)
    {
        return withMaxIndex(this.maxIndex, digestName, digestSize);
    }

    /**
     * As {@link #withWOTSDigest(ASN1ObjectIdentifier, int)}, and with a maximum index of the
     * caller's rather than this map's - the state map counterpart of
     * {@link BDS#withMaxIndex(int, ASN1ObjectIdentifier, int)}, and what
     * {@code XMSSMTPrivateKeyParameters.Builder.withBDSState} copies a state map with, so that a
     * state installed in a key is always one whose WOTS+ parameters the key's own parameter set
     * named. Only the map's own maximum index is the caller's: each layer keeps the one its
     * subtree fixes, as it does through every other copy of a state map.
     * <p>
     * The two used to have to be done one after the other, and in one order, because copying a
     * state that had not been given its digest yet was a NullPointerException; they can be done in
     * either order now, and this does them in one pass rather than either.
     * </p>
     *
     * @param maxIndex   the maximum index the copy is to carry.
     * @param digestName the tree digest of the key the copy belongs to.
     * @param digestSize its output length in bytes, where the digest does not fix one.
     */
    public BDSStateMap withMaxIndex(long maxIndex, ASN1ObjectIdentifier digestName, int digestSize)
    {
        BDSStateMap newStateMap = new BDSStateMap(maxIndex);

        synchronized (this)
        {
            for (Iterator<Integer> keys = bdsState.keySet().iterator(); keys.hasNext();)
            {
                Integer key = keys.next();

                newStateMap.bdsState.put(key, bdsState.get(key).withWOTSDigest(digestName, digestSize));
            }
        }

        return newStateMap;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        // Java deserialization does not run field initializers, so a crafted stream that declares
        // no bdsState field at all leaves it null, and one that declares it can put nulls in it.
        // The import path rebuilds a state map around the digest its key names before anything
        // validates it - withWOTSDigest() walks the map - so validate()'s own null checks are
        // reached too late to be what rejects this. Refuse it here, where the stream enters.
        if (bdsState == null)
        {
            throw new IOException("no state in BDS state map");
        }
        for (Iterator<Integer> it = bdsState.keySet().iterator(); it.hasNext();)
        {
            Integer layer = it.next();

            // a null key is not merely absent state: TreeMap.get(null) throws in its own right
            if (layer == null || bdsState.get(layer) == null)
            {
                throw new IOException("null state in BDS state map");
            }
        }

        // ObjectInputStream.available() is an estimate of what can be read without blocking, not
        // an end of data test - it answers zero for a stream that cannot supply the next block
        // header without blocking - so reading a byte is what actually says whether the maximum
        // index is there: read() returns -1 only at the end of this object's data.
        int first = in.read();

        if (first < 0)
        {
            // written before the maximum index was recorded. A state map cannot resolve that for
            // itself, holding no tree height of its own the way BDS does, so it marks it with a
            // value no state map can really carry and leaves it to XMSSMTPrivateKeyParameters,
            // which knows the parameter set. Zero, the mark this used to leave, is one a state map
            // really can carry: it is what a single use key shard taken at index 0 carries.
            this.maxIndex = -1L;
        }
        else
        {
            byte[] encoded = new byte[8];

            encoded[0] = (byte)first;
            in.readFully(encoded, 1, encoded.length - 1);

            this.maxIndex = Pack.bigEndianToLong(encoded, 0);
        }

        // and nothing after it, as BDS.readObject() requires of its own data. The two were
        // reworked together onto read() and only one came away with the check, so a legacy state
        // map encoding carrying bytes appended past its maximum index was a second encoding of the
        // same state map where the byte for byte equivalent on a BDS was refused. The outer
        // "unexpected data found at end of ObjectInputStream" in XMSSUtil.deserialize does not
        // cover this: these bytes are inside this object's own data rather than after it, so they
        // are consumed by the read that recovers it and the stream is at its end by the time that
        // check looks. BDSStateCodec calls checkFinished for both of the current formats, which
        // leaves this path the one place the two families disagreed.
        if (in.read() >= 0)
        {
            throw new IOException("inconsistent BDS state map data detected");
        }
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeLong(this.maxIndex);
    }
}
