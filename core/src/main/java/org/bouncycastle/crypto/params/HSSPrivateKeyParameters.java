package org.bouncycastle.crypto.params;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.crypto.signers.LMSContextBasedSigner;
import org.bouncycastle.crypto.signers.lms.LMSContext;
import org.bouncycastle.crypto.signers.lms.LMSEngine;
import org.bouncycastle.crypto.signers.lms.LMSSignature;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.io.Streams;

public class HSSPrivateKeyParameters
    extends LMSKeyParameters
    implements LMSContextBasedSigner
{
    private final int l;
    private final boolean isShard;
    private List<LMSPrivateKeyParameters> keys;
    private List<LMSSignature> sig;
    private final long indexLimit;
    private long index = 0;

    public HSSPrivateKeyParameters(LMSPrivateKeyParameters key, long index, long indexLimit)
    {
        super(true);

        this.l = 1;
        this.keys = Collections.singletonList(key);
        this.sig = Collections.emptyList();
        this.index = index;
        this.indexLimit = indexLimit;
        this.isShard = false;

        //
        // Correct Intermediate LMS values will be constructed during reset to index.
        //
        resetKeyToIndex();
    }

    public HSSPrivateKeyParameters(int l, List<LMSPrivateKeyParameters> keys, List<LMSSignature> sig, long index, long indexLimit)
    {
        super(true);

        this.l = l;
        this.keys = Collections.unmodifiableList(new ArrayList<LMSPrivateKeyParameters>(keys));
        this.sig = Collections.unmodifiableList(new ArrayList<LMSSignature>(sig));
        this.index = index;
        this.indexLimit = indexLimit;
        this.isShard = false;

        //
        // Correct Intermediate LMS values will be constructed during reset to index.
        //
        resetKeyToIndex();
    }

    private HSSPrivateKeyParameters(int l, List<LMSPrivateKeyParameters> keys, List<LMSSignature> sig, long index, long indexLimit, boolean isShard)
    {
        super(true);

        this.l = l;
        // No copy here, unlike the public constructor: the callers are extractKeyShard and
        // getInstance, which build fresh lists they do not retain.
        this.keys = Collections.unmodifiableList(keys);
        this.sig = Collections.unmodifiableList(sig);
        this.index = index;
        this.indexLimit = indexLimit;
        this.isShard = isShard;
    }

    public static HSSPrivateKeyParameters getInstance(byte[] privEnc, byte[] pubEnc)
        throws IOException
    {
        HSSPrivateKeyParameters pKey = getInstance(privEnc);

        HSSPublicKeyParameters pubKey = HSSPublicKeyParameters.getInstance(pubEnc);

        // The public key that arrived alongside the private one is authoritative, so where the root
        // tree already carries its root node in the cache it costs nothing to confirm the two agree.
        // That catches a tree cache which is internally consistent but belongs to a different key -
        // the one corruption the node-by-node check in LMSPrivateKeyParameters cannot see. It is
        // deliberately skipped when the root is not cached: recomputing it there means rebuilding the
        // whole tree, which is the work the cache exists to avoid (github #2414).
        byte[] cachedRoot = pKey.getRootKey().peekRootT();

        if (cachedRoot != null && !org.bouncycastle.util.Arrays.areEqual(
                cachedRoot, pubKey.getLMSPublicKey().getT1()))
        {
            throw new IOException("HSS private key tree cache does not match the public key");
        }

        return pKey;
    }

    /**
     * The HSS index and the component keys' one-time indices are two records of the same position in
     * the key, and a decoded key whose records disagree is refused. RFC 8554 sec. 1 requires each
     * one-time key to be used once; a stored key whose index has been rolled back while its
     * component keys stayed advanced - a partial write, a restore from backup, a buggy storage layer
     * - would otherwise sign a second message under a one-time key already used, and that signature
     * would verify, so nothing would surface it. The check is the identity the two records satisfy:
     * a level below the last contributes (q - 1) leaves of the levels beneath it, because its q has
     * already advanced past the subtree it signed, and the last level contributes its q directly.
     * Verified against every index of a two-level key and across a level boundary of a three-level
     * one (github #2414).
     * <p>
     * Applied at decode only. The constructor is also reached from the hierarchy update, which
     * rebuilds lower levels and is momentarily inconsistent by design; corrupt stored state can only
     * arrive here.
     */
    private static void checkIndexAgainstKeys(int d, List keys, long index)
        throws IOException
    {
        long implied = ((LMSPrivateKeyParameters)keys.get(d - 1)).getIndex();
        int shift = 0;

        for (int i = d - 2; i >= 0; i--)
        {
            shift += ((LMSPrivateKeyParameters)keys.get(i + 1)).getSigParameters().getH();
            if (shift >= 63)
            {
                // taller than the 64-bit index can address, so the two records cannot be compared
                return;
            }
            implied += (((long)((LMSPrivateKeyParameters)keys.get(i)).getIndex()) - 1L) << shift;
        }

        if (implied != index)
        {
            throw new IOException("HSS private key index " + index
                + " does not match the component key indices, which imply " + implied);
        }
    }

    public static HSSPrivateKeyParameters getInstance(Object src)
        throws IOException
    {
        if (src instanceof HSSPrivateKeyParameters)
        {
            return (HSSPrivateKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            int version = ((DataInputStream)src).readInt();
            if (version != 0 && version != 1)
            {
                throw new IllegalStateException("unknown version for hss private key");
            }
            int d = ((DataInputStream)src).readInt();
            if (d < 1 || d > 8)    // RFC 8554, Section 6.
            {
                throw new IOException("d value of HSS private key out of range: " + d);
            }
            long index = ((DataInputStream)src).readLong();
            long maxIndex = ((DataInputStream)src).readLong();
            if (index < 0 || maxIndex < 0 || index > maxIndex)
            {
                throw new IOException(
                    "HSS private key index out of range: index=" + index + " maxIndex=" + maxIndex);
            }
            boolean limited = ((DataInputStream)src).readBoolean();

            ArrayList<LMSPrivateKeyParameters> keys = new ArrayList<LMSPrivateKeyParameters>();
            ArrayList<LMSSignature> signatures = new ArrayList<LMSSignature>();

            for (int t = 0; t < d; t++)
            {
                // The component keys share this stream with the keys and signatures that follow,
                // so whether each one carries the tree-cache field cannot be inferred from the
                // stream having more data - the encoding version says: a version 0 encoding
                // predates the tree cache and its component keys end at the master secret, a
                // version 1 component always carries the cache field (github #2365).
                keys.add(LMSPrivateKeyParameters.readKey((DataInputStream)src, version != 0));
            }

            for (int t = 0; t < d - 1; t++)
            {
                signatures.add(LMSSignature.getInstance(src));
            }

            checkIndexAgainstKeys(d, keys, index);

            return new HSSPrivateKeyParameters(d, keys, signatures, index, maxIndex, limited);
        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));

                Exception hssFailure;

                try
                {
                    return getInstance(in);
                }
                catch (Exception e)
                {
                    hssFailure = e;
                }

                try
                {
                    // old style single LMS key.
                    LMSPrivateKeyParameters lmsKey = LMSPrivateKeyParameters.getInstance(src);
                    return new HSSPrivateKeyParameters(lmsKey, lmsKey.getIndex(), lmsKey.getIndexLimit());
                }
                catch (Exception e)
                {
                    //
                    // Neither shape parsed. The retry as a single LMS key is a compatibility path for
                    // encodings that predate HSS, so when it fails too the HSS failure is the one worth
                    // reporting - it is what the field checks raise - rather than the retry complaining
                    // about a version field it was never going to match. Reporting the retry's exception
                    // masked the real reason a key was rejected, which is how the field checks below
                    // looked absent through this entry point (github #2414).
                    //
                    if (hssFailure instanceof RuntimeException)
                    {
                        throw (RuntimeException)hssFailure;
                    }
                    if (hssFailure instanceof IOException)
                    {
                        throw (IOException)hssFailure;
                    }
                    throw Exceptions.ioException(hssFailure.getMessage(), hssFailure);
                }
            }
            finally
            {
                if (in != null)
                {
                    in.close();
                }
            }
        }
        else if (src instanceof InputStream)
        {
            return getInstance(Streams.readAll((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    public int getL()
    {
        return l;
    }

    public synchronized long getIndex()
    {
        return index;
    }

    public synchronized LMSParameters[] getLMSParameters()
    {
        int len = keys.size();

        LMSParameters[] parms = new LMSParameters[len];

        for (int i = 0; i < len; i++)
        {
            LMSPrivateKeyParameters lmsPrivateKey = keys.get(i);

            parms[i] = new LMSParameters(lmsPrivateKey.getSigParameters(), lmsPrivateKey.getOtsParameters());
        }

        return parms;
    }

    synchronized void incIndex()
    {
        index++;
    }

    /**
     * Advance the key past its current index without signing with it, replacing exhausted lower
     * trees as a signature would. Used by the tests to walk a key through the RFC 8554 vectors.
     */
    synchronized void incrementIndex()
    {
        rangeTestKeys();
        incIndex();
        keys.get(l - 1).incIndex();
    }

    private static HSSPrivateKeyParameters makeCopy(HSSPrivateKeyParameters privateKeyParameters)
    {
        try
        {
            return HSSPrivateKeyParameters.getInstance(privateKeyParameters.getEncoded());
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    private void updateHierarchy(LMSPrivateKeyParameters[] newKeys, LMSSignature[] newSig)
    {
        synchronized (this)
        {
            keys = Collections.unmodifiableList(Arrays.asList(newKeys));
            sig = Collections.unmodifiableList(Arrays.asList(newSig));
        }
    }

    /**
     * Return true if this key was split off another with {@link #extractKeyShard(int)} and so
     * covers a sub-range of that key's indexes.
     */
    public boolean isShard()
    {
        return isShard;
    }

    /**
     * Return the index one past the last this key may sign with.
     */
    public long getIndexLimit()
    {
        return indexLimit;
    }

    public long getUsagesRemaining()
    {
        return getIndexLimit() - getIndex();
    }

    LMSPrivateKeyParameters getRootKey()
    {
        return getKeys().get(0);
    }

    /**
     * Return a key that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     *
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    public HSSPrivateKeyParameters extractKeyShard(int usageCount)
    {
        synchronized (this)
        {
            if (usageCount < 0)
            {
                throw new IllegalArgumentException("usageCount cannot be negative");
            }
            if (usageCount > indexLimit - index)
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining in current leaf");
            }

            long shardIndex = index;
            long shardIndexLimit = index + usageCount;

            // Move this key's index along
            index = shardIndexLimit;

            List<LMSPrivateKeyParameters> keys = new ArrayList<LMSPrivateKeyParameters>(this.getKeys());
            List<LMSSignature> sig = new ArrayList<LMSSignature>(this.getSig());

            HSSPrivateKeyParameters shard = makeCopy(
                new HSSPrivateKeyParameters(l, keys, sig, shardIndex, shardIndexLimit, true));

            resetKeyToIndex();

            return shard;
        }
    }

    synchronized List<LMSPrivateKeyParameters> getKeys()
    {
        return keys;
    }

    synchronized List<LMSSignature> getSig()
    {
        return sig;
    }

    /**
     * Reset to index will ensure that all LMS keys are correct for a given HSS index value.
     * Normally LMS keys are updated in sync with their parent HSS key but in cases of sharding
     * the normal monotonic updating does not apply and the state of the LMS keys needs to be
     * reset to match the current HSS index.
     * <p>
     * Should only be called under the monitor (lock) or during construction before the instance escapes.
     * </p>
     */
    private void resetKeyToIndex()
    {
        // Extract the original keys
        List<LMSPrivateKeyParameters> originalKeys = getKeys();


        long[] qTreePath = new long[originalKeys.size()];
        long q = getIndex();

        for (int t = originalKeys.size() - 1; t >= 0; t--)
        {
            LMSigParameters sigParameters = originalKeys.get(t).getSigParameters();
            int mask = (1 << sigParameters.getH()) - 1;
            qTreePath[t] = q & mask;
            q >>>= sigParameters.getH();
        }

        boolean changed = false;
        LMSPrivateKeyParameters[] keys = originalKeys.toArray(new LMSPrivateKeyParameters[originalKeys.size()]);
        LMSSignature[] sig = this.sig.toArray(new LMSSignature[this.sig.size()]);

        LMSPrivateKeyParameters originalRootKey = this.getRootKey();


        //
        // We need to replace the root key to a new q value.
        //
        if (keys[0].getIndex() - 1 != qTreePath[0])
        {
            keys[0] = generateKey(
                originalRootKey.getSigParameters(),
                originalRootKey.getOtsParameters(),
                (int)qTreePath[0], originalRootKey.getI(), originalRootKey.getMasterSecret());
            changed = true;
        }


        for (int i = 1; i < qTreePath.length; i++)
        {

            LMSPrivateKeyParameters intermediateKey = keys[i - 1];

            byte[][] child = LMSEngine.deriveChildKey(
                intermediateKey.getOtsParameters(),
                intermediateKey.getI(),
                intermediateKey.getMasterSecret(),
                (int)qTreePath[i - 1]);
            byte[] childI = child[0];
            byte[] childSeed = child[1];

            //
            // Q values in LMS keys post increment after they are used.
            // For intermediate keys they will always be out by one from the derived q value (qValues[i])
            // For the end key its value will match so no correction is required.
            //
            boolean lmsQMatch =
                (i < qTreePath.length - 1) ? qTreePath[i] == keys[i].getIndex() - 1 : qTreePath[i] == keys[i].getIndex();

            //
            // Equality is I and seed being equal and the lmsQMath.
            // I and seed are derived from this nodes parent and will change if the parent q, I, seed changes.
            //
            boolean seedEquals = org.bouncycastle.util.Arrays.areEqual(childI, keys[i].getI())
                && org.bouncycastle.util.Arrays.constantTimeAreEqual(childSeed, keys[i].getMasterSecret());


            if (!seedEquals)
            {
                //
                // This means the parent has changed.
                //
                keys[i] = generateKey(
                    originalKeys.get(i).getSigParameters(),
                    originalKeys.get(i).getOtsParameters(),
                    (int)qTreePath[i], childI, childSeed);

                //
                // Ensure post increment occurs on parent and the new public key is signed.
                //
                sig[i - 1] = signPublicKey(keys[i - 1], keys[i].getPublicKey());
                changed = true;
            }
            else if (!lmsQMatch)
            {

                //
                // Q is different so we can generate a new private key but it will have the same public
                // key so we do not need to sign it again.
                //
                keys[i] = generateKey(
                    originalKeys.get(i).getSigParameters(),
                    originalKeys.get(i).getOtsParameters(),
                    (int)qTreePath[i], childI, childSeed);
                changed = true;
            }

        }


        if (changed)
        {
            // We mutate the HSS key here!
            updateHierarchy(keys, sig);
        }

    }

    public synchronized HSSPublicKeyParameters getPublicKey()
    {
        return new HSSPublicKeyParameters(l, getRootKey().getPublicKey());
    }

    /**
     * Check the key has an index left to sign with, and replace every lower tree that has used
     * all of its one-time keys with the next one its parent derives (RFC 8554 sec. 6.1).
     */
    private void rangeTestKeys()
    {
        synchronized (this)
        {
            if (index >= indexLimit)
            {
                throw new ExhaustedPrivateKeyException(
                    "hss private key" +
                        ((isShard) ? " shard" : "") +
                        " is exhausted");
            }


            int L = l;
            int d = L;
            List<LMSPrivateKeyParameters> prv = keys;
            // >= rather than ==: an index above 2^h steps straight over an equality test
            // (github #2414). Decode now rejects such a q, so this is belt and braces.
            while (prv.get(d - 1).getIndex() >= 1 << (prv.get(d - 1).getSigParameters().getH()))
            {
                d = d - 1;
                if (d == 0)
                {
                    throw new ExhaustedPrivateKeyException(
                        "hss private key" +
                            ((isShard) ? " shard" : "") +
                            " is exhausted the maximum limit for this HSS private key");
                }
            }


            while (d < L)
            {
                replaceConsumedKey(d);
                d = d + 1;
            }
        }
    }

    private void replaceConsumedKey(int d)
    {
        byte[][] child = keys.get(d - 1).deriveChildKey();
        byte[] childI = child[0];
        byte[] childRootSeed = child[1];

        List<LMSPrivateKeyParameters> newKeys = new ArrayList<LMSPrivateKeyParameters>(keys);

        //
        // We need the parameters from the LMS key we are replacing.
        //
        LMSPrivateKeyParameters oldPk = keys.get(d);


        newKeys.set(d, generateKey(oldPk.getSigParameters(), oldPk.getOtsParameters(), 0, childI, childRootSeed));

        List<LMSSignature> newSig = new ArrayList<LMSSignature>(sig);

        newSig.set(d - 1, signPublicKey(newKeys.get(d - 1), newKeys.get(d).getPublicKey()));


        this.keys = Collections.unmodifiableList(newKeys);
        this.sig = Collections.unmodifiableList(newSig);

    }

    /**
     * An LMS private key positioned at index q (RFC 8554 sec. 5.2, Algorithm 5).
     */
    private static LMSPrivateKeyParameters generateKey(LMSigParameters parameterSet, LMOtsParameters lmOtsParameters, int q, byte[] I, byte[] rootSeed)
    {
        //
        // RFC 8554 recommends that digest used in LMS and LMOTS be of the same strength to protect against
        // attackers going after the weaker of the two digests. This is not enforced here!
        //
        if (rootSeed == null || rootSeed.length < parameterSet.getM())
        {
            throw new IllegalArgumentException("root seed is less than " + parameterSet.getM());
        }

        return new LMSPrivateKeyParameters(parameterSet, lmOtsParameters, q, I, 1 << parameterSet.getH(), rootSeed);
    }

    /**
     * The chaining signature of an HSS hierarchy: a tree signs the public key of the tree below
     * it, consuming one of its one-time keys.
     */
    private static LMSSignature signPublicKey(LMSPrivateKeyParameters signer, LMSPublicKeyParameters publicKey)
    {
        LMSContext context = signer.generateLMSContext();

        byte[] encoded = publicKey.toByteArray();
        context.update(encoded, 0, encoded.length);

        return LMSEngine.generateSign(context);
    }

    @Override
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

        HSSPrivateKeyParameters that = (HSSPrivateKeyParameters)o;

        if (this.l != that.l || this.isShard != that.isShard || this.indexLimit != that.indexLimit)
        {
            return false;
        }

        //
        // index, keys and sig all move as consumed trees are replaced, and they move together -
        // replaceConsumedKey assigns keys and sig one after the other under this monitor - so read
        // each key's trio in one synchronized block to get a snapshot no unsynchronized reader
        // could tear. The lists are unmodifiable and replaced rather than mutated, so a captured
        // reference stays a coherent view after the lock drops. Neither monitor is held while the
        // other is taken, so a.equals(b) racing b.equals(a) cannot deadlock.
        //
        long thisIndex;
        List<LMSPrivateKeyParameters> thisKeys;
        List<LMSSignature> thisSig;
        synchronized (this)
        {
            thisIndex = this.index;
            thisKeys = this.keys;
            thisSig = this.sig;
        }

        long thatIndex;
        List<LMSPrivateKeyParameters> thatKeys;
        List<LMSSignature> thatSig;
        synchronized (that)
        {
            thatIndex = that.index;
            thatKeys = that.keys;
            thatSig = that.sig;
        }

        return thisIndex == thatIndex && thisKeys.equals(thatKeys) && thisSig.equals(thatSig);
    }

    @Override
    public synchronized byte[] getEncoded()
        throws IOException
    {
        //
        // Private keys are implementation dependent.
        //

        // Version 1: the component keys carry the mandatory tree-cache field their getEncoded
        // appends; a version 0 encoding (any release before the tree cache) carries them without
        // it. The version dispatch in getInstance is what keeps the shared stream unambiguous.
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        u32str(1, bOut); // Version.
        u32str(l, bOut);
        u64str(index, bOut);
        u64str(indexLimit, bOut);
        bOut.write(isShard ? 1 : 0); // Depth

        for (LMSPrivateKeyParameters key : keys)
        {
            bytes(key.getEncoded(), bOut);
        }

        for (LMSSignature s : sig)
        {
            bytes(s.getEncoded(), bOut);
        }

        return bOut.toByteArray();
    }

    @Override
    public int hashCode()
    {
        //
        // Deliberately not getPublicKey().hashCode(): that reaches the root key's tree, which is
        // only built if the node cache does not already hold it - 2^h LM-OTS public keys from an
        // implicit call no caller expects to cost anything. The fields used here are the ones that
        // do not move as the key signs: the root key material is fixed (resetKeyToIndex only
        // repositions it, and LMSPrivateKeyParameters.hashCode is itself index-independent),
        // whereas index, keys and sig all change. Equal keys agree on all of these, so the
        // equals() contract holds.
        //
        int hc = l;
        hc = 31 * hc + (isShard ? 1 : 0);
        hc = 31 * hc + (int)(indexLimit ^ (indexLimit >>> 32));
        hc = 31 * hc + getRootKey().hashCode();
        return hc;
    }

    @Override
    protected Object clone()
        throws CloneNotSupportedException
    {
        return makeCopy(this);
    }

    public LMSContext generateLMSContext()
    {
        LMSSignature[] signatures;
        LMSPublicKeyParameters[] publicKeys;
        LMSPrivateKeyParameters nextKey;
        int L = this.getL();

        synchronized (this)
        {
            rangeTestKeys();

            List<LMSPrivateKeyParameters> keys = this.getKeys();
            List<LMSSignature> sig = this.getSig();

            nextKey = this.getKeys().get(L - 1);

            // Step 2. Stand in for sig[L-1]
            int i = 0;
            signatures = new LMSSignature[L - 1];
            publicKeys = new LMSPublicKeyParameters[L - 1];
            while (i < L - 1)
            {
                signatures[i] = sig.get(i);
                publicKeys[i] = keys.get(i + 1).getPublicKey();
                i = i + 1;
            }

            //
            // increment the index.
            //
            this.incIndex();
        }

        return LMSEngine.withSignedPublicKeys(nextKey.generateLMSContext(), signatures, publicKeys);
    }

    public byte[] generateSignature(LMSContext context)
    {
        return LMSEngine.generateHSSSignature(getL(), context);
    }
}
