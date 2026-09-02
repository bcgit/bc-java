package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.io.Streams;

import static org.bouncycastle.pqc.crypto.lms.HSS.rangeTestKeys;

/**
 * @deprecated use {@link org.bouncycastle.crypto.params.HSSPrivateKeyParameters} instead.
 */
@Deprecated
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

    private HSSPublicKeyParameters publicKey;

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
        this.keys = Collections.unmodifiableList(keys);
        this.sig = Collections.unmodifiableList(sig);
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

        pKey.publicKey = pubKey;

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
                throw new IOException("unknown version for hss private key");
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
                    // about a version field it was never going to match (github #2414).
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

    protected void updateHierarchy(LMSPrivateKeyParameters[] newKeys, LMSSignature[] newSig)
    {
        synchronized (this)
        {
            keys = Collections.unmodifiableList(Arrays.asList(newKeys));
            sig = Collections.unmodifiableList(Arrays.asList(newSig));
        }
    }

    boolean isShard()
    {
        return isShard;
    }

    long getIndexLimit()
    {
        return indexLimit;
    }

    public long getUsagesRemaining()
    {
        return getIndexLimit() - getIndex();
    }

    LMSPrivateKeyParameters getRootKey()
    {
        return keys.get(0);
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
     * Normally LMS keys updated in sync with their parent HSS key but in cases of sharding
     * the normal monotonic updating does not apply and the state of the LMS keys needs to be
     * reset to match the current HSS index.
     */
    void resetKeyToIndex()
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
        LMSPrivateKeyParameters[] keys = originalKeys.toArray(new LMSPrivateKeyParameters[originalKeys.size()]);//  new LMSPrivateKeyParameters[originalKeys.size()];
        LMSSignature[] sig = this.sig.toArray(new LMSSignature[this.sig.size()]);//   new LMSSignature[originalKeys.size() - 1];

        LMSPrivateKeyParameters originalRootKey = this.getRootKey();


        //
        // We need to replace the root key to a new q value; the last level reads the derived
        // value itself, which for a single level hierarchy is the root.
        //
        boolean rootQMatch = (qTreePath.length > 1)
            ? qTreePath[0] == keys[0].getIndex() - 1
            : qTreePath[0] == keys[0].getIndex();

        if (!rootQMatch)
        {
            keys[0] = LMS.generateKeys(
                originalRootKey.getSigParameters(),
                originalRootKey.getOtsParameters(),
                (int)qTreePath[0], originalRootKey.getI(), originalRootKey.getMasterSecret());
            changed = true;
        }


        for (int i = 1; i < qTreePath.length; i++)
        {

            LMSPrivateKeyParameters intermediateKey = keys[i - 1];
            int n = intermediateKey.getOtsParameters().getN();

            byte[] childI = new byte[16];
            byte[] childSeed = new byte[n];
            SeedDerive derive = new SeedDerive(
                intermediateKey.getI(),
                intermediateKey.getMasterSecret(),
                DigestUtil.getDigest(intermediateKey.getOtsParameters()));
            derive.setQ((int)qTreePath[i - 1]);
            derive.setJ(~1);

            derive.deriveSeed(childSeed, true);
            byte[] postImage = new byte[n];
            derive.deriveSeed(postImage, false);
            System.arraycopy(postImage, 0, childI, 0, childI.length);

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
                keys[i] = LMS.generateKeys(
                    originalKeys.get(i).getSigParameters(),
                    originalKeys.get(i).getOtsParameters(),
                    (int)qTreePath[i], childI, childSeed);

                //
                // Ensure post increment occurs on parent and the new public key is signed.
                //
                sig[i - 1] = LMS.generateSign(keys[i - 1], keys[i].getPublicKey().toByteArray());
                changed = true;
            }
            else if (!lmsQMatch)
            {

                //
                // Q is different so we can generate a new private key but it will have the same public
                // key so we do not need to sign it again.
                //
                keys[i] = LMS.generateKeys(
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

    void replaceConsumedKey(int d)
    {

        LMOtsPrivateKey currentOTSKey = keys.get(d - 1).getCurrentOTSKey();
        int n = currentOTSKey.getParameter().getN();

        SeedDerive deriver = currentOTSKey.getDerivationFunction();
        deriver.setJ(~1);
        byte[] childRootSeed = new byte[n];
        deriver.deriveSeed(childRootSeed, true);
        byte[] postImage = new byte[n];
        deriver.deriveSeed(postImage, false);
        byte[] childI = new byte[16];
        System.arraycopy(postImage, 0, childI, 0, childI.length);

        List<LMSPrivateKeyParameters> newKeys = new ArrayList<LMSPrivateKeyParameters>(keys);

        //
        // We need the parameters from the LMS key we are replacing.
        //
        LMSPrivateKeyParameters oldPk = keys.get(d);


        newKeys.set(d, LMS.generateKeys(oldPk.getSigParameters(), oldPk.getOtsParameters(), 0, childI, childRootSeed));

        List<LMSSignature> newSig = new ArrayList<LMSSignature>(sig);

        newSig.set(d - 1, LMS.generateSign(newKeys.get(d - 1), newKeys.get(d).getPublicKey().toByteArray()));


        this.keys = Collections.unmodifiableList(newKeys);
        this.sig = Collections.unmodifiableList(newSig);

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

        if (l != that.l)
        {
            return false;
        }
        if (isShard != that.isShard)
        {
            return false;
        }
        if (indexLimit != that.indexLimit)
        {
            return false;
        }
        if (index != that.index)
        {
            return false;
        }
        if (!keys.equals(that.keys))
        {
            return false;
        }
        return sig.equals(that.sig);
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
        Composer composer = Composer.compose()
            .u32str(1) // Version.
            .u32str(l)
            .u64str(index)
            .u64str(indexLimit)
            .bool(isShard); // Depth

        for (LMSPrivateKeyParameters key : keys)
        {
            composer.bytes(key);
        }

        for (LMSSignature s : sig)
        {
            composer.bytes(s);
        }

        return composer.build();
    }

    @Override
    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    @Override
    protected Object clone()
        throws CloneNotSupportedException
    {
        return makeCopy(this);
    }

    public LMSContext generateLMSContext()
    {
        LMSSignedPubKey[] signed_pub_key;
        LMSContext context;
        int L = this.getL();

        // the HSS index and the bottom key's q are two records of one position: claim both here,
        // bottom key first so an exhausted one leaves each untouched.
        synchronized (this)
        {
            rangeTestKeys(this);

            List<LMSPrivateKeyParameters> keys = this.getKeys();
            List<LMSSignature> sig = this.getSig();

            LMSPrivateKeyParameters nextKey = keys.get(L - 1);

            // Step 2. Stand in for sig[L-1]
            int i = 0;
            signed_pub_key = new LMSSignedPubKey[L - 1];
            while (i < L - 1)
            {
                signed_pub_key[i] = new LMSSignedPubKey(
                    sig.get(i),
                    keys.get(i + 1).getPublicKey());
                i = i + 1;
            }

            context = nextKey.generateLMSContext();

            //
            // increment the index.
            //
            this.incIndex();
        }

        return context.withSignedPublicKeys(signed_pub_key);
    }

    public byte[] generateSignature(LMSContext context)
    {
        try
        {
            return HSS.generateSignature(getL(), context).getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage(), e);
        }
    }
}
