package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.util.io.Streams;

import static org.bouncycastle.pqc.crypto.lms.HSS.rangeTestKeys;

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

        pKey.publicKey = HSSPublicKeyParameters.getInstance(pubEnc);

        return pKey;
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
            if (((DataInputStream)src).readInt() != 0)
            {
                throw new IllegalStateException("unknown version for hss private key");
            }
            int d = ((DataInputStream)src).readInt();
            long index = ((DataInputStream)src).readLong();
            long maxIndex = ((DataInputStream)src).readLong();
            boolean limited = ((DataInputStream)src).readBoolean();

            ArrayList<LMSPrivateKeyParameters> keys = new ArrayList<LMSPrivateKeyParameters>();
            ArrayList<LMSSignature> signatures = new ArrayList<LMSSignature>();

            for (int t = 0; t < d; t++)
            {
                keys.add(LMSPrivateKeyParameters.getInstance(src));
            }

            for (int t = 0; t < d - 1; t++)
            {
                signatures.add(LMSSignature.getInstance(src));
            }

            return new HSSPrivateKeyParameters(d, keys, signatures, index, maxIndex, limited);
        }
        else if (src instanceof byte[])
        {
            InputStream in = null;
            try // 1.5 / 1.6 compatibility
            {
                in = new DataInputStream(new ByteArrayInputStream((byte[])src));
                return getInstance(in);
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
        return indexLimit - index;
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

            if (getUsagesRemaining() < usageCount)
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining in current leaf");
            }

            long maxIndexForShard = index + usageCount;
            long shardStartIndex = index;

            //
            // Move this keys index along
            //
            index += usageCount;

            List<LMSPrivateKeyParameters> keys = new ArrayList<LMSPrivateKeyParameters>(this.getKeys());
            List<LMSSignature> sig = new ArrayList<LMSSignature>(this.getSig());

            HSSPrivateKeyParameters shard = makeCopy(new HSSPrivateKeyParameters(l, keys, sig, shardStartIndex, maxIndexForShard, true));

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
        // We need to replace the root key to a new q value.
        //
        if (keys[0].getIndex() - 1 != qTreePath[0])
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

            byte[] childI = new byte[16];
            byte[] childSeed = new byte[32];
            SeedDerive derive = new SeedDerive(
                intermediateKey.getI(),
                intermediateKey.getMasterSecret(),
                DigestUtil.getDigest(intermediateKey.getOtsParameters().getDigestOID()));
            derive.setQ((int)qTreePath[i - 1]);
            derive.setJ(~1);

            derive.deriveSeed(childSeed, true);
            byte[] postImage = new byte[32];
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
                && org.bouncycastle.util.Arrays.areEqual(childSeed, keys[i].getMasterSecret());


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

        SeedDerive deriver = keys.get(d - 1).getCurrentOTSKey().getDerivationFunction();
        deriver.setJ(~1);
        byte[] childRootSeed = new byte[32];
        deriver.deriveSeed(childRootSeed, true);
        byte[] postImage = new byte[32];
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

        Composer composer = Composer.compose()
            .u32str(0) // Version.
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
        int result = l;
        result = 31 * result + (isShard ? 1 : 0);
        result = 31 * result + keys.hashCode();
        result = 31 * result + sig.hashCode();
        result = 31 * result + (int)(indexLimit ^ (indexLimit >>> 32));
        result = 31 * result + (int)(index ^ (index >>> 32));
        return result;
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
        LMSPrivateKeyParameters nextKey;
        int L = this.getL();

        synchronized (this)
        {
            rangeTestKeys(this);

            List<LMSPrivateKeyParameters> keys = this.getKeys();
            List<LMSSignature> sig = this.getSig();

            nextKey = this.getKeys().get(L - 1);

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

            //
            // increment the index.
            //
            this.incIndex();
        }

        return nextKey.generateLMSContext().withSignedPublicKeys(signed_pub_key);
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
