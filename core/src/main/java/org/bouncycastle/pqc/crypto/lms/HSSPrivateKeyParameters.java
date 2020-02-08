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

public class HSSPrivateKeyParameters
    extends LMSKeyParameters
{
    private final LMSPrivateKeyParameters rootKey;
    private final int l;
    private final boolean limited;
    private List<LMSPrivateKeyParameters> keys;
    private List<LMSSignature> sig;
    private final long indexLimit;
    private long index = 0;


    public HSSPrivateKeyParameters(int l, LMSPrivateKeyParameters[] keys, LMSSignature[] sig)
    {
        super(true);

        this.l = l;
        this.keys = Collections.unmodifiableList(Arrays.asList(keys.clone()));
        this.sig = Collections.unmodifiableList(Arrays.asList(sig.clone()));
        this.rootKey = this.keys.get(0);
        this.limited = false;

        int m = 1;
        for (LMSPrivateKeyParameters pk : keys)
        {
            m *= pk.getMaxQ();
        }
        indexLimit = m;
    }


    private HSSPrivateKeyParameters(int l, List<LMSPrivateKeyParameters> keys, List<LMSSignature> sig, long index, long indexLimit, boolean limited)
    {
        super(true);

        this.l = l;
        this.keys = Collections.unmodifiableList(new ArrayList<LMSPrivateKeyParameters>(keys));
        this.sig = Collections.unmodifiableList(new ArrayList<LMSSignature>(sig));
        this.rootKey = this.keys.get(0);
        this.index = index;
        this.indexLimit = indexLimit;
        this.limited = limited;
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
            int index = ((DataInputStream)src).readInt();
            int maxIndex = ((DataInputStream)src).readInt();
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

    synchronized void incIndex()
    {
        index++;
    }

    public LMSPrivateKeyParameters getRootKey()
    {
        return rootKey;
    }

    protected void updateHierarchy(LMSPrivateKeyParameters[] newKeys, LMSSignature[] newSig)
    {
        synchronized (this)
        {
            keys = Collections.unmodifiableList(Arrays.asList(newKeys));
            sig = Collections.unmodifiableList(Arrays.asList(newSig));
        }
    }

    public boolean isLimited()
    {
        return limited;
    }

    public long getIndexLimit()
    {
        return indexLimit;
    }

    //        long used = 0;
//
//        int last = keys.size() - 1;
//
//        for (int t = 0; t < keys.size(); t++)
//        {
//            LMSPrivateKeyParameters key = keys.get(t);
//            int lim = (1 << key.getSigParameters().getH());
//
//            if (t == last)
//            {
//                used += key.getIndex();
//            }
//            else
//            {
//                if (key.getIndex() - 1 > 0)
//                {
//                    used += (key.getIndex() - 1) * lim;
//                }
//            }
//        }
//
//        return used;


    public long getUsagesRemaining()
    {
        return indexLimit - index;
    }

//    synchronized LMSPrivateKeyParameters getNextSigningKey()
//    {
//        //
//        // Algorithm 8
//        //
//        // Step 1.
//
//        int L = this.getL();
//
//        int d = L;
//        List<LMSPrivateKeyParameters> prv = this.getKeys();
//        while (prv.get(d - 1).getUsagesRemaining() == 0)
//        {
//            if (limited || d == 1) // we've exhausted the zero layer.
//            {
//                throw new ExhaustedPrivateKeyException("hss private key is exhausted");
//            }
//            d = d - 1;
//        }
//
//        while (d < L)
//        {
//            this.replaceConsumedKey(d);
//            d = d + 1;
//        }
//
//        return this.getKeys().get(L - 1);
//    }


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
            long shartStartIndex = index;

            //
            // Move this keys index along
            //
            index += usageCount;

            List<LMSPrivateKeyParameters> keys = new ArrayList<LMSPrivateKeyParameters>(this.getKeys());
            List<LMSSignature> sig = new ArrayList<LMSSignature>(this.getSig());
            return new HSSPrivateKeyParameters(l, keys, sig, shartStartIndex, maxIndexForShard, true);
        }
    }

    public synchronized List<LMSPrivateKeyParameters> getKeys()
    {
        return keys;
    }

    public synchronized List<LMSSignature> getSig()
    {
        return sig;
    }

    public synchronized HSSPublicKeyParameters getPublicKey()
    {
        return new HSSPublicKeyParameters(l, rootKey.getPublicKey());
    }


    private void replaceConsumedKey(int d)
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
        if (limited != that.limited)
        {
            return false;
        }
        if (index != that.index)
        {
            return false;
        }
        if (indexLimit != that.indexLimit)
        {
            return false;
        }
        if (rootKey != null ? !rootKey.equals(that.rootKey) : that.rootKey != null)
        {
            return false;
        }
        if (keys != null ? !keys.equals(that.keys) : that.keys != null)
        {
            return false;
        }
        return sig != null ? sig.equals(that.sig) : that.sig == null;
    }

    @Override
    public int hashCode()
    {
        int result = rootKey != null ? rootKey.hashCode() : 0;
        result = 31 * result + l;
        result = 31 * result + (limited ? 1 : 0);
        result = 31 * result + (keys != null ? keys.hashCode() : 0);
        result = 31 * result + (sig != null ? sig.hashCode() : 0);
        result = 31 * result + (int)(index ^ (index >>> 32));
        result = 31 * result + (int)(indexLimit ^ (indexLimit >>> 32));
        return result;
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
            .u32str(index)
            .u32str(indexLimit)
            .bool(limited); // Depth

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
}
