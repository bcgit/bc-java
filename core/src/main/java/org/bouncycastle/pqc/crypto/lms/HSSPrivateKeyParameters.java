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

    boolean isLimited()
    {
        return limited;
    }

    long getIndexLimit()
    {
        return indexLimit;
    }


    public long getUsagesRemaining()
    {
        return indexLimit - index;
    }

    public HSSPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            HSSPrivateKeyParameters keyParameters = this.extractKeyShard(1);

            return keyParameters;
        }
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
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
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

    synchronized List<LMSPrivateKeyParameters> getKeys()
    {
        return keys;
    }

    synchronized List<LMSSignature> getSig()
    {
        return sig;
    }

    public synchronized HSSPublicKeyParameters getPublicKey()
    {
        return new HSSPublicKeyParameters(l, rootKey.getPublicKey());
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
