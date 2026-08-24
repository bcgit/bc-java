package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.WeakHashMap;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * @deprecated use {@link org.bouncycastle.crypto.params.LMSPrivateKeyParameters} instead.
 */
@Deprecated
public class LMSPrivateKeyParameters
    extends LMSKeyParameters
    implements LMSContextBasedSigner
{
    private static CacheKey T1 = new CacheKey(1);
    private static CacheKey[] internedKeys = new CacheKey[64];

    static
    {
        internedKeys[1] = T1;
        for (int i = 2; i < internedKeys.length; i++)
        {
            internedKeys[i] = new CacheKey(i);
        }
    }

    private final byte[] I;
    private final LMSigParameters parameters;
    private final LMOtsParameters otsParameters;
    private final int maxQ;
    private final byte[] masterSecret;
    private final Map<CacheKey, byte[]> tCache;
    private final int maxCacheR;
    private final Digest tDigest;

    private int q;

    //
    // These are not final because they can be generated.
    // They also do not need to be persisted.
    //
    private LMSPublicKeyParameters publicKey;


    public LMSPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I, int maxQ, byte[] masterSecret)
    {
        super(true);
        this.parameters = lmsParameter;
        this.otsParameters = otsParameters;
        this.q = q;
        this.I = Arrays.clone(I);
        this.maxQ = maxQ;
        this.masterSecret = Arrays.clone(masterSecret);
        this.maxCacheR = 1 << (parameters.getH() + 1);
        this.tCache = new WeakHashMap<CacheKey, byte[]>();
        this.tDigest = DigestUtil.getDigest(lmsParameter);
    }

    private LMSPrivateKeyParameters(LMSPrivateKeyParameters parent, int q, int maxQ)
    {
        super(true);
        this.parameters = parent.parameters;
        this.otsParameters = parent.otsParameters;
        this.q = q;
        this.I = parent.I;
        this.maxQ = maxQ;
        this.masterSecret = parent.masterSecret;
        this.maxCacheR = 1 << parameters.getH();
        this.tCache = parent.tCache;
        this.tDigest = DigestUtil.getDigest(parameters);
        this.publicKey = parent.publicKey;
    }

    public static LMSPrivateKeyParameters getInstance(byte[] privEnc, byte[] pubEnc)
        throws IOException
    {
        LMSPrivateKeyParameters pKey = getInstance(privEnc);
    
        pKey.publicKey = LMSPublicKeyParameters.getInstance(pubEnc);

        return pKey;
    }

    public static LMSPrivateKeyParameters getInstance(Object src)
        throws IOException
    {
        if (src instanceof LMSPrivateKeyParameters)
        {
            return (LMSPrivateKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            DataInputStream dIn = (DataInputStream)src;

            LMSPrivateKeyParameters key = readCoreKey(dIn);

            //
            // Anything after the master secret is a cache of the top of the Merkle tree (see
            // getEncoded). Priming it here means the first signature made after the key is decoded
            // does not have to rebuild the whole tree, which otherwise costs about as much as key
            // generation. For a standalone key the cache is optional trailing data rather than a
            // new version so that releases predating it still read the key - they stop at the
            // master secret and ignore what follows - at the cost of it being absent rather than
            // malformed when a stream supplies no more bytes. Component keys inside an HSS private
            // key share their stream with the keys and signatures that follow, so "more data"
            // means nothing there - they are read via readKey, where the enclosing HSS encoding's
            // version dictates whether the cache field is present (github #2365).
            //
            if (dIn.available() > 0)
            {
                readTreeCache(dIn, key);
            }

            return key;
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

    /**
     * Read a component key from a stream shared with the other keys and signatures of an HSS
     * private key. Unlike the public getInstance entry point, whether the tree-cache field is
     * present is dictated by the caller - from the enclosing HSS encoding's version - rather
     * than inferred from the stream having more data, which is meaningless mid-stream.
     */
    static LMSPrivateKeyParameters readKey(DataInputStream dIn, boolean withCache)
        throws IOException
    {
        LMSPrivateKeyParameters key = readCoreKey(dIn);

        if (withCache)
        {
            readTreeCache(dIn, key);
        }

        return key;
    }

    private static LMSPrivateKeyParameters readCoreKey(DataInputStream dIn)
        throws IOException
    {
        /*
        .u32str(0) // version
        .u32str(parameters.getType()) // type
        .u32str(otsParameters.getType()) // ots type
        .bytes(I) // I at 16 bytes
        .u32str(q) // q
        .u32str(maxQ) // maximum q
        .u32str(masterSecret.length) // length of master secret.
        .bytes(masterSecret) // the master secret
        .build();
         */

        if (dIn.readInt() != 0)
        {
            throw new IllegalStateException("expected version 0 lms private key");
        }

        int sigType = dIn.readInt();
        LMSigParameters parameter = LMSigParameters.getParametersForType(sigType);
        if (parameter == null)
        {
            throw new IOException("unknown LMS type code: " + sigType);
        }
        int otsType = dIn.readInt();
        LMOtsParameters otsParameter = LMOtsParameters.getParametersForType(otsType);
        if (otsParameter == null)
        {
            throw new IOException("unknown LM-OTS type code: " + otsType);
        }
        byte[] I = new byte[16];
        dIn.readFully(I);

        int q = dIn.readInt();
        int maxQ = dIn.readInt();
        int l = dIn.readInt();
        if (l < 0)
        {
            throw new IllegalStateException("secret length less than zero");
        }
        if (l > dIn.available())
        {
            throw new IOException("secret length exceeded " + dIn.available());
        }
        byte[] masterSecret = new byte[l];
        dIn.readFully(masterSecret);

        return new LMSPrivateKeyParameters(parameter, otsParameter, q, I, maxQ, masterSecret);
    }

    private static void readTreeCache(DataInputStream dIn, LMSPrivateKeyParameters key)
        throws IOException
    {
        int cacheCount = dIn.readInt();
        if (cacheCount < 0 || cacheCount >= internedKeys.length)
        {
            throw new IOException("tree cache node count out of range: " + cacheCount);
        }
        int m = key.getSigParameters().getM();
        if ((long)cacheCount * m > dIn.available())
        {
            throw new IOException("tree cache length exceeded " + dIn.available());
        }
        byte[][] cachedT = new byte[cacheCount + 1][];
        for (int r = 1; r <= cacheCount; r++)
        {
            cachedT[r] = new byte[m];
            dIn.readFully(cachedT[r]);
        }
        key.primeTreeCache(cachedT);
    }

    LMOtsPrivateKey getCurrentOTSKey()
    {
        synchronized (this)
        {
            if (q >= maxQ)
            {
                throw new ExhaustedPrivateKeyException("ots private keys expired");
            }
            return new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
        }
    }

    /**
     * Return the key index (the q value).
     *
     * @return private key index number.
     */
    public synchronized int getIndex()
    {
        return q;
    }

    synchronized void incIndex()
    {
        q++;
    }

    public LMSContext generateLMSContext()
    {
        // Step 1.
        LMSigParameters lmsParameter = this.getSigParameters();

        // Step 2
        int h = lmsParameter.getH();
        int q = getIndex();
        LMOtsPrivateKey otsPk = getNextOtsPrivateKey();

        int i = 0;
        int r = (1 << h) + q;
        byte[][] path = new byte[h][];

        while (i < h)
        {
            int tmp = (r / (1 << i)) ^ 1;

            path[i] = this.findT(tmp);
            i++;
        }

        return otsPk.getSignatureContext(this.getSigParameters(), path);
    }

    public byte[] generateSignature(LMSContext context)
    {
        try
        {
            return LMS.generateSign(context).getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage(), e);
        }
    }

    LMOtsPrivateKey getNextOtsPrivateKey()
    {
        synchronized (this)
        {
            if (q >= maxQ)
            {
                throw new ExhaustedPrivateKeyException("ots private key exhausted");
            }
            LMOtsPrivateKey otsPrivateKey = new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
            incIndex();
            return otsPrivateKey;
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
    public LMSPrivateKeyParameters extractKeyShard(int usageCount)
    {
        synchronized (this)
        {
            if (usageCount < 0)
            {
                throw new IllegalArgumentException("usageCount cannot be negative");
            }
            if (usageCount > maxQ - q)
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }

            int shardIndex = q;
            int shardIndexLimit = q + usageCount;

            // Move this key's index along
            q = shardIndexLimit;

            return new LMSPrivateKeyParameters(this, shardIndex, shardIndexLimit);
        }
    }

    public LMSigParameters getSigParameters()
    {
        return parameters;
    }

    public LMOtsParameters getOtsParameters()
    {
        return otsParameters;
    }

    public byte[] getI()
    {
        return Arrays.clone(I);
    }

    public byte[] getMasterSecret()
    {
        return Arrays.clone(masterSecret);
    }

    public int getIndexLimit()
    {
        return maxQ;
    }

    // TODO Only needs 'int'
    public long getUsagesRemaining()
    {
        return getIndexLimit() - getIndex();
    }

    public LMSPublicKeyParameters getPublicKey()
    {
        synchronized (this)
        {
            if (publicKey == null)
            {
                publicKey = new LMSPublicKeyParameters(parameters, otsParameters, this.findT(T1), I);
            }
            return publicKey;
        }
    }

    byte[] findT(int r)
    {
        if (r < maxCacheR)
        {
            return findT(r < internedKeys.length ? internedKeys[r] : new CacheKey(r));
        }

        return calcT(r);
    }

    private byte[] findT(CacheKey key)
    {
        synchronized (tCache)
        {
            byte[] t = tCache.get(key);

            if (t != null)
            {
                return t;
            }

            t = calcT(key.index);
            tCache.put(key, t);

            return t;
        }
    }

    private byte[] calcT(int r)
    {
        int h = this.getSigParameters().getH();

        int twoToh = 1 << h;

        byte[] T;

        // r is a base 1 index.

        if (r >= twoToh)
        {
            LmsUtils.byteArray(this.getI(), tDigest);
            LmsUtils.u32str(r, tDigest);
            LmsUtils.u16str(LMS.D_LEAF, tDigest);
            //
            // These can be pre generated at the time of key generation and held within the private key.
            // However it will cost memory to have them stick around.
            //
            byte[] K = LM_OTS.lms_ots_generatePublicKey(this.getOtsParameters(), this.getI(), (r - twoToh), this.getMasterSecret());

            LmsUtils.byteArray(K, tDigest);
            T = new byte[tDigest.getDigestSize()];
            tDigest.doFinal(T, 0);
            return T;
        }

        byte[] t2r = findT(2 * r);
        byte[] t2rPlus1 = findT((2 * r + 1));

        LmsUtils.byteArray(this.getI(), tDigest);
        LmsUtils.u32str(r, tDigest);
        LmsUtils.u16str(LMS.D_INTR, tDigest);
        LmsUtils.byteArray(t2r, tDigest);
        LmsUtils.byteArray(t2rPlus1, tDigest);
        T = new byte[tDigest.getDigestSize()];
        tDigest.doFinal(T, 0);

        return T;
    }

    /**
     * Populate the node cache with the top-of-tree nodes recovered from the optional trailing
     * cache in a version 0 encoding. Entries are keyed on the interned cache keys so they are not
     * evicted, matching the state a freshly generated key reaches after its public key has been
     * derived.
     *
     * @param cachedT nodes indexed by tree node number; index 0 is unused, entries 1..n are cached.
     */
    void primeTreeCache(byte[][] cachedT)
    {
        synchronized (tCache)
        {
            for (int r = 1; r < cachedT.length; r++)
            {
                if (cachedT[r] != null)
                {
                    tCache.put(internedKeys[r], cachedT[r]);
                }
            }
        }
    }

    /**
     * Return true if the top of the Merkle tree is present in the node cache - either because
     * this key has been used/queried, or because it was decoded from the optional trailing data in
     * a version 0 encoding (see getEncoded). Used by the regression tests that verify tree-cache
     * persistence.
     */
    boolean isTreeCachePrimed()
    {
        synchronized (tCache)
        {
            return tCache.get(T1) != null;
        }
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

        LMSPrivateKeyParameters that = (LMSPrivateKeyParameters)o;

        if (q != that.q)
        {
            return false;
        }
        if (maxQ != that.maxQ)
        {
            return false;
        }
        if (!Arrays.areEqual(I, that.I))
        {
            return false;
        }
        if (parameters != null ? !parameters.equals(that.parameters) : that.parameters != null)
        {
            return false;
        }
        if (otsParameters != null ? !otsParameters.equals(that.otsParameters) : that.otsParameters != null)
        {
            return false;
        }
        if (!Arrays.constantTimeAreEqual(masterSecret, that.masterSecret))
        {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    public byte[] getEncoded()
        throws IOException
    {
        //
        // NB there is no formal specification for the encoding of private keys.
        // It is implementation dependent.
        //
        // Format:
        //     version u32                 (0)
        //     type u32
        //     otstype u32
        //     I u8x16
        //     q u32
        //     maxQ u32
        //     master secret Length u32
        //     master secret u8[]
        //     tree cache node count u32   (n; the top-of-tree nodes 1..n) - optional
        //     tree cache nodes u8[]       (n * getSigParameters().getM() bytes) - optional
        //
        // The tree cache carries the top of the Merkle tree so that the first signature made after
        // the key is decoded does not have to rebuild the whole tree - which otherwise costs about
        // as much as key generation (see github #2365). The nodes are a deterministic function of I,
        // the master secret and the parameters and are independent of q, so persisting them leaks
        // nothing the (already encoded) master secret does not. The cache is appended after the
        // master secret rather than announced by a new version number, so a key written by this
        // method is still readable by releases that predate it: their decoder returns at the end of
        // the master secret and never looks at the trailing bytes.
        //

        int cacheTop = Math.min(internedKeys.length, maxCacheR);

        Composer composer = Composer.compose()
            .u32str(0) // version
            .u32str(parameters.getType()) // type
            .u32str(otsParameters.getType()) // ots type
            .bytes(I) // I at 16 bytes
            .u32str(q) // q
            .u32str(maxQ) // maximum q
            .u32str(masterSecret.length) // length of master secret.
            .bytes(masterSecret) // the master secret
            .u32str(cacheTop - 1); // number of cached tree nodes (nodes 1 .. cacheTop-1)

        for (int r = 1; r < cacheTop; r++)
        {
            composer.bytes(findT(r)); // top-of-tree node r
        }

        return composer.build();
    }

    private static class CacheKey
    {
        private final int index;

        CacheKey(int index)
        {
            this.index = index;
        }

        public int hashCode()
        {
            return index;
        }

        public boolean equals(Object o)
        {
            if (o instanceof CacheKey)
            {
                return ((CacheKey)o).index == this.index;
            }

            return false;
        }
    }
}
