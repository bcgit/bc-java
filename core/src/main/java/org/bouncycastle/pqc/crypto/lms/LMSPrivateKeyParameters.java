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

public class LMSPrivateKeyParameters
    extends LMSKeyParameters
    implements LMSContextBasedSigner
{
    private static CacheKey T1 = new CacheKey(1);
    private static CacheKey[] internedKeys = new CacheKey[129];

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
        this.tDigest = DigestUtil.getDigest(lmsParameter.getDigestOID());
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
        this.tDigest = DigestUtil.getDigest(parameters.getDigestOID());
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

            LMSigParameters parameter = LMSigParameters.getParametersForType(dIn.readInt());
            LMOtsParameters otsParameter = LMOtsParameters.getParametersForType(dIn.readInt());
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
            if (q + usageCount >= maxQ)
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
            LMSPrivateKeyParameters keyParameters = new LMSPrivateKeyParameters(this, q, q + usageCount);
            q += usageCount;

            return keyParameters;
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

    public long getUsagesRemaining()
    {
        return maxQ - q;
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
        if (!Arrays.areEqual(masterSecret, that.masterSecret))
        {
            return false;
        }

        //
        // Only compare public keys if they both exist.
        // Otherwise we would trigger the creation of one or both of them
        //
        if (publicKey != null && that.publicKey != null)
        {
            return publicKey.equals(that.publicKey);
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = q;
        result = 31 * result + Arrays.hashCode(I);
        result = 31 * result + (parameters != null ? parameters.hashCode() : 0);
        result = 31 * result + (otsParameters != null ? otsParameters.hashCode() : 0);
        result = 31 * result + maxQ;
        result = 31 * result + Arrays.hashCode(masterSecret);
        result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
        return result;
    }

    public byte[] getEncoded()
        throws IOException
    {
        //
        // NB there is no formal specification for the encoding of private keys.
        // It is implementation dependent.
        //
        // Format:
        //     version u32
        //     type u32
        //     otstype u32
        //     I u8x16
        //     q u32
        //     maxQ u32
        //     master secret Length u32
        //     master secret u8[]
        //

        return Composer.compose()
            .u32str(0) // version
            .u32str(parameters.getType()) // type
            .u32str(otsParameters.getType()) // ots type
            .bytes(I) // I at 16 bytes
            .u32str(q) // q
            .u32str(maxQ) // maximum q
            .u32str(masterSecret.length) // length of master secret.
            .bytes(masterSecret) // the master secret
            .build();
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
