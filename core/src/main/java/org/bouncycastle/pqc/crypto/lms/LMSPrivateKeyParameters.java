package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.util.Arrays;

public class LMSPrivateKeyParameters
    extends LMSKeyParameters
{
    private final byte[] I;
    private final LMSigParameters parameters;
    private final LMOtsParameters otsParameters;
    private final int maxQ;
    private final byte[] masterSecret;
    
    private int q;
    
    //
    // These are not final because they can be generated.
    // They also do not need to be persisted.
    //
    private LMSPublicKeyParameters publicKey;
    private byte[] T1;

    public LMSPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I, int maxQ, byte[] masterSecret)
    {
        super(true);

        this.parameters = lmsParameter;
        this.otsParameters = otsParameters;
        this.q = q;
        this.I = Arrays.clone(I);
        this.maxQ = maxQ;
        this.masterSecret = Arrays.clone(masterSecret);
    }

    public static LMSPrivateKeyParameters getInstance(Object src, int secretSizeLimit)
        throws Exception
    {
        if (src instanceof LMSPublicKeyParameters)
        {
            return (LMSPrivateKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            if (((DataInputStream)src).readInt() != 0)
            {
                throw new LMSException("expected version 0 lms private key");
            }

            LMSigParameters parameter = LMSigParameters.getParametersForType(((DataInputStream)src).readInt());
            LMOtsParameters otsParameter = LMOtsParameters.getParametersForType(((DataInputStream)src).readInt());
            byte[] I = new byte[16];
            ((DataInputStream)src).readFully(I);

            int q = ((DataInputStream)src).readInt();
            int maxQ = ((DataInputStream)src).readInt();
            int l = ((DataInputStream)src).readInt();
            if (l < 0)
            {
                throw new LMSException("secret length less than zero");
            }
            if (l > secretSizeLimit)
            {
                throw new LMSException("secret length exceeded " + secretSizeLimit);
            }
            byte[] masterSecret = new byte[l];
            ((DataInputStream)src).readFully(masterSecret);

            return new LMSPrivateKeyParameters(parameter, otsParameter, q, I, maxQ, masterSecret);

        }
        else if (src instanceof byte[])
        {
            return getInstance(new DataInputStream(new ByteArrayInputStream((byte[])src)), secretSizeLimit);
        }
        else if (src instanceof InputStream)
        {
            return getInstance(new DataInputStream((InputStream)src), secretSizeLimit);
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
            LMOtsPrivateKey otsPrivateKey = new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
            return otsPrivateKey;
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

    LMOtsPrivateKey getNextOtsPrivateKey()
    {
        synchronized (this)
        {
            if (q >= maxQ)
            {
                throw new ExhaustedPrivateKeyException("ots private key exhausted");
            }
            LMOtsPrivateKey otsPrivateKey = new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
            q++;
            return otsPrivateKey;
        }
    }

    public LMSPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            LMSPrivateKeyParameters keyParameters = this.extractKeyShard(1);

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
    public LMSPrivateKeyParameters extractKeyShard(int usageCount)
    {
        synchronized (this)
        {
            if (q + usageCount >= maxQ)
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
            LMSPrivateKeyParameters keyParameters = new LMSPrivateKeyParameters(parameters, otsParameters, q, I, q + usageCount, masterSecret);
            q += usageCount;

            return keyParameters;
        }
    }

    public LMSigParameters getParameters()
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

    public int getMaxQ()
    {
        return maxQ;
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

                T1 = LMS.appendixC(this);

                publicKey = new LMSPublicKeyParameters(parameters, otsParameters, T1, I);
            }
            return publicKey;
        }
    }

    public byte[] getT1()
    {
        synchronized (this)
        {
            // if we have a T array then use that.
            if (T1 == null)
            {
                //
                // Otherwise use the Appendix C alg to calculate the T1 value.
                //
                T1 = getPublicKey().getT1();
            }
            return T1;
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
        // It is implementation independent.
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
}
