package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.pqc.crypto.lms.exceptions.LMSException;
import org.bouncycastle.pqc.crypto.lms.exceptions.LMSPrivateKeyExhaustionException;
import org.bouncycastle.util.Encodable;

public class LmsPrivateKey
    implements Encodable
{

    private final byte[] I;
    private final LmsParameter parameterSet;
    private final LmOtsParameter lmOtsParameter;
    private final int maxQ;
    private final byte[] masterSecret;
    private int q;
    //
    // These are not final because they can be generated.
    // They also do not need to be persisted.
    //
    private LmsPublicKey publicKey;
    private byte[] T1;



    public LmsPrivateKey(LmsParameter lmsParameter, LmOtsParameter lmOtsParameter, int q, byte[] I, int maxQ, byte[] masterSecret)
    {
        this.parameterSet = lmsParameter;
        this.lmOtsParameter = lmOtsParameter;
        this.q = q;
        this.I = I;
        this.maxQ = maxQ;
        this.masterSecret = masterSecret;
    }

    public static LmsPrivateKey getInstance(Object src, int secretSizeLimit)
        throws Exception
    {
        if (src instanceof LmsPublicKey)
        {
            return (LmsPrivateKey)src;
        }
        else if (src instanceof DataInputStream)
        {
            if (((DataInputStream)src).readInt() != 0)
            {
                throw new LMSException("expected vetsion 0 lms private key");
            }

            LmsParameter parameter = LmsParameters.getParametersForType(((DataInputStream)src).readInt());
            LmOtsParameter otsParameter = LmOtsParameters.getOtsParameter(((DataInputStream)src).readInt());
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

            return new LmsPrivateKey(parameter, otsParameter, q, I, maxQ, masterSecret);

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


    LmOtsPrivateKey getCurrentOTSKey()
        throws LMSException
    {
        synchronized (this)
        {
            if (q >= maxQ)
            {
                throw new LMSPrivateKeyExhaustionException("ots private keys expired");
            }
            LmOtsPrivateKey otsPrivateKey = new LmOtsPrivateKey(lmOtsParameter, I, q, masterSecret);
            return otsPrivateKey;
        }
    }

    public LmOtsPrivateKey getNextOtsPrivateKey()
        throws LMSException
    {
        synchronized (this)
        {
            if (q >= maxQ)
            {
                throw new LMSPrivateKeyExhaustionException("ots private keys expired");
            }
            LmOtsPrivateKey otsPrivateKey = new LmOtsPrivateKey(lmOtsParameter, I, q, masterSecret);
            q++;
            return otsPrivateKey;
        }
    }

    public LmsParameter getParameterSet()
    {
        return parameterSet;
    }

    public LmOtsParameter getLmOtsType()
    {
        return lmOtsParameter;
    }

    public int getQ()
    {
        return q;
    }

    public byte[] getI()
    {
        return I;
    }

    public int getMaxQ()
    {
        return maxQ;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }

    public boolean hasRemainingOTSPrivateKeys()
    {
        return q < maxQ;
    }


    public LmsPublicKey getPublicKey()
        throws LMSException
    {
        synchronized (this)
        {
            if (publicKey == null)
            {

                T1 = LMS.appendixC(this);

                publicKey = new LmsPublicKey(parameterSet, lmOtsParameter, T1, I);
            }
            return publicKey;
        }
    }

    public byte[] getT1()
        throws LMSException
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


    public LmOtsParameter getLmOtsParameter()
    {
        return lmOtsParameter;
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

        LmsPrivateKey that = (LmsPrivateKey)o;

        if (q != that.q)
        {
            return false;
        }
        if (maxQ != that.maxQ)
        {
            return false;
        }
        if (!Arrays.equals(I, that.I))
        {
            return false;
        }
        if (parameterSet != null ? !parameterSet.equals(that.parameterSet) : that.parameterSet != null)
        {
            return false;
        }
        if (lmOtsParameter != null ? !lmOtsParameter.equals(that.lmOtsParameter) : that.lmOtsParameter != null)
        {
            return false;
        }
        if (!Arrays.equals(masterSecret, that.masterSecret))
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
        result = 31 * result + (parameterSet != null ? parameterSet.hashCode() : 0);
        result = 31 * result + (lmOtsParameter != null ? lmOtsParameter.hashCode() : 0);
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
            .u32str(parameterSet.getType()) // type
            .u32str(lmOtsParameter.getType()) // ots type
            .bytes(I) // I at 16 bytes
            .u32str(q) // q
            .u32str(maxQ) // maximum q
            .u32str(masterSecret.length) // length of master secret.
            .bytes(masterSecret) // the master secret
            .build();

    }
}
