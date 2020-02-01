package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.util.Arrays;

public class LmsPublicKey
{
    private final LmsParameter parameterSet;
    private final LmOtsParameter lmOtsType;
    private final byte[] I;
    private final byte[] T1;


    public LmsPublicKey(LmsParameter parameterSet, LmOtsParameter lmOtsType, byte[] T1, byte[] I)
    {
        this.parameterSet = parameterSet;
        this.lmOtsType = lmOtsType;
        this.I = I;
        this.T1 = T1;
    }

    public static LmsPublicKey getInstance(Object src)
        throws Exception
    {
        if (src instanceof LmsPublicKey)
        {
            return (LmsPublicKey)src;
        }
        else if (src instanceof DataInputStream)
        {

            int pubType = ((DataInputStream)src).readInt();
            LmsParameter lmsParameter = LmsParameters.getParametersForType(pubType);
            LmOtsParameter ostTypeCode = LmOtsParameters.getOtsParameter(((DataInputStream)src).readInt());

            byte[] I = new byte[16];
            ((DataInputStream)src).readFully(I);

            byte[] T1 = new byte[lmsParameter.getM()];
            ((DataInputStream)src).readFully(T1);
            return new LmsPublicKey(lmsParameter, ostTypeCode, T1, I);
        }
        else if (src instanceof byte[])
        {
            return getInstance(new DataInputStream(new ByteArrayInputStream((byte[])src)));
        }
        else if (src instanceof InputStream)
        {
            return getInstance(new DataInputStream((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    public byte[] getEncoded()
    {
        return Composer.compose()
            .u32str(parameterSet.getType())
            .u32str(lmOtsType.getType())
            .bytes(I)
            .bytes(T1)
            .build();
    }

    public LmsParameter getParameterSet()
    {
        return parameterSet;
    }

    public LmOtsParameter getLmOtsType()
    {
        return lmOtsType;
    }

    public byte[] getT1()
    {
        return T1;
    }

    public byte[] getI()
    {
        return I;
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

        LmsPublicKey publicKey = (LmsPublicKey)o;

        if (!parameterSet.equals(publicKey.parameterSet))
        {
            return false;
        }
        if (!lmOtsType.equals(publicKey.lmOtsType))
        {
            return false;
        }
        if (!Arrays.equals(I, publicKey.I))
        {
            return false;
        }
        return Arrays.equals(T1, publicKey.T1);
    }

    @Override
    public int hashCode()
    {
        int result = parameterSet.hashCode();
        result = 31 * result + lmOtsType.hashCode();
        result = 31 * result + Arrays.hashCode(I);
        result = 31 * result + Arrays.hashCode(T1);
        return result;
    }
}
