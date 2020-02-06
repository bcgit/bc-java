package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public class LMSPublicKeyParameters
    extends LMSKeyParameters
{
    private final LMSigParameters parameterSet;
    private final LMOtsParameters lmOtsType;
    private final byte[] I;
    private final byte[] T1;

    public LMSPublicKeyParameters(LMSigParameters parameterSet, LMOtsParameters lmOtsType, byte[] T1, byte[] I)
    {
        super(false);

        this.parameterSet = parameterSet;
        this.lmOtsType = lmOtsType;
        this.I = I;
        this.T1 = T1;
    }

    public static LMSPublicKeyParameters getInstance(Object src)
        throws IOException
    {
        if (src instanceof LMSPublicKeyParameters)
        {
            return (LMSPublicKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            int pubType = ((DataInputStream)src).readInt();
            LMSigParameters lmsParameter = LMSigParameters.getParametersForType(pubType);
            LMOtsParameters ostTypeCode = LMOtsParameters.getParametersForType(((DataInputStream)src).readInt());

            byte[] I = new byte[16];
            ((DataInputStream)src).readFully(I);

            byte[] T1 = new byte[lmsParameter.getM()];
            ((DataInputStream)src).readFully(T1);
            return new LMSPublicKeyParameters(lmsParameter, ostTypeCode, T1, I);
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
            return getInstance(new DataInputStream((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    public byte[] getEncoded()
        throws IOException
    {
        return this.toByteArray();
    }

    public LMSigParameters getSigParameters()
    {
        return parameterSet;
    }

    public LMOtsParameters getOtsParameters()
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

        LMSPublicKeyParameters publicKey = (LMSPublicKeyParameters)o;

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

    byte[] toByteArray()
    {
        return Composer.compose()
            .u32str(parameterSet.getType())
            .u32str(lmOtsType.getType())
            .bytes(I)
            .bytes(T1)
            .build();
    }
}
