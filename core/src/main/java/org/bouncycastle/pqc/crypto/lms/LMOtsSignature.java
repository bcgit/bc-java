package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.util.Encodable;

public class LMOtsSignature
    implements Encodable
{
    private final LmOtsParameters type;
    private final byte[] C;
    private final byte[] y;

    public LMOtsSignature(LmOtsParameters type, byte[] c, byte[] y)
    {
        this.type = type;
        C = c;
        this.y = y;
    }

    public static LMOtsSignature getInstance(Object src)
        throws Exception
    {
        if (src instanceof LMSPublicKeyParameters)
        {
            return (LMOtsSignature)src;
        }
        else if (src instanceof DataInputStream)
        {


            LmOtsParameters type = LmOtsParameters.getParametersForType(((DataInputStream)src).readInt());
            byte[] C = new byte[type.getN()];

            ((DataInputStream)src).readFully(C);

            byte[] sig = new byte[type.getP()*type.getN()];
            ((DataInputStream)src).readFully(sig);


            return new LMOtsSignature(type, C, sig);
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


    public LmOtsParameters getType()
    {
        return type;
    }

    public byte[] getC()
    {
        return C;
    }

    public byte[] getY()
    {
        return y;
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

        LMOtsSignature that = (LMOtsSignature)o;

        if (type != null ? !type.equals(that.type) : that.type != null)
        {
            return false;
        }
        if (!Arrays.equals(C, that.C))
        {
            return false;
        }
        return Arrays.equals(y, that.y);
    }

    @Override
    public int hashCode()
    {
        int result = type != null ? type.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(C);
        result = 31 * result + Arrays.hashCode(y);
        return result;
    }

    @Override
    public byte[] getEncoded()
        throws IOException
    {
        return Composer.compose()
            .u32str(type.getType())
            .bytes(C)
            .bytes(y)
            .build();
    }
}
