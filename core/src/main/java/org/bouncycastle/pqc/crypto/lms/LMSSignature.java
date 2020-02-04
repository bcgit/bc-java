package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.bouncycastle.util.Encodable;

public class LMSSignature
    implements Encodable
{
    private final int q;
    private final LMOtsSignature otsSignature;
    private final LmsParameter parameter;
    private final byte[][] y;

    public LMSSignature(int q, LMOtsSignature otsSignature, LmsParameter parameter, byte[][] y)
    {
        this.q = q;
        this.otsSignature = otsSignature;
        this.parameter = parameter;
        this.y = y;
    }

    public static LMSSignature getInstance(Object src)
        throws Exception
    {
        if (src instanceof LMSPublicKeyParameters)
        {
            return (LMSSignature)src;
        }
        else if (src instanceof DataInputStream)
        {

            int q = ((DataInputStream)src).readInt();
            LMOtsSignature otsSignature = LMOtsSignature.getInstance(src);
            LmsParameter type = LMSParameters.getParametersForType(((DataInputStream)src).readInt());

            byte[][] path = new byte[type.getH()][];
            for (int h = 0; h < path.length; h++)
            {
                path[h] = new byte[type.getM()];
                ((DataInputStream)src).readFully(path[h]);
            }

            return new LMSSignature(q, otsSignature, type, path);
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

        LMSSignature that = (LMSSignature)o;

        if (q != that.q)
        {
            return false;
        }
        if (otsSignature != null ? !otsSignature.equals(that.otsSignature) : that.otsSignature != null)
        {
            return false;
        }
        if (parameter != null ? !parameter.equals(that.parameter) : that.parameter != null)
        {
            return false;
        }
        return Arrays.deepEquals(y, that.y);
    }

    @Override
    public int hashCode()
    {
        int result = q;
        result = 31 * result + (otsSignature != null ? otsSignature.hashCode() : 0);
        result = 31 * result + (parameter != null ? parameter.hashCode() : 0);
        result = 31 * result + Arrays.deepHashCode(y);
        return result;
    }

    @Override
    public byte[] getEncoded()
        throws IOException
    {
        return Composer.compose()
            .u32str(q)
            .bytes(otsSignature.getEncoded())
            .u32str(parameter.getType())
            .bytes(y)
            .build();

    }

    public int getQ()
    {
        return q;
    }

    public LMOtsSignature getOtsSignature()
    {
        return otsSignature;
    }

    public LmsParameter getParameter()
    {
        return parameter;
    }

    public byte[][] getY()
    {
        return y;
    }
}
