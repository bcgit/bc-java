package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

public class HSSPublicKeyParameters
    extends LMSKeyParameters
{
    private final int l;
    private final LMSPublicKeyParameters lmsPublicKey;

    public HSSPublicKeyParameters(int l, LMSPublicKeyParameters lmsPublicKey)
    {
        super(false);

        this.l = l;
        this.lmsPublicKey = lmsPublicKey;
    }

    public static HSSPublicKeyParameters getInstance(Object src)
        throws IOException
    {
        if (src instanceof HSSPublicKeyParameters)
        {
            return (HSSPublicKeyParameters)src;
        }
        else if (src instanceof DataInputStream)
        {
            int L = ((DataInputStream)src).readInt();
            LMSPublicKeyParameters lmsPublicKey = LMSPublicKeyParameters.getInstance(src);
            return new HSSPublicKeyParameters(L, lmsPublicKey);
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
                if (in != null) in.close();
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

    public LMSPublicKeyParameters getLMSPublicKey()
    {
        return lmsPublicKey;
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

        HSSPublicKeyParameters publicKey = (HSSPublicKeyParameters)o;

        if (l != publicKey.l)
        {
            return false;
        }
        return lmsPublicKey.equals(publicKey.lmsPublicKey);
    }

    @Override
    public int hashCode()
    {
        int result = l;
        result = 31 * result + lmsPublicKey.hashCode();
        return result;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return Composer.compose().u32str(l)
            .bytes(lmsPublicKey.getEncoded())
            .build();
    }
}
