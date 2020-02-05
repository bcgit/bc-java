package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class HSSPublicKeyParameters
    extends HSSKeyParameters
{
    private final int l;
    private final LMSPublicKeyParameters lmsPublicKey;

    public HSSPublicKeyParameters(int l, LMSPublicKeyParameters lmsPublicKey)
    {
        super(false);

        this.l = l;
        this.lmsPublicKey = lmsPublicKey;
    }

    static HSSPublicKeyParameters getInstance(Object src)
        throws Exception
    {

        if (src instanceof LMSPublicKeyParameters)
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
            return getInstance(new DataInputStream(new ByteArrayInputStream((byte[])src)));
        }
        else if (src instanceof InputStream)
        {
            return getInstance(new DataInputStream((InputStream)src));
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }

    public int getL()
    {
        return l;
    }

    LMSPublicKeyParameters getLmsPublicKey()
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
