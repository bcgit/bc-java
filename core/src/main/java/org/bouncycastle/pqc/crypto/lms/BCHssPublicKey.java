package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class BCHssPublicKey
    implements HssPublicKey
{
    private final int l;
    private final LmsPublicKey lmsPublicKey;

    public BCHssPublicKey(int l, LmsPublicKey lmsPublicKey)
    {
        this.l = l;
        this.lmsPublicKey = lmsPublicKey;
    }

    static BCHssPublicKey getInstance(Object src)
        throws Exception
    {

        if (src instanceof LmsPublicKey)
        {
            return (BCHssPublicKey)src;
        }
        else if (src instanceof DataInputStream)
        {

            int L = ((DataInputStream)src).readInt();
            LmsPublicKey lmsPublicKey = LmsPublicKey.getInstance(src);
            return new BCHssPublicKey(L, lmsPublicKey);
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
    public int getL()
    {
        return l;
    }

    @Override
    public LmsPublicKey getLmsPublicKey()
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

        BCHssPublicKey publicKey = (BCHssPublicKey)o;

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
