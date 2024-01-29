package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.io.LimitedBuffer;

public class Prehash
    implements Digest
{
    public static Prehash forDigest(Digest digest)
    {
        return new Prehash(digest);
    }

    private final String algorithmName;
    private final LimitedBuffer buf;

    private Prehash(Digest digest)
    {
        algorithmName = digest.getAlgorithmName();
        buf = new LimitedBuffer(digest.getDigestSize());
    }

    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getDigestSize()
    {
        return buf.limit();
    }

    public void update(byte in)
    {
        buf.write(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        buf.write(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        try
        {
            if (getDigestSize() != buf.size())
            {
                throw new IllegalStateException("Incorrect prehash size");
            }

            return buf.copyTo(out, outOff);
        }
        finally
        {
            reset();
        }
    }

    public void reset()
    {
        buf.reset();
    }
}
