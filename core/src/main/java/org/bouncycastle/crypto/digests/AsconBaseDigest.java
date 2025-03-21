package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.AsconPermutationFriend;

abstract class AsconBaseDigest
    extends BufferBaseDigest
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();

        private Friend()
        {
        }
    }

    AsconPermutationFriend.AsconPermutation p;
    protected int ASCON_PB_ROUNDS = 12;

    protected AsconBaseDigest()
    {
        super(ProcessingBufferType.Immediate, 8);
        p = AsconPermutationFriend.getAsconPermutation(ISAPDigest.Friend.getFriend(Friend.INSTANCE));
        DigestSize = 32;
    }

    protected abstract long pad(int i);

    protected abstract long loadBytes(final byte[] bytes, int inOff);

    protected abstract long loadBytes(final byte[] bytes, int inOff, int n);

    protected abstract void setBytes(long w, byte[] bytes, int inOff);

    protected abstract void setBytes(long w, byte[] bytes, int inOff, int n);

    protected void processBytes(byte[] input, int inOff)
    {
        p.x0 ^= loadBytes(input, inOff);
        p.p(ASCON_PB_ROUNDS);
    }

    protected void finish(byte[] output, int outOff)
    {
        padAndAbsorb();
        /* squeeze full output blocks */
        squeeze(output, outOff, DigestSize);
    }

    protected void padAndAbsorb()
    {
        p.x0 ^= loadBytes(m_buf, 0, m_bufPos) ^ pad(m_bufPos);
        p.p(12);
    }

    protected void squeeze(byte[] output, int outOff, int len)
    {
        /* squeeze full output blocks */
        while (len > BlockSize)
        {
            setBytes(p.x0, output, outOff);
            p.p(ASCON_PB_ROUNDS);
            outOff += BlockSize;
            len -= BlockSize;
        }
        /* squeeze final output block */
        setBytes(p.x0, output, outOff, len);
    }

    protected int hash(byte[] output, int outOff, int outLen)
    {
        ensureSufficientOutputBuffer(output, outOff, outLen);
        padAndAbsorb();
        /* squeeze full output blocks */
        squeeze(output, outOff, outLen);
        return outLen;
    }

    protected void ensureSufficientOutputBuffer(byte[] output, int outOff, int len)
    {
        if (outOff + len > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
    }
}
