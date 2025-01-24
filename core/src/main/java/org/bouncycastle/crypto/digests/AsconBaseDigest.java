package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;

abstract class AsconBaseDigest
    extends BufferBaseDigest
{
    protected long x0;
    protected long x1;
    protected long x2;
    protected long x3;
    protected long x4;
    protected int ASCON_PB_ROUNDS = 12;

    protected AsconBaseDigest()
    {
        DigestSize = 32;
        BlockSize = 8;
        m_buf = new byte[BlockSize];
    }

    private void round(long C)
    {
        long t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
        long t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
        long t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
        long t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
        long t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
        x0 = t0 ^ Longs.rotateRight(t0, 19) ^ Longs.rotateRight(t0, 28);
        x1 = t1 ^ Longs.rotateRight(t1, 39) ^ Longs.rotateRight(t1, 61);
        x2 = ~(t2 ^ Longs.rotateRight(t2, 1) ^ Longs.rotateRight(t2, 6));
        x3 = t3 ^ Longs.rotateRight(t3, 10) ^ Longs.rotateRight(t3, 17);
        x4 = t4 ^ Longs.rotateRight(t4, 7) ^ Longs.rotateRight(t4, 41);
    }

    protected void p(int nr)
    {
        if (nr == 12)
        {
            round(0xf0L);
            round(0xe1L);
            round(0xd2L);
            round(0xc3L);
        }
        if (nr >= 8)
        {
            round(0xb4L);
            round(0xa5L);
        }
        round(0x96L);
        round(0x87L);
        round(0x78L);
        round(0x69L);
        round(0x5aL);
        round(0x4bL);
    }

    protected abstract long pad(int i);

    protected abstract long loadBytes(final byte[] bytes, int inOff);

    protected abstract long loadBytes(final byte[] bytes, int inOff, int n);

    protected abstract void setBytes(long w, byte[] bytes, int inOff);

    protected abstract void setBytes(long w, byte[] bytes, int inOff, int n);

    protected void processBytes(byte[] input, int inOff)
    {
        x0 ^= loadBytes(input, inOff);
        p(ASCON_PB_ROUNDS);
    }

    protected void finish(byte[] output, int outOff)
    {
        padAndAbsorb();
        /* squeeze full output blocks */
        squeeze(output, outOff, DigestSize);
    }

    protected void padAndAbsorb()
    {
        x0 ^= loadBytes(m_buf, 0, m_bufPos);
        x0 ^= pad(m_bufPos);
        p(12);
    }

    protected void squeeze(byte[] output, int outOff, int len)
    {
        /* squeeze full output blocks */
        while (len > BlockSize)
        {
            setBytes(x0, output, outOff);
            p(ASCON_PB_ROUNDS);
            outOff += BlockSize;
            len -= BlockSize;
        }
        /* squeeze final output block */
        setBytes(x0, output, outOff, len);
        reset();
    }

    protected int hash(byte[] output, int outOff, int outLen)
    {
        if (DigestSize + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        padAndAbsorb();
        /* squeeze full output blocks */
        squeeze(output, outOff, outLen);
        return outLen;
    }

    public void reset()
    {
        Arrays.clear(m_buf);
        m_bufPos = 0;
    }
}
