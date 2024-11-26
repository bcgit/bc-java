package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;

abstract class AsconBaseDigest
    implements ExtendedDigest
{
    protected long x0;
    protected long x1;
    protected long x2;
    protected long x3;
    protected long x4;
    protected final int CRYPTO_BYTES = 32;
    protected final int ASCON_HASH_RATE = 8;
    protected int ASCON_PB_ROUNDS = 12;
    protected final byte[] m_buf = new byte[ASCON_HASH_RATE];
    protected int m_bufPos = 0;


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

    @Override
    public int getDigestSize()
    {
        return CRYPTO_BYTES;
    }

    @Override
    public int getByteLength()
    {
        return ASCON_HASH_RATE;
    }

    @Override
    public void update(byte in)
    {
        m_buf[m_bufPos] = in;
        if (++m_bufPos == ASCON_HASH_RATE)
        {
            x0 ^= loadBytes(m_buf, 0);
            p(ASCON_PB_ROUNDS);
            m_bufPos = 0;
        }
    }

    @Override
    public void update(byte[] input, int inOff, int len)
    {
        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        int available = 8 - m_bufPos;
        if (len < available)
        {
            System.arraycopy(input, inOff, m_buf, m_bufPos, len);
            m_bufPos += len;
            return;
        }
        int inPos = 0;
        if (m_bufPos > 0)
        {
            System.arraycopy(input, inOff, m_buf, m_bufPos, available);
            inPos += available;
            x0 ^= loadBytes(m_buf, 0);
            p(ASCON_PB_ROUNDS);
        }
        int remaining;
        while ((remaining = len - inPos) >= 8)
        {
            x0 ^= loadBytes(input, inOff + inPos);
            p(ASCON_PB_ROUNDS);
            inPos += 8;
        }
        System.arraycopy(input, inOff + inPos, m_buf, 0, remaining);
        m_bufPos = remaining;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        return hash(output, outOff, CRYPTO_BYTES);
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
        while (len > ASCON_HASH_RATE)
        {
            setBytes(x0, output, outOff);
            p(ASCON_PB_ROUNDS);
            outOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* squeeze final output block */
        setBytes(x0, output, outOff, len);
        reset();
    }

    protected int hash(byte[] output, int outOff, int outLen)
    {
        if (CRYPTO_BYTES + outOff > output.length)
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
