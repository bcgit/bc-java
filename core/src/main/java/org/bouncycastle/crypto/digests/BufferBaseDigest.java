package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;

public abstract class BufferBaseDigest
    implements ExtendedDigest
{
    protected int DigestSize;
    protected int BlockSize;
    protected byte[] m_buf;
    protected int m_bufPos;
    protected String algorithmName;

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    @Override
    public int getDigestSize()
    {
        return DigestSize;
    }

    @Override
    public int getByteLength()
    {
        return BlockSize;
    }

    @Override
    public void update(byte in)
    {
        m_buf[m_bufPos] = in;
        if (++m_bufPos == BlockSize)
        {
            processBytes(m_buf, 0);
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
        int available = BlockSize - m_bufPos;
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
            processBytes(m_buf, 0);
        }
        int remaining;
        while ((remaining = len - inPos) >= BlockSize)
        {
            processBytes(input, inOff + inPos);
            inPos += 8;
        }
        System.arraycopy(input, inOff + inPos, m_buf, 0, remaining);
        m_bufPos = remaining;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        if (DigestSize + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        finish(output, outOff);
        reset();
        return DigestSize;
    }

    protected abstract void processBytes(byte[] input, int inOff);
    protected abstract void finish(byte[] output, int outOff);
}
