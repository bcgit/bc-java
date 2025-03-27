package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Xof;

abstract class AsconXofBase
    extends AsconBaseDigest
    implements Xof
{
    private boolean m_squeezing;
    private final byte[] buffer = new byte[BlockSize];
    private int bytesInBuffer;

    @Override
    public void update(byte in)
    {
        ensureNoAbsorbWhileSqueezing(m_squeezing);
        super.update(in);
    }

    @Override
    public void update(byte[] input, int inOff, int len)
    {
        ensureNoAbsorbWhileSqueezing(m_squeezing);
        super.update(input, inOff, len);
    }

    @Override
    public int doOutput(byte[] output, int outOff, int outLen)
    {
        ensureSufficientOutputBuffer(output, outOff, outLen);

        /* Use buffered output first */
        int bytesOutput = 0;
        if (bytesInBuffer != 0)
        {
            int startPos = BlockSize - bytesInBuffer;
            int bytesToOutput = Math.min(outLen, bytesInBuffer);
            System.arraycopy(buffer, startPos, output, outOff, bytesToOutput);
            bytesInBuffer -= bytesToOutput;
            bytesOutput += bytesToOutput;
        }

        int available = outLen - bytesOutput;
        /* If we still need to output data */
        if (available >= BlockSize)
        {
            /* Output full blocks */
            int bytesToOutput = available - available % BlockSize;
            bytesOutput += hash(output, outOff + bytesOutput, bytesToOutput);
        }

        /* If we need to output a partial buffer */
        if (bytesOutput < outLen)
        {
            /* Access the next buffer's worth of data */
            hash(buffer, 0, BlockSize);

            /* Copy required length of data */
            int bytesToOutput = outLen - bytesOutput;
            System.arraycopy(buffer, 0, output, outOff + bytesOutput, bytesToOutput);
            bytesInBuffer = buffer.length - bytesToOutput;
            bytesOutput += bytesToOutput;
        }

        /* return the length of data output */
        return bytesOutput;
    }

    @Override
    public int doFinal(byte[] output, int outOff, int outLen)
    {
        int rlt = doOutput(output, outOff, outLen);
        reset();
        return rlt;
    }

    @Override
    public void reset()
    {
        m_squeezing = false;
        bytesInBuffer = 0;
        super.reset();
    }

    @Override
    protected void padAndAbsorb()
    {
        if (!m_squeezing)
        {
            m_squeezing = true;
            super.padAndAbsorb();
        }
        else
        {
            p.p(ASCON_PB_ROUNDS);
        }
    }

    private void ensureNoAbsorbWhileSqueezing(boolean m_squeezing)
    {
        if (m_squeezing)
        {
            throw new IllegalStateException("attempt to absorb while squeezing");
        }
    }
}
