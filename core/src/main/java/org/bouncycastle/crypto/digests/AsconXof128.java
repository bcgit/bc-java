package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Pack;

/**
 * Ascon-XOF128 was introduced in NIST Special Publication (SP) 800-232
 * (Initial Public Draft).
 * <p>
 * Additional details and the specification can be found in:
 * <a href="https://csrc.nist.gov/pubs/sp/800/232/ipd">NIST SP 800-232 (Initial Public Draft)</a>.
 * For reference source code and implementation details, please see:
 * <a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
 * ASM implementations of Ascon (NIST SP 800-232)</a>.
 * </p>
 */
public class AsconXof128
    extends AsconBaseDigest
    implements Xof
{
    protected boolean m_squeezing = false;

    private final byte[] buffer = new byte[ASCON_HASH_RATE];
    protected int bytesInBuffer;

    public AsconXof128()
    {
        this(true);
    }

    protected AsconXof128(final boolean doReset)
    {
        if (doReset)
        {
            reset();
        }
    }

    protected long pad(int i)
    {
        return 0x01L << (i << 3);
    }

    protected long loadBytes(final byte[] bytes, int inOff)
    {
        return Pack.littleEndianToLong(bytes, inOff);
    }

    protected long loadBytes(final byte[] bytes, int inOff, int n)
    {
        return Pack.littleEndianToLong(bytes, inOff, n);
    }

    protected void setBytes(long w, byte[] bytes, int inOff)
    {
        Pack.longToLittleEndian(w, bytes, inOff);
    }

    protected void setBytes(long w, byte[] bytes, int inOff, int n)
    {
        Pack.longToLittleEndian(w, bytes, inOff, n);
    }

    protected void padAndAbsorb()
    {
        if (!m_squeezing)
        {
            m_squeezing = true;
            super.padAndAbsorb();
        }
        else
        {
            p(ASCON_PB_ROUNDS);
        }
    }

    @Override
    public String getAlgorithmName()
    {
        return "Ascon-XOF-128";
    }

    @Override
    public void update(byte in)
    {
        if (m_squeezing)
        {
            throw new IllegalArgumentException("attempt to absorb while squeezing");
        }
        super.update(in);
    }

    @Override
    public void update(byte[] input, int inOff, int len)
    {
        if (m_squeezing)
        {
            throw new IllegalArgumentException("attempt to absorb while squeezing");
        }
        super.update(input, inOff, len);
    }

    @Override
    public int doOutput(byte[] output, int outOff, int outLen)
    {
        if (outLen + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }

        /* Use buffered output first */
        int bytesOutput = 0;
        if (bytesInBuffer != 0)
        {
            int startPos = ASCON_HASH_RATE - bytesInBuffer;
            int bytesToOutput = Math.min(outLen, bytesInBuffer);
            System.arraycopy(buffer, startPos, output, outOff, bytesToOutput);
            bytesInBuffer -= bytesToOutput;
            bytesOutput += bytesToOutput;
        }

        /* If we still need to output data */
        if (outLen - bytesOutput >= ASCON_HASH_RATE)
        {
            /* Output full blocks */
            int bytesToOutput = ASCON_HASH_RATE * ((outLen - bytesOutput) / ASCON_HASH_RATE);
            bytesOutput += hash(output, outOff + bytesOutput, bytesToOutput);
        }

        /* If we need to output a partial buffer */
        if (bytesOutput < outLen)
        {
            /* Access the next buffer's worth of data */
            hash(buffer, 0, ASCON_HASH_RATE);

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
    public int getByteLength()
    {
        return 8;
    }

    @Override
    public void reset()
    {
        m_squeezing = false;
        bytesInBuffer = 0;
        super.reset();
        /* initialize */
        x0 = -2701369817892108309L;
        x1 = -3711838248891385495L;
        x2 = -1778763697082575311L;
        x3 = 1072114354614917324L;
        x4 = -2282070310009238562L;
    }

    protected void baseReset()
    {
        super.reset();
    }
}
