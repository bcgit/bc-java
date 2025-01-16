package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Longs;

abstract class AsconBaseEngine
    extends AEADBufferBaseEngine
{
    protected int nr;
    protected long K0;
    protected long K1;
    protected long N0;
    protected long N1;
    protected long ASCON_IV;
    protected long x0;
    protected long x1;
    protected long x2;
    protected long x3;
    protected long x4;
    protected long dsep; //domain separation

    protected abstract long pad(int i);

    protected abstract long loadBytes(byte[] in, int inOff);

    protected abstract void setBytes(long n, byte[] bs, int off);

    protected AsconBaseEngine(ProcessingBufferType type)
    {
        super(type);
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

    protected abstract void ascon_aeadinit();

    protected void finishAAD(State nextState)
    {
        // State indicates whether we ever received AAD
        switch (m_state)
        {
        case DecAad:
        case EncAad:
            processFinalAadBlock();
            p(nr);
            break;
        default:
            break;
        }
        // domain separation
        x4 ^= dsep;
        m_aadPos = 0;
        m_state = nextState;
    }

    protected abstract void processFinalAadBlock();

    protected abstract void processFinalDecrypt(byte[] input, int inLen, byte[] output, int outOff);

    protected abstract void processFinalEncrypt(byte[] input, int inLen, byte[] output, int outOff);

    protected void processBufferAAD(byte[] buffer, int inOff)
    {
        x0 ^= loadBytes(buffer, inOff);
        if (BlockSize == 16)
        {
            x1 ^= loadBytes(buffer, 8 + inOff);
        }
        p(nr);
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        if (forEncryption)
        {
            processFinalEncrypt(m_buf, m_bufPos, output, outOff);
        }
        else
        {
            processFinalDecrypt(m_buf, m_bufPos, output, outOff);
        }
        mac = new byte[MAC_SIZE];
        setBytes(x3, mac, 0);
        setBytes(x4, mac, 8);
    }

    @Override
    protected void processFinalAAD()
    {
        processFinalAadBlock();
        p(nr);
    }

    protected void processBufferDecrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
        long t0 = loadBytes(buffer, bufOff);
        setBytes(x0 ^ t0, output, outOff);
        x0 = t0;

        if (BlockSize == 16)
        {
            long t1 = loadBytes(buffer, bufOff + 8);
            setBytes(x1 ^ t1, output, outOff + 8);
            x1 = t1;
        }
        p(nr);
    }

    protected void processBufferEncrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
        x0 ^= loadBytes(buffer, bufOff);
        setBytes(x0, output, outOff);

        if (BlockSize == 16)
        {
            x1 ^= loadBytes(buffer, bufOff + 8);
            setBytes(x1, output, outOff + 8);
        }
        p(nr);
    }

    protected void reset(boolean clearMac)
    {
        bufferReset();
        ascon_aeadinit();
        super.reset(clearMac);
    }

    public abstract String getAlgorithmVersion();
}
