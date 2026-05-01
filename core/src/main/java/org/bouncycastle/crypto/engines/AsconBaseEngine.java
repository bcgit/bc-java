package org.bouncycastle.crypto.engines;

abstract class AsconBaseEngine
    extends AEADBaseEngine
{
    protected int nr;
    protected long K0;
    protected long K1;
    protected long N0;
    protected long N1;
    protected long ASCON_IV;
    AsconPermutationFriend.AsconPermutation p = new AsconPermutationFriend.AsconPermutation();
    protected long dsep; //domain separation

    protected abstract long pad(int i);

    protected abstract long loadBytes(byte[] in, int inOff);

    protected abstract void setBytes(long n, byte[] bs, int off);

    protected abstract void ascon_aeadinit();

    protected void finishAAD(State nextState, boolean isDofinal)
    {
        // State indicates whether we ever received AAD
        switch (m_state.ord)
        {
        case State.DEC_AAD:
        case State.ENC_AAD:
            this.processFinalAAD();
            p.p(nr);
            break;
        default:
            break;
        }
        // domain separation
        p.x4 ^= dsep;
        m_aadPos = 0;
        m_state = nextState;
    }

    protected abstract void processFinalDecrypt(byte[] input, int inLen, byte[] output, int outOff);

    protected abstract void processFinalEncrypt(byte[] input, int inLen, byte[] output, int outOff);

    protected void processBufferAAD(byte[] buffer, int inOff)
    {
        p.x0 ^= loadBytes(buffer, inOff);
        if (BlockSize == 16)
        {
            p.x1 ^= loadBytes(buffer, 8 + inOff);
        }
        p.p(nr);
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
        setBytes(p.x3, mac, 0);
        setBytes(p.x4, mac, 8);
    }

    protected void processBufferDecrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
        long t0 = loadBytes(buffer, bufOff);
        setBytes(p.x0 ^ t0, output, outOff);
        p.x0 = t0;

        if (BlockSize == 16)
        {
            long t1 = loadBytes(buffer, bufOff + 8);
            setBytes(p.x1 ^ t1, output, outOff + 8);
            p.x1 = t1;
        }
        p.p(nr);
    }

    protected void processBufferEncrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
        p.x0 ^= loadBytes(buffer, bufOff);
        setBytes(p.x0, output, outOff);

        if (BlockSize == 16)
        {
            p.x1 ^= loadBytes(buffer, bufOff + 8);
            setBytes(p.x1, output, outOff + 8);
        }
        p.p(nr);
    }

    protected void reset(boolean clearMac)
    {
        super.reset(clearMac);
        ascon_aeadinit();
    }

    public abstract String getAlgorithmVersion();
}
