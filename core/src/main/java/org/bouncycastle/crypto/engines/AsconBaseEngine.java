package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;

abstract class AsconBaseEngine
    extends AEADBaseEngine
{
    protected enum State
    {
        Uninitialized,
        EncInit,
        EncAad,
        EncData,
        EncFinal,
        DecInit,
        DecAad,
        DecData,
        DecFinal,
    }


    protected State m_state = State.Uninitialized;
    protected int nr;
    protected int ASCON_AEAD_RATE;
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
    protected int m_bufferSizeDecrypt;
    protected byte[] m_buf;
    protected int m_bufPos = 0;
    protected long dsep; //domain separation

    protected abstract long pad(int i);

    protected abstract long loadBytes(byte[] in, int inOff);

    protected abstract void setBytes(long n, byte[] bs, int off);

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

    protected void checkAAD()
    {
        switch (m_state)
        {
        case DecInit:
            m_state = State.DecAad;
            break;
        case EncInit:
            m_state = State.EncAad;
            break;
        case DecAad:
        case EncAad:
            break;
        case EncFinal:
            throw new IllegalStateException(getAlgorithmName() + " cannot be reused for encryption");
        default:
            throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
    }

    protected boolean checkData()
    {
        switch (m_state)
        {
        case DecInit:
        case DecAad:
            finishAAD(State.DecData);
            return false;
        case EncInit:
        case EncAad:
            finishAAD(State.EncData);
            return true;
        case DecData:
            return false;
        case EncData:
            return true;
        case EncFinal:
            throw new IllegalStateException(getAlgorithmName() + " cannot be reused for encryption");
        default:
            throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
    }

    private void finishAAD(State nextState)
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
        m_bufPos = 0;
        m_state = nextState;
    }

    protected abstract void processFinalAadBlock();

    protected abstract void processFinalDecrypt(byte[] input, int inLen, byte[] output, int outOff);

    protected abstract void processFinalEncrypt(byte[] input, int inLen, byte[] output, int outOff);

    protected void processBufferAAD(byte[] buffer, int inOff)
    {
        x0 ^= loadBytes(buffer, inOff);
        if (ASCON_AEAD_RATE == 16)
        {
            x1 ^= loadBytes(buffer, 8 + inOff);
        }
        p(nr);
    }


    protected void processBufferDecrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
        if (outOff + ASCON_AEAD_RATE > output.length)
        {
            throw new OutputLengthException("output buffer too short");
        }
        long t0 = loadBytes(buffer, bufOff);
        setBytes(x0 ^ t0, output, outOff);
        x0 = t0;

        if (ASCON_AEAD_RATE == 16)
        {
            long t1 = loadBytes(buffer, bufOff + 8);
            setBytes(x1 ^ t1, output, outOff + 8);
            x1 = t1;
        }
        p(nr);
    }

    protected void processBufferEncrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
        if (outOff + ASCON_AEAD_RATE > output.length)
        {
            throw new OutputLengthException("output buffer too short");
        }
        x0 ^= loadBytes(buffer, bufOff);
        setBytes(x0, output, outOff);

        if (ASCON_AEAD_RATE == 16)
        {
            x1 ^= loadBytes(buffer, bufOff + 8);
            setBytes(x1, output, outOff + 8);
        }
        p(nr);
    }

    public void processAADByte(byte in)
    {
        checkAAD();
        m_buf[m_bufPos] = in;
        if (++m_bufPos == ASCON_AEAD_RATE)
        {
            processBufferAAD(m_buf, 0);
            m_bufPos = 0;
        }
    }

    public void processAADBytes(byte[] inBytes, int inOff, int len)
    {
        if ((inOff + len) > inBytes.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        // Don't enter AAD state until we actually get input
        if (len <= 0)
        {
            return;
        }
        checkAAD();
        if (m_bufPos > 0)
        {
            int available = ASCON_AEAD_RATE - m_bufPos;
            if (len < available)
            {
                System.arraycopy(inBytes, inOff, m_buf, m_bufPos, len);
                m_bufPos += len;
                return;
            }
            System.arraycopy(inBytes, inOff, m_buf, m_bufPos, available);
            inOff += available;
            len -= available;
            processBufferAAD(m_buf, 0);
            //m_bufPos = 0;
        }
        while (len >= ASCON_AEAD_RATE)
        {
            processBufferAAD(inBytes, inOff);
            inOff += ASCON_AEAD_RATE;
            len -= ASCON_AEAD_RATE;
        }
        System.arraycopy(inBytes, inOff, m_buf, 0, len);
        m_bufPos = len;
    }

    public int processBytes(byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff)
        throws DataLengthException
    {
        if ((inOff + len) > inBytes.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        boolean forEncryption = checkData();
        int resultLength = 0;

        if (forEncryption)
        {
            if (m_bufPos > 0)
            {
                int available = ASCON_AEAD_RATE - m_bufPos;
                if (len < available)
                {
                    System.arraycopy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return 0;
                }

                System.arraycopy(inBytes, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;

                processBufferEncrypt(m_buf, 0, outBytes, outOff);
                resultLength = ASCON_AEAD_RATE;
                //m_bufPos = 0;
            }

            while (len >= ASCON_AEAD_RATE)
            {
                processBufferEncrypt(inBytes, inOff, outBytes, outOff + resultLength);
                inOff += ASCON_AEAD_RATE;
                len -= ASCON_AEAD_RATE;
                resultLength += ASCON_AEAD_RATE;
            }
        }
        else
        {
            int available = m_bufferSizeDecrypt - m_bufPos;
            if (len < available)
            {
                System.arraycopy(inBytes, inOff, m_buf, m_bufPos, len);
                m_bufPos += len;
                return 0;
            }

            // NOTE: Need 'while' here because ASCON_AEAD_RATE < CRYPTO_ABYTES in some parameter sets
            while (m_bufPos >= ASCON_AEAD_RATE)
            {
                processBufferDecrypt(m_buf, 0, outBytes, outOff + resultLength);
                m_bufPos -= ASCON_AEAD_RATE;
                System.arraycopy(m_buf, ASCON_AEAD_RATE, m_buf, 0, m_bufPos);
                resultLength += ASCON_AEAD_RATE;

                available += ASCON_AEAD_RATE;
                if (len < available)
                {
                    System.arraycopy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return resultLength;
                }
            }

            available = ASCON_AEAD_RATE - m_bufPos;
            System.arraycopy(inBytes, inOff, m_buf, m_bufPos, available);
            inOff += available;
            len -= available;
            processBufferDecrypt(m_buf, 0, outBytes, outOff + resultLength);
            resultLength += ASCON_AEAD_RATE;
            //m_bufPos = 0;

            while (len >= m_bufferSizeDecrypt)
            {
                processBufferDecrypt(inBytes, inOff, outBytes, outOff + resultLength);
                inOff += ASCON_AEAD_RATE;
                len -= ASCON_AEAD_RATE;
                resultLength += ASCON_AEAD_RATE;
            }
        }

        System.arraycopy(inBytes, inOff, m_buf, 0, len);
        m_bufPos = len;

        return resultLength;
    }

    public int doFinal(byte[] outBytes, int outOff)
        throws IllegalStateException, InvalidCipherTextException, DataLengthException
    {
        boolean forEncryption = checkData();
        int resultLength;
        if (forEncryption)
        {
            resultLength = m_bufPos + MAC_SIZE;
            if (outOff + resultLength > outBytes.length)
            {
                throw new OutputLengthException("output buffer too short");
            }
            processFinalEncrypt(m_buf, m_bufPos, outBytes, outOff);
            mac = new byte[MAC_SIZE];
            setBytes(x3, mac, 0);
            setBytes(x4, mac, 8);
            System.arraycopy(mac, 0, outBytes, outOff + m_bufPos, MAC_SIZE);
            reset(false);
        }
        else
        {
            if (m_bufPos < MAC_SIZE)
            {
                throw new InvalidCipherTextException("data too short");
            }
            m_bufPos -= MAC_SIZE;
            resultLength = m_bufPos;
            if (outOff + resultLength > outBytes.length)
            {
                throw new OutputLengthException("output buffer too short");
            }
            processFinalDecrypt(m_buf, m_bufPos, outBytes, outOff);
            x3 ^= loadBytes(m_buf, m_bufPos);
            x4 ^= loadBytes(m_buf, m_bufPos + 8);
            if ((x3 | x4) != 0L)
            {
                throw new InvalidCipherTextException("mac check in " + getAlgorithmName() + " failed");
            }
            reset(true);
        }
        return resultLength;
    }

    public int getUpdateOutputSize(int len)
    {
        int total = Math.max(0, len);
        switch (m_state)
        {
        case DecInit:
        case DecAad:
            total = Math.max(0, total - MAC_SIZE);
            break;
        case DecData:
        case DecFinal:
            total = Math.max(0, total + m_bufPos - MAC_SIZE);
            break;
        case EncData:
        case EncFinal:
            total += m_bufPos;
            break;
        default:
            break;
        }
        return total - total % ASCON_AEAD_RATE;
    }

    public int getOutputSize(int len)
    {
        int total = Math.max(0, len);

        switch (m_state)
        {
        case DecInit:
        case DecAad:
            return Math.max(0, total - MAC_SIZE);
        case DecData:
        case DecFinal:
            return Math.max(0, total + m_bufPos - MAC_SIZE);
        case EncData:
        case EncFinal:
            return total + m_bufPos + MAC_SIZE;
        default:
            return total + MAC_SIZE;
        }
    }


    protected void reset(boolean clearMac)
    {
        Arrays.clear(m_buf);
        m_bufPos = 0;

        switch (m_state)
        {
        case DecInit:
        case EncInit:
            break;
        case DecAad:
        case DecData:
        case DecFinal:
            m_state = State.DecInit;
            break;
        case EncAad:
        case EncData:
        case EncFinal:
            m_state = State.EncFinal;
            return;
        default:
            throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
        ascon_aeadinit();
        super.reset(clearMac);
    }

    public abstract String getAlgorithmVersion();
}
