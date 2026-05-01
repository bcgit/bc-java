package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;

abstract class AsconBaseEngine
    implements AEADCipher
{
    protected static final int UNINITIALIZED = 0;
    protected static final int ENCINIT = 1;
    protected static final int ENCAAD = 2;
    protected static final int ENCDATA = 3;
    protected static final int ENCFINAL = 4;
    protected static final int DECINIT = 5;
    protected static final int DECAAD = 6;
    protected static final int DECDATA = 7;
    protected static final int DECFINAL = 8;

    protected static final State Uninitialized = new State(UNINITIALIZED);
    protected static final State EncInit = new State(ENCINIT);
    protected static final State EncAad = new State(ENCAAD);
    protected static final State EncData = new State(ENCDATA);
    protected static final State EncFinal = new State(ENCFINAL);
    protected static final State DecInit = new State(DECINIT);
    protected static final State DecAad = new State(DECAAD);
    protected static final State DecData = new State(DECDATA);
    protected static final State DecFinal = new State(DECFINAL);

    protected static class State
    {
        int ord;

        private State(int ord)
        {
            this.ord = ord;
        }
    }

    protected State m_state = Uninitialized;
    protected String algorithmName;
    protected byte[] mac;
    protected byte[] initialAssociatedText;
    protected int CRYPTO_KEYBYTES;
    protected int CRYPTO_ABYTES;
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
        switch (m_state.ord)
        {
        case DECINIT:
            m_state = DecAad;
            break;
        case ENCINIT:
            m_state = EncAad;
            break;
        case DECAAD:
        case ENCAAD:
            break;
        case ENCFINAL:
            throw new IllegalStateException(getAlgorithmName() + " cannot be reused for encryption");
        default:
            throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
    }

    protected boolean checkData()
    {
        switch (m_state.ord)
        {
        case DECINIT:
        case DECAAD:
            finishAAD(DecData);
            return false;
        case ENCINIT:
        case ENCAAD:
            finishAAD(EncData);
            return true;
        case DECDATA:
            return false;
        case ENCDATA:
            return true;
        case ENCFINAL:
            throw new IllegalStateException(getAlgorithmName() + " cannot be reused for encryption");
        default:
            throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
    }

    private void finishAAD(State nextState)
    {
        // State indicates whether we ever received AAD
        switch (m_state.ord)
        {
        case DECAAD:
        case ENCAAD:
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

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{in}, 0, 1, out, outOff);
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
            resultLength = m_bufPos + CRYPTO_ABYTES;
            if (outOff + resultLength > outBytes.length)
            {
                throw new OutputLengthException("output buffer too short");
            }
            processFinalEncrypt(m_buf, m_bufPos, outBytes, outOff);
            mac = new byte[CRYPTO_ABYTES];
            setBytes(x3, mac, 0);
            setBytes(x4, mac, 8);
            System.arraycopy(mac, 0, outBytes, outOff + m_bufPos, CRYPTO_ABYTES);
            reset(false);
        }
        else
        {
            if (m_bufPos < CRYPTO_ABYTES)
            {
                throw new InvalidCipherTextException("data too short");
            }
            m_bufPos -= CRYPTO_ABYTES;
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

    public byte[] getMac()
    {
        return mac;
    }

    public int getUpdateOutputSize(int len)
    {
        int total = Math.max(0, len);
        switch (m_state.ord)
        {
        case DECINIT:
        case DECAAD:
            total = Math.max(0, total - CRYPTO_ABYTES);
            break;
        case DECDATA:
        case DECFINAL:
            total = Math.max(0, total + m_bufPos - CRYPTO_ABYTES);
            break;
        case ENCDATA:
        case ENCFINAL:
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

        switch (m_state.ord)
        {
        case DECINIT:
        case DECAAD:
            return Math.max(0, total - CRYPTO_ABYTES);
        case DECDATA:
        case DECFINAL:
            return Math.max(0, total + m_bufPos - CRYPTO_ABYTES);
        case ENCDATA:
        case ENCFINAL:
            return total + m_bufPos + CRYPTO_ABYTES;
        default:
            return total + CRYPTO_ABYTES;
        }
    }

    public void reset()
    {
        reset(true);
    }

    protected void reset(boolean clearMac)
    {
        if (clearMac)
        {
            mac = null;
        }
        Arrays.clear(m_buf);
        m_bufPos = 0;

        switch (m_state.ord)
        {
        case DECINIT:
        case ENCINIT:
            break;
        case DECAAD:
        case DECDATA:
        case DECFINAL:
            m_state = DecInit;
            break;
        case ENCAAD:
        case ENCDATA:
        case ENCFINAL:
            m_state = EncFinal;
            return;
        default:
            throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
        ascon_aeadinit();
        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    public int getKeyBytesSize()
    {
        return CRYPTO_KEYBYTES;
    }

    public int getIVBytesSize()
    {
        return CRYPTO_ABYTES;
    }


    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public abstract String getAlgorithmVersion();

}
