package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;

abstract class AEADBufferBaseEngine
    extends AEADBaseEngine
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

    protected byte[] m_buf;
    protected byte[] m_aad;
    protected int m_bufPos;
    protected int m_aadPos;
    protected boolean aadFinished;
    protected boolean initialised = false;
    protected int AADBufferSize;
    protected int BlockSize;
    protected State m_state = Uninitialized;

    @Override
    public void processAADByte(byte input)
    {
        checkAAD();
        if (m_aadPos == AADBufferSize)
        {
            processBufferAAD(m_aad, 0);
            m_aadPos = 0;
        }
        m_aad[m_aadPos++] = input;
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        // Don't enter AAD state until we actually get input
        if (len <= 0)
        {
            return;
        }

        checkAAD();
        if (m_aadPos > 0)
        {
            int available = AADBufferSize - m_aadPos;
            if (len <= available)
            {
                System.arraycopy(input, inOff, m_aad, m_aadPos, len);
                m_aadPos += len;
                return;
            }

            System.arraycopy(input, inOff, m_aad, m_aadPos, available);
            inOff += available;
            len -= available;

            processBufferAAD(m_aad, 0);
            m_aadPos = 0;
        }
        while (len > AADBufferSize)
        {
            processBufferAAD(input, inOff);
            inOff += AADBufferSize;
            len -= AADBufferSize;
        }
        System.arraycopy(input, inOff, m_aad, m_aadPos, len);
        m_aadPos += len;
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        boolean forEncryption = checkData();

        int resultLength = 0;

        if (forEncryption)
        {
            if (m_bufPos > 0)
            {
                int available = BlockSize - m_bufPos;
                if (len <= available)
                {
                    System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return 0;
                }

                System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;

                validateAndProcessBuffer(m_buf, 0, output, outOff);
                resultLength = BlockSize;
                //m_bufPos = 0;
            }

            while (len > BlockSize)
            {
                validateAndProcessBuffer(input, inOff, output, outOff + resultLength);
                inOff += BlockSize;
                len -= BlockSize;
                resultLength += BlockSize;
            }
        }
        else
        {
            int available = BlockSize + MAC_SIZE - m_bufPos;
            if (len <= available)
            {
                System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                m_bufPos += len;
                return 0;
            }
            if (BlockSize >= MAC_SIZE)
            {
                if (m_bufPos > BlockSize)
                {
                    validateAndProcessBuffer(m_buf, 0, output, outOff);
                    m_bufPos -= BlockSize;
                    System.arraycopy(m_buf, BlockSize, m_buf, 0, m_bufPos);
                    resultLength = BlockSize;

                    available += BlockSize;
                    if (len <= available)
                    {
                        System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return resultLength;
                    }
                }

                available = BlockSize - m_bufPos;
                System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;
                validateAndProcessBuffer(m_buf, 0, output, outOff + resultLength);
                resultLength += BlockSize;
                //m_bufPos = 0;
            }
            else
            {
                while (m_bufPos > BlockSize && len + m_bufPos > BlockSize + MAC_SIZE)
                {
                    validateAndProcessBuffer(m_buf, resultLength, output, outOff + resultLength);
                    m_bufPos -= BlockSize;
                    resultLength += BlockSize;
                }
                if (m_bufPos != 0)
                {
                    System.arraycopy(m_buf, resultLength, m_buf, 0, m_bufPos);
                    if (m_bufPos + len > BlockSize + MAC_SIZE)
                    {
                        available = Math.max(BlockSize - m_bufPos, 0);
                        System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                        inOff += available;
                        validateAndProcessBuffer(m_buf, 0, output, outOff + resultLength);
                        resultLength += BlockSize;
                        len -= available;
                    }
                    else
                    {
                        System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return resultLength;
                    }
                }
            }
            while (len > BlockSize + MAC_SIZE)
            {
                validateAndProcessBuffer(input, inOff, output, outOff + resultLength);
                inOff += BlockSize;
                len -= BlockSize;
                resultLength += BlockSize;
            }
        }

        System.arraycopy(input, inOff, m_buf, 0, len);
        m_bufPos = len;

        return resultLength;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        boolean forEncryption = checkData();
        int resultLength;
        if (forEncryption)
        {
            resultLength = m_bufPos + MAC_SIZE;
        }
        else
        {
            if (m_bufPos < MAC_SIZE)
            {
                throw new InvalidCipherTextException("data too short");
            }

            m_bufPos -= MAC_SIZE;

            resultLength = m_bufPos;
        }

        if (outOff > output.length - resultLength)
        {
            throw new OutputLengthException("output buffer too short");
        }
        processFinalBlock(output, outOff);
        if (forEncryption)
        {
            System.arraycopy(mac, 0, output, outOff + resultLength - MAC_SIZE, MAC_SIZE);
        }
        else
        {
            if (!Arrays.constantTimeAreEqual(MAC_SIZE, mac, 0, m_buf, m_bufPos))
            {
                throw new InvalidCipherTextException(algorithmName + " mac does not match");
            }
        }
        reset(!forEncryption);
        return resultLength;
    }

    public int getBlockSize()
    {
        return BlockSize;
    }

    public int getUpdateOutputSize(int len)
    {
        // The -1 is to account for the lazy processing of a full buffer
        int total = Math.max(0, len) - 1;

        switch (m_state.ord)
        {
        case DECINIT:
        case DECAAD:
            total = Math.max(0, total - MAC_SIZE);
            break;
        case DECDATA:
        case DECFINAL:
            total = Math.max(0, total + m_bufPos - MAC_SIZE);
            break;
        case ENCDATA:
        case ENCFINAL:
            total = Math.max(0, total + m_bufPos);
            break;
        default:
            break;
        }
        return total - total % BlockSize;
    }

    public int getOutputSize(int len)
    {
        int total = Math.max(0, len);

        switch (m_state.ord)
        {
        case DECINIT:
        case DECAAD:
            return Math.max(0, total - MAC_SIZE);
        case DECDATA:
        case DECFINAL:
            return Math.max(0, total + m_bufPos - MAC_SIZE);
        case ENCDATA:
        case ENCFINAL:
            return total + m_bufPos + MAC_SIZE;
        default:
            return total + MAC_SIZE;
        }
    }

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
        {
            processFinalAAD();
            break;
        }
        default:
            break;
        }

        m_aadPos = 0;
        m_state = nextState;
    }

    protected void bufferReset()
    {
        Arrays.fill(m_buf, (byte)0);
        Arrays.fill(m_aad, (byte)0);
        m_bufPos = 0;
        m_aadPos = 0;
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
    }

    protected void validateAndProcessBuffer(byte[] input, int inOff, byte[] output, int outOff)
    {
        if (outOff > output.length - BlockSize)
        {
            throw new OutputLengthException("output buffer too short");
        }
        processBuffer(input, inOff, output, outOff);
    }

    protected abstract void processFinalBlock(byte[] output, int outOff);

    protected abstract void processBufferAAD(byte[] input, int inOff);

    protected abstract void processFinalAAD();

    protected abstract void processBuffer(byte[] input, int inOff, byte[] output, int outOff);
}
