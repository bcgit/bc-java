package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;

abstract class AEADBufferBaseEngine
    extends AEADBaseEngine
{
    protected enum ProcessingBufferType
    {
        Buffered,
        BufferedLargeMac,
        Immediate,
        ImmediateLargeMac,
    }

    protected enum State
    {
        Uninitialized,
        EncInit,
        EncAad, // can process AAD
        EncData, // cannot process AAD
        EncFinal,
        DecInit,
        DecAad, // can process AAD
        DecData, // cannot process AAD
        DecFinal,
    }

    protected byte[] m_buf;
    protected byte[] m_aad;
    protected int m_bufPos;
    protected int m_aadPos;
    protected int AADBufferSize;
    protected int BlockSize;
    protected State m_state = State.Uninitialized;
    protected int m_bufferSizeDecrypt;
    protected AADProcessingBuffer processor;

    protected AEADBufferBaseEngine(ProcessingBufferType type)
    {
        switch (type)
        {
        case Buffered:
            processor = new BufferedAADProcessor();
            break;
        case BufferedLargeMac:
            processor = new BufferedLargeMacAADProcessor();
            break;
        case Immediate:
            processor = new ImmediateAADProcessor();
            break;
        case ImmediateLargeMac:
            processor = new ImmediateLargeMacAADProcessor();
            break;
        }
    }

    private interface AADProcessingBuffer
    {
        void processAADByte(byte input);

        int processDecryptBytes(byte[] input, int inOff, int len, byte[] output, int outOff);

        int getUpdateOutputSize(int len);

        boolean isLengthWithinAvailableSpace(int len, int available);

        boolean isLengthExceedingBlockSize(int len, int size);
    }

    private abstract class BufferedBaseAADProcessor
        implements AADProcessingBuffer
    {
        public void processAADByte(byte input)
        {
            if (m_aadPos == AADBufferSize)
            {
                processBufferAAD(m_aad, 0);
                m_aadPos = 0;
            }
            m_aad[m_aadPos++] = input;
        }

        public boolean isLengthWithinAvailableSpace(int len, int available)
        {
            return len <= available;
        }

        public boolean isLengthExceedingBlockSize(int len, int size)
        {
            return len > size;
        }

        @Override
        public int getUpdateOutputSize(int len)
        {
            // The -1 is to account for the lazy processing of a full buffer
            return Math.max(0, len) - 1;
        }
    }

    private class BufferedAADProcessor
        extends BufferedBaseAADProcessor
    {
        @Override
        public int processDecryptBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            int resultLength = 0;
            int available = m_bufferSizeDecrypt - m_bufPos;
            if (m_bufPos > 0)
            {
                if (m_bufPos > BlockSize)
                {
                    processBufferDecrypt(m_buf, 0, output, outOff);
                    m_bufPos -= BlockSize;
                    System.arraycopy(m_buf, BlockSize, m_buf, 0, m_bufPos);
                    resultLength = BlockSize;

                    available += BlockSize;
                    if (len <= available)
                    {
                        System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return -1;
                    }
                }

                available = BlockSize - m_bufPos;
                System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                inOff += available;
                processBufferDecrypt(m_buf, 0, output, outOff + resultLength);
            }
            return inOff;
        }
    }

    private class BufferedLargeMacAADProcessor
        extends BufferedBaseAADProcessor
    {
        @Override
        public int processDecryptBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            int resultLength = 0;

            int available;
            while (m_bufPos > BlockSize && len + m_bufPos > m_bufferSizeDecrypt)
            {
                processBufferDecrypt(m_buf, resultLength, output, outOff + resultLength);
                m_bufPos -= BlockSize;
                resultLength += BlockSize;
            }
            if (m_bufPos > 0)
            {
                System.arraycopy(m_buf, resultLength, m_buf, 0, m_bufPos);
                if (m_bufPos + len > m_bufferSizeDecrypt)
                {
                    available = Math.max(BlockSize - m_bufPos, 0);
                    System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                    inOff += available;
                    processBufferDecrypt(m_buf, 0, output, outOff + resultLength);
                }
                else
                {
                    System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return -1;
                }
            }
            return inOff;
        }
    }

    private abstract class ImmediateBaseAADProcessor
        implements AADProcessingBuffer
    {
        public void processAADByte(byte input)
        {
            m_aad[m_aadPos++] = input;
            if (m_aadPos == AADBufferSize)
            {
                processBufferAAD(m_aad, 0);
                m_aadPos = 0;
            }
        }

        public int getUpdateOutputSize(int len)
        {
            return Math.max(0, len);
        }

        public boolean isLengthWithinAvailableSpace(int len, int available)
        {
            return len < available;
        }

        public boolean isLengthExceedingBlockSize(int len, int size)
        {
            return len >= size;
        }
    }

    private class ImmediateAADProcessor
        extends ImmediateBaseAADProcessor
    {
        @Override
        public int processDecryptBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            int resultLength = 0;
            int available = m_bufferSizeDecrypt - m_bufPos;
            if (m_bufPos > 0)
            {
                if (m_bufPos >= BlockSize)
                {
                    processBufferDecrypt(m_buf, 0, output, outOff);
                    m_bufPos -= BlockSize;
                    System.arraycopy(m_buf, BlockSize, m_buf, 0, m_bufPos);
                    resultLength = BlockSize;

                    available += BlockSize;
                    if (len < available)
                    {
                        System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return -1;
                    }
                }

                available = Math.max(BlockSize - m_bufPos, 0);
                System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                inOff += available;
                processBufferDecrypt(m_buf, 0, output, outOff + resultLength);
            }
            return inOff;
        }
    }

    private class ImmediateLargeMacAADProcessor
        extends ImmediateBaseAADProcessor
    {
        @Override
        public int processDecryptBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            int resultLength = 0;
            int available;

            while (m_bufPos >= BlockSize && len + m_bufPos >= m_bufferSizeDecrypt)
            {
                processBufferDecrypt(m_buf, resultLength, output, outOff + resultLength);
                m_bufPos -= BlockSize;
                resultLength += BlockSize;
            }
            if (m_bufPos > 0)
            {
                System.arraycopy(m_buf, resultLength, m_buf, 0, m_bufPos);
                if (m_bufPos + len >= m_bufferSizeDecrypt)
                {
                    available = Math.max(BlockSize - m_bufPos, 0);
                    System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                    inOff += available;
                    processBufferDecrypt(m_buf, 0, output, outOff + resultLength);
                }
                else
                {
                    System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return -1;
                }
            }
            return inOff;
        }
    }

    @Override
    public void processAADByte(byte input)
    {
        checkAAD();
        processor.processAADByte(input);
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        ensureSufficientInputBuffer(input, inOff, len);
        // Don't enter AAD state until we actually get input
        if (len <= 0)
        {
            return;
        }

        checkAAD();
        if (m_aadPos > 0)
        {
            int available = AADBufferSize - m_aadPos;
            if (processor.isLengthWithinAvailableSpace(len, available))
            {
                System.arraycopy(input, inOff, m_aad, m_aadPos, len);
                m_aadPos += len;
                return;
            }

            System.arraycopy(input, inOff, m_aad, m_aadPos, available);
            inOff += available;
            len -= available;

            processBufferAAD(m_aad, 0);

        }
        while (processor.isLengthExceedingBlockSize(len, AADBufferSize))
        {
            processBufferAAD(input, inOff);
            inOff += AADBufferSize;
            len -= AADBufferSize;
        }
        System.arraycopy(input, inOff, m_aad, 0, len);
        m_aadPos = len;
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        ensureSufficientInputBuffer(input, inOff, len);
        int available, resultLength;
        if (checkData())
        {
            resultLength = 0;
            available = processor.getUpdateOutputSize(len) + m_bufPos;
            ensureSufficientOutputBuffer(output, outOff, available - available % BlockSize);
            if (m_bufPos > 0)
            {
                available = BlockSize - m_bufPos;
                if (processor.isLengthWithinAvailableSpace(len, available))
                {
                    System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return 0;
                }
                System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;

                processBufferEncrypt(m_buf, 0, output, outOff);
                resultLength = BlockSize;
            }
            while (processor.isLengthExceedingBlockSize(len, BlockSize))
            {
                processBufferEncrypt(input, inOff, output, outOff + resultLength);
                inOff += BlockSize;
                len -= BlockSize;
                resultLength += BlockSize;
            }
        }
        else
        {
            available = m_bufferSizeDecrypt - m_bufPos;
            if (processor.isLengthWithinAvailableSpace(len, available))
            {
                System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                m_bufPos += len;
                return 0;
            }
            resultLength = (processor.getUpdateOutputSize(len) + m_bufPos - MAC_SIZE);
            resultLength -= resultLength % BlockSize;
            ensureSufficientOutputBuffer(output, outOff, resultLength);
            int originalInOff = inOff;
            int originalm_bufPos = m_bufPos;
            if ((inOff = processor.processDecryptBytes(input, inOff, len, output, outOff)) == -1)
            {
                return resultLength;
            }
            resultLength = inOff - originalInOff;
            len -= resultLength;
            resultLength += originalm_bufPos;
            while (processor.isLengthExceedingBlockSize(len, m_bufferSizeDecrypt))
            {
                processBufferDecrypt(input, inOff, output, outOff + resultLength);
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
        int total = processor.getUpdateOutputSize(len);
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

    protected void finishAAD(State nextState)
    {
        // State indicates whether we ever received AAD
        switch (m_state)
        {
        case DecAad:
        case EncAad:
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
        switch (m_state)
        {
        case DecInit:
        case EncInit:
            break;
        case DecAad:
        case DecData:
        case DecFinal:
            m_state = State.DecFinal;
            break;
        case EncAad:
        case EncData:
        case EncFinal:
            m_state = State.EncFinal;
            return;
        default:
            throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
    }

    protected void ensureSufficientOutputBuffer(byte[] output, int outOff, int len)
    {
        if (len >= BlockSize && outOff + len > output.length)
        {
            throw new OutputLengthException("output buffer too short");
        }
    }

    protected void ensureSufficientInputBuffer(byte[] input, int inOff, int len)
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
    }

    protected void ensureInitialized()
    {
        if (m_state == State.Uninitialized)
        {
            throw new IllegalStateException("Need to call init function before operation");
        }
    }

    protected abstract void processFinalBlock(byte[] output, int outOff);

    protected abstract void processBufferAAD(byte[] input, int inOff);

    protected abstract void processFinalAAD();

    protected abstract void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff);

    protected abstract void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff);
}
