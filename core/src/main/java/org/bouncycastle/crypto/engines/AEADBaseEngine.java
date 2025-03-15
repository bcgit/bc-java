package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

abstract class AEADBaseEngine
    implements AEADCipher
{
    protected enum ProcessingBufferType
    {
        Buffered, // Store a (aad) block size of input and process after the input size exceeds the buffer size
        Immediate, //process the input immediately when the input size is equal or greater than the block size
    }

    protected enum AADOperatorType
    {
        Default,
        Counter,//add a counter to count the size of AAD
        Stream //process AAD data during the process data, used for elephant
    }

    protected enum DataOperatorType
    {
        Default,
        Counter,
        Stream,
        StreamCipher
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

    protected boolean forEncryption;
    protected String algorithmName;
    protected int KEY_SIZE;
    protected int IV_SIZE;
    protected int MAC_SIZE;
    protected byte[] initialAssociatedText;
    protected byte[] mac;
    protected byte[] m_buf;
    protected byte[] m_aad;
    protected int m_bufPos;
    protected int m_aadPos;
    protected int AADBufferSize;
    protected int BlockSize;
    protected State m_state = State.Uninitialized;
    protected int m_bufferSizeDecrypt;
    protected AADProcessingBuffer processor;
    protected AADOperator aadOperator;
    protected DataOperator dataOperator;

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getKeyBytesSize()
    {
        return KEY_SIZE;
    }

    public int getIVBytesSize()
    {
        return IV_SIZE;
    }

    public byte[] getMac()
    {
        return mac;
    }

    public void reset()
    {
        reset(true);
    }

    public void init(boolean forEncryption, CipherParameters params)
    {
        this.forEncryption = forEncryption;
        KeyParameter key;
        byte[] npub;
        byte[] k;

        if (params instanceof AEADParameters)
        {
            AEADParameters aeadParameters = (AEADParameters)params;
            key = aeadParameters.getKey();
            npub = aeadParameters.getNonce();
            initialAssociatedText = aeadParameters.getAssociatedText();

            int macSizeBits = aeadParameters.getMacSize();
            if (macSizeBits != MAC_SIZE * 8)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV withIV = (ParametersWithIV)params;
            key = (KeyParameter)withIV.getParameters();
            npub = withIV.getIV();
            initialAssociatedText = null;
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to " + algorithmName);
        }

        if (key == null)
        {
            throw new IllegalArgumentException(algorithmName + " Init parameters must include a key");
        }
        if (npub == null || npub.length != IV_SIZE)
        {
            throw new IllegalArgumentException(algorithmName + " requires exactly " + IV_SIZE + " bytes of IV");
        }

        k = key.getKey();
        if (k.length != KEY_SIZE)
        {
            throw new IllegalArgumentException(algorithmName + " key must be " + KEY_SIZE + " bytes long");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));

        m_state = forEncryption ? State.EncInit : State.DecInit;
        init(k, npub);
        reset(true);
        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    protected void reset(boolean clearMac)
    {
        ensureInitialized();
        if (clearMac)
        {
            mac = null;
        }
        if (m_buf != null)
        {
            Arrays.fill(m_buf, (byte)0);
            m_bufPos = 0;
        }
        if (m_aad != null)
        {
            Arrays.fill(m_aad, (byte)0);
            m_aadPos = 0;
        }
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
        aadOperator.reset();
        dataOperator.reset();
    }

    protected void setInnerMembers(ProcessingBufferType type, AADOperatorType aadOperatorType, DataOperatorType dataOperatorType)
    {
        switch (type)
        {
        case Buffered:
            processor = new BufferedAADProcessor();
            break;
        case Immediate:
            processor = new ImmediateAADProcessor();
            break;
        }

        m_bufferSizeDecrypt = BlockSize + MAC_SIZE;

        switch (aadOperatorType)
        {
        case Default:
            m_aad = new byte[AADBufferSize];
            aadOperator = new DefaultAADOperator();
            break;
        case Counter:
            m_aad = new byte[AADBufferSize];
            aadOperator = new CounterAADOperator();
            break;
        case Stream:
            AADBufferSize = 0;
            aadOperator = new StreamAADOperator();
            break;
        }

        switch (dataOperatorType)
        {
        case Default:
            m_buf = new byte[m_bufferSizeDecrypt];
            dataOperator = new DefaultDataOperator();
            break;
        case Counter:
            m_buf = new byte[m_bufferSizeDecrypt];
            dataOperator = new CounterDataOperator();
            break;
        case Stream:
            m_buf = new byte[MAC_SIZE];
            dataOperator = new StreamDataOperator();
            break;
        case StreamCipher:
            BlockSize = 0;
            m_buf = new byte[m_bufferSizeDecrypt];
            dataOperator = new StreamCipherOperator();
            break;
        }
    }

    protected interface AADProcessingBuffer
    {
        void processAADByte(byte input);

        int getUpdateOutputSize(int len);

        boolean isLengthWithinAvailableSpace(int len, int available);

        boolean isLengthExceedingBlockSize(int len, int size);
    }

    private class BufferedAADProcessor
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

        @Override
        public boolean isLengthWithinAvailableSpace(int len, int available)
        {
            return len <= available;
        }

        @Override
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

    private class ImmediateAADProcessor
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

        @Override
        public int getUpdateOutputSize(int len)
        {
            return Math.max(0, len);
        }

        @Override
        public boolean isLengthWithinAvailableSpace(int len, int available)
        {
            return len < available;
        }

        @Override
        public boolean isLengthExceedingBlockSize(int len, int size)
        {
            return len >= size;
        }
    }

    protected interface AADOperator
    {
        void processAADByte(byte input);

        void processAADBytes(byte[] input, int inOff, int len);

        void reset();

        int getLen();
    }

    protected class DefaultAADOperator
        implements AADOperator
    {
        @Override
        public void processAADByte(byte input)
        {
            processor.processAADByte(input);
        }

        @Override
        public void processAADBytes(byte[] input, int inOff, int len)
        {
            processAadBytes(input, inOff, len);
        }

        public void reset()
        {
        }

        @Override
        public int getLen()
        {
            return m_aadPos;
        }
    }

    protected class CounterAADOperator
        implements AADOperator
    {
        private int aadLen;

        @Override
        public void processAADByte(byte input)
        {
            aadLen++;
            processor.processAADByte(input);
        }

        @Override
        public void processAADBytes(byte[] input, int inOff, int len)
        {
            aadLen += len;
            processAadBytes(input, inOff, len);
        }

        public int getLen()
        {
            return aadLen;
        }

        public void reset()
        {
            aadLen = 0;
        }
    }

    protected static class StreamAADOperator
        implements AADOperator
    {
        private final ErasableOutputStream stream = new ErasableOutputStream();

        @Override
        public void processAADByte(byte input)
        {
            stream.write(input);
        }

        @Override
        public void processAADBytes(byte[] input, int inOff, int len)
        {
            stream.write(input, inOff, len);
        }

        public byte[] getBytes()
        {
            return stream.getBuf();
        }

        @Override
        public void reset()
        {
            stream.reset();
        }

        @Override
        public int getLen()
        {
            return stream.size();
        }
    }

    protected interface DataOperator
    {
        int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff);

        int getLen();

        void reset();
    }

    protected class DefaultDataOperator
        implements DataOperator
    {
        public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            return processEncDecBytes(input, inOff, len, output, outOff);
        }

        @Override
        public int getLen()
        {
            return m_bufPos;
        }

        @Override
        public void reset()
        {
        }
    }

    protected class CounterDataOperator
        implements DataOperator
    {
        private int messegeLen;

        public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            messegeLen += len;
            return processEncDecBytes(input, inOff, len, output, outOff);
        }

        @Override
        public int getLen()
        {
            return messegeLen;
        }

        @Override
        public void reset()
        {
            messegeLen = 0;
        }
    }

    protected class StreamDataOperator
        implements DataOperator
    {
        private final ErasableOutputStream stream = new ErasableOutputStream();

        @Override
        public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            ensureInitialized();
            stream.write(input, inOff, len);
            m_bufPos = stream.size();
            return 0;
        }

        public byte[] getBytes()
        {
            return stream.getBuf();
        }

        @Override
        public int getLen()
        {
            return stream.size();
        }

        @Override
        public void reset()
        {
            stream.reset();
        }
    }

    protected class StreamCipherOperator
        implements DataOperator
    {
        private int len;

        @Override
        public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            boolean forEncryption = checkData(false);
            if (forEncryption)
            {
                this.len = len;
                processBufferEncrypt(input, inOff, output, outOff);
                return len;
            }
            else
            {
                // keep last mac size bytes
                int available = Math.max(m_bufPos + len - MAC_SIZE, 0);
                int rlt = 0;
                if (m_bufPos > 0)
                {
                    this.len = Math.min(available, m_bufPos);
                    rlt = this.len;
                    processBufferDecrypt(m_buf, 0, output, outOff);
                    available -= rlt;
                    m_bufPos -= rlt;
                    System.arraycopy(m_buf, rlt, m_buf, 0, m_bufPos);
                }
                if (available > 0)
                {
                    this.len = available;
                    processBufferDecrypt(input, inOff, output, outOff);
                    rlt += available;
                    len -= available;
                    inOff += available;
                }

                System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                m_bufPos += len;
                return rlt;
            }
        }

        @Override
        public int getLen()
        {
            return len;
        }

        @Override
        public void reset()
        {
        }
    }

    @Override
    public void processAADByte(byte input)
    {
        checkAAD();
        aadOperator.processAADByte(input);
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
        aadOperator.processAADBytes(input, inOff, len);
    }

    private void processAadBytes(byte[] input, int inOff, int len)
    {
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

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{in}, 0, 1, out, outOff);
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        ensureSufficientInputBuffer(input, inOff, len);
        return dataOperator.processBytes(input, inOff, len, output, outOff);
    }

    protected int processEncDecBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
    {
        boolean forEncryption = checkData(false);
        int available, resultLength;
        available = (forEncryption ? BlockSize : m_bufferSizeDecrypt) - m_bufPos;
        // The function is just an operator < or <=
        if (processor.isLengthWithinAvailableSpace(len, available))
        {
            System.arraycopy(input, inOff, m_buf, m_bufPos, len);
            m_bufPos += len;
            return 0;
        }
        resultLength = processor.getUpdateOutputSize(len) + m_bufPos - (forEncryption ? 0 : MAC_SIZE);
        ensureSufficientOutputBuffer(output, outOff, resultLength - resultLength % BlockSize);
        resultLength = 0;
        if (forEncryption)
        {
            if (m_bufPos > 0)
            {
                System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;
                processBufferEncrypt(m_buf, 0, output, outOff);
                resultLength = BlockSize;
            }
            // The function is just an operator >= or >
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
            // loop will run more than once for the following situation: pb128, ascon80pq, ascon128, ISAP_A_128(A)
            while (processor.isLengthExceedingBlockSize(m_bufPos, BlockSize)
                && processor.isLengthExceedingBlockSize(len + m_bufPos, m_bufferSizeDecrypt))
            {
                processBufferDecrypt(m_buf, resultLength, output, outOff + resultLength);
                m_bufPos -= BlockSize;
                resultLength += BlockSize;
            }
            if (m_bufPos > 0)
            {
                System.arraycopy(m_buf, resultLength, m_buf, 0, m_bufPos);
                if (processor.isLengthWithinAvailableSpace(m_bufPos + len, m_bufferSizeDecrypt))
                {
                    System.arraycopy(input, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return resultLength;
                }
                available = Math.max(BlockSize - m_bufPos, 0);
                System.arraycopy(input, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;
                processBufferDecrypt(m_buf, 0, output, outOff + resultLength);
                resultLength += BlockSize;
            }
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
        boolean forEncryption = checkData(true);
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

        ensureSufficientOutputBuffer(output, outOff, resultLength);
        mac = new byte[MAC_SIZE];
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

    public final int getBlockSize()
    {
        return BlockSize;
    }

    public int getUpdateOutputSize(int len)
    {
        int total = getTotalBytesForUpdate(len);
        return total - total % BlockSize;
    }

    protected int getTotalBytesForUpdate(int len)
    {
        int total = processor.getUpdateOutputSize(len);
        switch (m_state)
        {
        case DecInit:
        case DecAad:
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
        return total;
    }

    public int getOutputSize(int len)
    {
        int total = Math.max(0, len);

        switch (m_state)
        {
        case DecInit:
        case DecAad:
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

    protected boolean checkData(boolean isDoFinal)
    {
        switch (m_state)
        {
        case DecInit:
        case DecAad:
            finishAAD(State.DecData, isDoFinal);
            return false;
        case EncInit:
        case EncAad:
            finishAAD(State.EncData, isDoFinal);
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

    protected final void ensureSufficientOutputBuffer(byte[] output, int outOff, int len)
    {
        if (outOff + len > output.length)
        {
            throw new OutputLengthException("output buffer too short");
        }
    }

    protected final void ensureSufficientInputBuffer(byte[] input, int inOff, int len)
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
    }

    protected final void ensureInitialized()
    {
        if (m_state == State.Uninitialized)
        {
            throw new IllegalStateException("Need to call init function before operation");
        }
    }

    // Used for Grain128 AEAD and Romulus Engine
    protected void finishAAD1(State nextState)
    {
        switch (m_state)
        {
        case DecInit:
        case DecAad:
        case EncInit:
        case EncAad:
        {
            processFinalAAD();
            break;
        }
        default:
            break;
        }
        m_state = nextState;
    }

    // Use for Elephant and Sparkle
    protected void finishAAD2(State nextState)
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

    // Used for Gift-Cofb, ISAP, PhotonBeetle and Xoodyak
    protected void finishAAD3(State nextState, boolean isDoFinal)
    {
        // State indicates whether we ever received AAD
        switch (m_state)
        {
        case DecInit:
        case DecAad:
            if (!isDoFinal && dataOperator.getLen() <= MAC_SIZE)
            {
                return;
            }
        case EncInit:
        case EncAad:
            processFinalAAD();
            break;
        }

        m_aadPos = 0;
        m_state = nextState;
    }

    protected abstract void finishAAD(State nextState, boolean isDoFinal);

    protected abstract void init(byte[] key, byte[] iv);

    protected abstract void processFinalBlock(byte[] output, int outOff);

    protected abstract void processBufferAAD(byte[] input, int inOff);

    protected abstract void processFinalAAD();

    protected abstract void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff);

    protected abstract void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff);

    protected static final class ErasableOutputStream
        extends ByteArrayOutputStream
    {
        public ErasableOutputStream()
        {
        }

        public byte[] getBuf()
        {
            return buf;
        }
    }
}
