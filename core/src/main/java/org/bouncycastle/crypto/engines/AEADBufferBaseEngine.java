package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;

abstract class AEADBufferBaseEngine
    extends AEADBaseEngine
{
    protected byte[] buffer;
    protected byte[] aadData;
    protected int bufferOff;
    protected int aadDataOff;
    protected boolean aadFinished;
    protected boolean initialised = false;
    protected int AADBufferSize;
    protected int BlockSize;

    @Override
    public void processAADByte(byte input)
    {
        if (aadFinished)
        {
            throw new IllegalArgumentException("AAD cannot be added after reading input for "
                + (forEncryption ? "encryption" : "decryption"));
        }
        aadData[aadDataOff++] = input;
        if (aadDataOff >= AADBufferSize)
        {
            processBufferAAD(aadData, 0);
            aadDataOff = 0;
        }

    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        if (aadFinished)
        {
            throw new IllegalArgumentException("AAD cannot be added after reading input for "
                + (forEncryption ? "encryption" : "decryption"));
        }
        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        int tmp;
        if (aadDataOff + len >= AADBufferSize)
        {
            tmp = AADBufferSize - aadDataOff;
            System.arraycopy(input, inOff, aadData, aadDataOff, tmp);
            processBufferAAD(aadData, 0);
            inOff += tmp;
            len -= tmp;
            aadDataOff = 0;
        }
        while (len >= AADBufferSize)
        {
            processBufferAAD(input, inOff);
            inOff += AADBufferSize;
            len -= AADBufferSize;
        }
        System.arraycopy(input, inOff, aadData, aadDataOff, len);
        aadDataOff += len;
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException(algorithmName + " needs to be initialized");
        }
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        int blockLen = len + bufferOff - (forEncryption ? 0 : MAC_SIZE);
        if (blockLen / BlockSize * BlockSize + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        int tmp;
        int rv = 0;

        int originalInOff = inOff;
        if (!forEncryption && bufferOff >= BlockSize)
        {
            processFinalAADBlock();
            processBuffer(buffer, 0, output, outOff);
            rv += BlockSize;
            System.arraycopy(buffer, BlockSize, buffer, 0, bufferOff - BlockSize);
            bufferOff -= BlockSize;
            blockLen -= BlockSize;
            outOff += BlockSize;
        }
        if (blockLen >= BlockSize)
        {
            processFinalAADBlock();
            tmp = Math.max(BlockSize - bufferOff, 0);
            System.arraycopy(input, inOff, buffer, bufferOff, tmp);
            processBuffer(buffer, 0, output, outOff);
            inOff += tmp;
            rv += BlockSize;
            blockLen -= BlockSize;
            outOff += BlockSize;
            bufferOff = 0;
        }
        while (blockLen >= BlockSize)
        {
            processBuffer(input, inOff, output, outOff);
            outOff += BlockSize;
            inOff += BlockSize;
            rv += BlockSize;
            blockLen -= BlockSize;
        }
        len -= inOff - originalInOff;
        System.arraycopy(input, inOff, buffer, bufferOff, len);
        bufferOff += len;
        return rv;
    }

    public int getBlockSize()
    {
        return BlockSize;
    }

    protected abstract void processBufferAAD(byte[] input, int inOff);

    protected abstract void processFinalAADBlock();

    protected abstract void processBuffer(byte[] input, int inOff, byte[] output, int outOff);
}
