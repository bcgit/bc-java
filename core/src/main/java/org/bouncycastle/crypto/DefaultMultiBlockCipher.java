package org.bouncycastle.crypto;

import org.bouncycastle.util.Arrays;

public abstract class DefaultMultiBlockCipher
    implements MultiBlockCipher
{
    protected DefaultMultiBlockCipher()
    {
    }

    public int getMultiBlockSize()
    {
        return this.getBlockSize();
    }

    public int processBlocks(byte[] in, int inOff, int blockCount, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {

        // TODO check if the underlying cipher supports the multiblock interface and call it directly?

        int resultLen = 0;
        int blockSize = this.getMultiBlockSize();
        int len = blockCount * blockSize;
        if (in == out && Arrays.segmentsOverlap(inOff, len, outOff, len))
        {
            in = new byte[len];
            System.arraycopy(out, inOff, in, 0, len);
            inOff = 0;
        }
        for (int i = 0; i != blockCount; i++)
        {
            resultLen += this.processBlock(in, inOff, out, outOff + resultLen);

            inOff += blockSize;
        }

        return resultLen;
    }
}
