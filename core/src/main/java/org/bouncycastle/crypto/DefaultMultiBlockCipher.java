package org.bouncycastle.crypto;

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
        if (in == out && segmentsOverlap(inOff, len, outOff, len))
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

    protected boolean segmentsOverlap(int inOff, int inLen, int outOff, int outLen)
    {
        // please ensure a valid check for inLen > 0 and outLen > 0 outside this function
        return inOff <= outOff + outLen && outOff <= inOff + inLen;
    }
}
