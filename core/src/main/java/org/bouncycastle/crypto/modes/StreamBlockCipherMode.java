package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

public abstract class StreamBlockCipherMode
    implements BlockCipher, StreamCipher
{
    private final BlockCipher cipher;

    protected StreamBlockCipherMode(BlockCipher cipher)
    {
        this.cipher = cipher;
    }

    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    public final byte returnByte(byte in)
    {
        return processByte(in);
    }

    public void processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (outOff + len > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }

        if (inOff + len > in.length)
        {
            throw new DataLengthException("input buffer too small");
        }

        int inStart = inOff;
        int inEnd = inOff + len;
        int outStart = outOff;

        while (inStart < inEnd)
        {
             out[outStart++] = processByte(in[inStart++]);
        }
    }

    protected abstract byte processByte(byte b);
}
