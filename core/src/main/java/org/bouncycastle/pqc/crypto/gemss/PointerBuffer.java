package org.bouncycastle.pqc.crypto.gemss;

import org.bouncycastle.util.Pack;

class PointerBuffer
    extends Pointer
{
    private byte[] buffer;

    public PointerBuffer(int p, int length)
    {
        super(p);
        if (length % 8 != 0)
        {
            throw new IllegalArgumentException("length must be a multiple of 8");
        }
        this.buffer = new byte[length];
    }

    public PointerBuffer(Pointer p, int length)
    {
        super(p);
        if (length % 8 != 0)
        {
            throw new IllegalArgumentException("length must be a multiple of 8");
        }
        this.buffer = new byte[length];
    }

    public byte[] getBuffer()
    {
        return buffer;
    }

    public void bufferFill(int p)
    {
        if (buffer.length % 8 == 0)
        {
            for (int i = 0; i < buffer.length && p < array.length; ++p)
            {
                array[p] |= Pack.littleEndianToLong(buffer, i);
                i += 8;
            }
        }
    }
}
