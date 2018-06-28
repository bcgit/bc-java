package org.bouncycastle.gpg.keybox;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * Wraps an existing ByteArrayBuffer with support for unsigned int reads.
 * Method names in the nomenclature of the spec.
 */
class KeyBoxByteBuffer
{
    private final ByteBuffer buffer;

    public KeyBoxByteBuffer(ByteBuffer buffer)
    {
        this.buffer = buffer;
    }

    static KeyBoxByteBuffer wrap(Object src)
        throws IOException
    {

        if (src == null)
        {
            return null;
        }
        else if (src instanceof KeyBoxByteBuffer) // Same type.
        {
            return (KeyBoxByteBuffer)src;
        }
        else if (src instanceof ByteBuffer) // ByteBuffer
        {
            return new KeyBoxByteBuffer((ByteBuffer)src);
        }
        else if (src instanceof byte[]) // ByteArray
        {
            return wrap(ByteBuffer.wrap((byte[])src));
        }
        else if (src instanceof ByteArrayOutputStream) // ByteArrayInputStream specifically.
        {
            return wrap(((ByteArrayOutputStream)src).toByteArray());
        }
        else if (src instanceof InputStream) // InputStream
        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            byte[] buf = new byte[4096];
            int i;

            while ((i = ((InputStream)src).read(buf)) >= 0)
            {
                bos.write(buf, 0, i);
            }

            bos.flush();
            bos.close();

            return wrap(bos);
        }

        throw new IllegalStateException("Could not convert " + src.getClass().getCanonicalName() + " to KeyBoxByteBuffer");
    }

    public int size()
    {
        return this.buffer.limit() - 20;
    }

    public byte[] rangeOf(int start, int end)
    {
        int p = buffer.position();
        buffer.position(start);
        byte[] data = new byte[end - start];
        buffer.get(data);
        buffer.position(p);
        return data;
    }

    public boolean hasRemaining()
    {
        return buffer.hasRemaining();
    }

    public int position()
    {
        return buffer.position();
    }

    public void position(int p)
    {
        buffer.position(p);
    }

    public int u16()
    {
        return (u8() << 8) | u8();
    }

    public long u32()
    {
        return ((u8() << 24) | (u8() << 16) | (u8() << 8) | u8());
    }

    public int u8()
    {
        return ((int)buffer.get() & 0xFF);
    }

    public void bN(byte[] array)
    {
        buffer.get(array);
    }

    public ByteBuffer getBuffer()
    {
        return buffer;
    }
}
