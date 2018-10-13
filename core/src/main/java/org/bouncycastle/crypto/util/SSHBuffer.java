package org.bouncycastle.crypto.util;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

/**
 * A Buffer for dealing with SSH key products.
 */
public class SSHBuffer
{
    private final byte[] buffer;
    private int pos = 0;

    public SSHBuffer(byte[] magic, byte[] buffer)
    {
        this.buffer = buffer;
        for (int i = 0; i != magic.length; i++)
        {
            if (magic[i] != buffer[i])
            {
                throw new IllegalArgumentException("magic-number incorrect");
            }
        }

        pos += magic.length;
    }

    public SSHBuffer(byte[] buffer)
    {
        this.buffer = buffer;
    }

    public long readCount()
    {
        if (pos + 8 > buffer.length)
        {
            throw new IllegalArgumentException("not enough data for long");
        }

        long rv = org.bouncycastle.util.Pack.bigEndianToLong(buffer, pos);

        pos += 8;

        return rv;
    }


    public boolean nextEquals(byte[] value)
    {
        if (pos + value.length > buffer.length)
        {
            return false;
        }

        for (int t = 0; t < value.length; t++)
        {
            if (buffer[pos + t] != value[t])
            {
                return false;
            }
        }
        return true;
    }

    public long u32l()
    {
        if (pos + 4 > buffer.length)
        {
            throw new IllegalArgumentException("4 bytes for U32 exceeds buffer.");
        }

        long i = (buffer[pos++] & 0xFF) << 24;
        i |= (buffer[pos++] & 0xFF) << 16;
        i |= (buffer[pos++] & 0xFF) << 8;
        i |= (buffer[pos++] & 0xFF);
        return i;


    }


    public int readU32()
    {
        if (pos + 4 > buffer.length)
        {
            throw new IllegalArgumentException("4 bytes for U32 exceeds buffer.");
        }

        int i = (buffer[pos++] & 0xFF) << 24;
        i |= (buffer[pos++] & 0xFF) << 16;
        i |= (buffer[pos++] & 0xFF) << 8;
        i |= (buffer[pos++] & 0xFF);
        return i;

    }

    public String cString()
    {
        int len = readU32();
        if (pos + len > buffer.length)
        {
            throw new IllegalArgumentException("C string length exceeds buffer length");
        }

        String rsp = new String(buffer, pos, len);
        pos += len;
        return rsp;
    }

    public byte[] readString()
    {
        int len = readU32();
        if (len == 0)
        {
            return new byte[0];
        }

        if (pos + len > buffer.length)
        {
            throw new IllegalArgumentException("C string length exceeds buffer length");
        }

        return Arrays.copyOfRange(buffer, pos, pos += len);
    }

    public byte[] readPaddedString()
    {
        int len = readU32();
        if (len == 0)
        {
            return new byte[0];
        }

        if (pos + len > buffer.length)
        {
            throw new IllegalArgumentException("not enough data for string");
        }

        return Arrays.copyOfRange(buffer, pos, pos += (len - (buffer[pos + len - 1] & 0xff)));
    }


    public BigInteger positiveBigNum()
    {
        int len = readU32();
        if (pos + len > buffer.length)
        {
            throw new IllegalArgumentException("C string length exceeds buffer length");
        }

        byte[] d = new byte[len];
        System.arraycopy(buffer, pos, d, 0, d.length);
        pos += len;
        return new BigInteger(1, d);
    }

    public byte[] getBuffer()
    {
        return Arrays.clone(buffer);
    }

    public boolean hasRemaining()
    {
        return pos < buffer.length;
    }

    public void rewind(int i)
    {
        pos -= i;
        if (pos < 0)
        {
            throw new IllegalArgumentException("Rewind places read position before start of buffer. " + pos);
        }
    }
}
