package org.bouncycastle.crypto.util;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * A Buffer for dealing with SSH key products.
 */
class SSHBuffer
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

    public int readU32()
    {
        if (pos > (buffer.length - 4))
        {
            throw new IllegalArgumentException("4 bytes for U32 exceeds buffer.");
        }

        int i = (buffer[pos++] & 0xFF) << 24;
        i |= (buffer[pos++] & 0xFF) << 16;
        i |= (buffer[pos++] & 0xFF) << 8;
        i |= (buffer[pos++] & 0xFF);

        return i;
    }

    public String readString()
    {
        return Strings.fromByteArray(readBlock());
    }

    public byte[] readBlock()
    {
        int len = readU32();
        if (len == 0)
        {
            return new byte[0];
        }

        if (pos > (buffer.length - len))
        {
            throw new IllegalArgumentException("not enough data for block");
        }

        int start = pos; pos += len;
        return Arrays.copyOfRange(buffer, start, pos);
    }

    public void skipBlock()
    {
        int len = readU32();
        if (pos > (buffer.length - len))
        {
            throw new IllegalArgumentException("not enough data for block");
        }

        pos += len;
    }

    public byte[] readPaddedBlock()
    {
        return readPaddedBlock(8);
    }

    public byte[] readPaddedBlock(int blockSize)
    {
        int len = readU32();
        if (len == 0)
        {
            return new byte[0];
        }

        if (pos > (buffer.length - len))
        {
            throw new IllegalArgumentException("not enough data for block");
        }

        int align = len % blockSize;
        if (0 != align)
        {
            throw new IllegalArgumentException("missing padding");
        }

        int start = pos; pos += len;
        int end = pos;

        if (len > 0)
        {
            // TODO If encryption is supported, should be constant-time
            int lastByte = buffer[pos - 1] & 0xFF;
            if (0 < lastByte && lastByte < blockSize)
            {
                int padCount = lastByte;
                end -= padCount;

                for (int i = 1, padPos = end; i <= padCount; ++i, ++padPos)
                {
                    if (i != (buffer[padPos] & 0xFF))
                    {
                        throw new IllegalArgumentException("incorrect padding");
                    }
                }
            }
        }

        return Arrays.copyOfRange(buffer, start, end);
    }

    public BigInteger readBigNumPositive()
    {
        int len = readU32();
        if (pos + len > buffer.length)
        {
            throw new IllegalArgumentException("not enough data for big num");
        }

        int start = pos; pos += len;
        byte[] d = Arrays.copyOfRange(buffer, start, pos);
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
}
