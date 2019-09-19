package org.bouncycastle.crypto.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.Strings;

class SSHBuilder
{
    private final ByteArrayOutputStream bos = new ByteArrayOutputStream();

    public void u32(int value)
    {
        bos.write((value >>> 24) & 0xFF);
        bos.write((value >>> 16) & 0xFF);
        bos.write((value >>> 8) & 0xFF);
        bos.write(value & 0xFF);
    }

    public void writeBigNum(BigInteger n)
    {
        writeBlock(n.toByteArray());
    }

    public void writeBlock(byte[] value)
    {
        u32(value.length);
        try
        {
            bos.write(value);
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    public void writeBytes(byte[] value)
    {
        try
        {
            bos.write(value);
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    public void writeString(String str)
    {
        writeBlock(Strings.toByteArray(str));
    }

    public byte[] getBytes()
    {
        return bos.toByteArray();
    }

    public byte[] getPaddedBytes()
    {
        return getPaddedBytes(8);
    }

    public byte[] getPaddedBytes(int blockSize)
    {
        int align = bos.size() % blockSize;
        if (0 != align)
        {
            int padCount = blockSize - align;
            for (int i = 1; i <= padCount; ++i)
            {
                bos.write(i);
            }
        }
        return bos.toByteArray();
    }
}
