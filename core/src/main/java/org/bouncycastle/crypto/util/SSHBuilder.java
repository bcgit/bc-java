package org.bouncycastle.crypto.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Strings;

class SSHBuilder
{
    private final ByteArrayOutputStream bos = new ByteArrayOutputStream();

    public void u32(long value)
    {
        bos.write((int)((value >>> 24) & 0xFF));
        bos.write((int)((value >>> 16) & 0xFF));
        bos.write((int)((value >>> 8) & 0xFF));
        bos.write((int)(value & 0xFF));
    }

    public void rawArray(byte[] value)
    {
        u32(value.length);
        try
        {
            bos.write(value);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public void write(byte[] value)
    {
        try
        {
            bos.write(value);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public void writeString(String str)
    {
        rawArray(Strings.toByteArray(str));
    }

    public byte[] getBytes()
    {
        return bos.toByteArray();
    }

}
