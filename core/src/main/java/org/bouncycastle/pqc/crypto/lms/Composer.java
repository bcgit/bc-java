package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.util.Encodable;

/**
 * Type to assist in build LMS messages.
 */
public class Composer
{
    private final ByteArrayOutputStream bos = new ByteArrayOutputStream();

    private Composer()
    {

    }

    public static Composer compose()
    {
        return new Composer();
    }

    public Composer u64str(long n)
    {
        u32str((int)(n >>> 32));
        u32str((int)n);

        return this;
    }

    public Composer u32str(int n)
    {
        bos.write((byte)(n >>> 24));
        bos.write((byte)(n >>> 16));
        bos.write((byte)(n >>> 8));
        bos.write((byte)(n));
        return this;
    }

    public Composer u16str(int n)
    {
        n &= 0xFFFF;
        bos.write((byte)(n >>> 8));
        bos.write((byte)(n));
        return this;
    }

    public Composer bytes(Encodable[] encodable)
    {
        try
        {
            for (Encodable e : encodable)
            {
                bos.write(e.getEncoded());
            }
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        return this;
    }


    public Composer bytes(Encodable encodable)
    {
        try
        {
            bos.write(encodable.getEncoded());
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        return this;
    }

    public Composer pad(int v, int len)
    {
        for (; len >= 0; len--)
        {
            try
            {

                bos.write(v);

            }
            catch (Exception ex)
            {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }

        return this;
    }

    public Composer bytes(byte[][] arrays)
    {
        try
        {
            for (byte[] array : arrays)
            {
                bos.write(array);
            }
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        return this;
    }

    public Composer bytes(byte[][] arrays, int start, int end)
    {
        try
        {
            int j = start;
            while (j != end)
            {
                bos.write(arrays[j]);
                j++;
            }
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        return this;
    }


    public Composer bytes(byte[] array)
    {
        try
        {
            bos.write(array);
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        return this;
    }


    public Composer bytes(byte[] array, int start, int len)
    {
        try
        {
            bos.write(array, start, len);
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        return this;
    }

    public byte[] build()
    {
        return bos.toByteArray();
    }

    public Composer padUntil(int v, int requiredLen)
    {
        while (bos.size() < requiredLen)
        {
            bos.write(v);
        }

        return this;
    }

    public Composer bool(boolean v)
    {
        bos.write(v ? 1 : 0);
        return this;
    }
}
