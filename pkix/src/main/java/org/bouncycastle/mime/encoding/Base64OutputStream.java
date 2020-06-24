package org.bouncycastle.mime.encoding;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.encoders.Base64;

public class Base64OutputStream
    extends FilterOutputStream
{
    private static final byte[] nl = new byte[2];
    private final byte[] buffer = new byte[54];

    private int    bufOff;

    static
    {
        nl[0] = '\r';
        nl[1] = '\n';
    }

    public Base64OutputStream(OutputStream stream)
    {
        super(stream);
    }

    public void write(int b)
        throws IOException
    {
        buffer[bufOff++] = (byte)b;
        if (bufOff == buffer.length)
        {
            Base64.encode(buffer, 0, buffer.length, out);
            out.write(nl);
            bufOff = 0;
        }
    }

    public void write(byte[] input, int off, int len)
        throws IOException
    {
        int remaining = len;
        int index = off;
        if (remaining > buffer.length - bufOff)
        {
            System.arraycopy(input, off, buffer, bufOff, buffer.length - bufOff);
            Base64.encode(buffer, 0, buffer.length, out);
            out.write(nl);

            index += buffer.length - bufOff;
            remaining -= buffer.length - bufOff;
            bufOff = 0;

            while (remaining >= buffer.length)
            {
                Base64.encode(input, index, buffer.length, out);
                out.write(nl);
                remaining -= buffer.length;
                index += buffer.length;
            }
        }

        if (remaining > 0)
        {
            System.arraycopy(input, index, buffer, bufOff, remaining);
            bufOff += remaining;
        }
    }

    public void write(byte[] buf)
        throws IOException
    {
        write(buf, 0, buf.length);
    }

    public void close()
        throws IOException
    {
        if (bufOff > 0)
        {
            Base64.encode(buffer, 0, bufOff, out);
            out.write(nl);
        }
        out.close();
    }
}
