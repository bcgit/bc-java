package org.bouncycastle.mime.encoding;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.encoders.Base64;

public class Base64OutputStream
    extends FilterOutputStream
{
    byte[] buffer = new byte[54];
    int    bufOff;

    public Base64OutputStream(OutputStream stream)
    {
        super(stream);
    }

    public void write(int b)
        throws IOException
    {
        doWrite((byte)b);
    }

    public void write(byte[] buf, int bufOff, int len)
        throws IOException
    {
        for (int i = 0; i != len; i++)
        {
            doWrite(buf[bufOff + i]);
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
        }
        out.close();
    }
    
    private void doWrite(byte b)
        throws IOException
    {
        buffer[bufOff++] = b;
        if (bufOff == buffer.length)
        {
            Base64.encode(buffer, 0, buffer.length, out);
            out.write('\r');
            out.write('\n');
            bufOff = 0;
        }
    }
}
