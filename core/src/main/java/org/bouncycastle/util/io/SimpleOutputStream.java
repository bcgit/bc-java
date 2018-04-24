package org.bouncycastle.util.io;

import java.io.IOException;
import java.io.OutputStream;

public abstract class SimpleOutputStream extends OutputStream
{
    public void close()
    {
    }

    public void flush()
    {
    }

    public void write(int b) throws IOException
    {
        byte[] buf = new byte[]{ (byte)b };
        write(buf, 0, 1);
    }
}
