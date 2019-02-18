package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

class NullOutputStream
    extends OutputStream
{
    static final NullOutputStream INSTANCE = new NullOutputStream();

    private NullOutputStream()
    {
    }

    public void write(byte[] buf) throws IOException
    {
    }

    public void write(byte[] buf, int off, int len) throws IOException
    {
    }

    public void write(int b) throws IOException
    {
    }
}
