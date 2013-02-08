package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;

class WrappedGeneratorStream
    extends OutputStream
{
    private final OutputStream    _out;
    private final StreamGenerator _sGen;

    public WrappedGeneratorStream(OutputStream out, StreamGenerator sGen)
    {
        _out = out;
        _sGen = sGen;
    }
    public void write(byte[] bytes)
        throws IOException
    {
        _out.write(bytes);
    }

    public void write(byte[] bytes, int offset, int length)
        throws IOException
    {
        _out.write(bytes, offset, length);
    }

    public void write(int b)
        throws IOException
    {
        _out.write(b);
    }

    public void flush()
        throws IOException
    {
        _out.flush();
    }

    public void close()
        throws IOException
    {
        _sGen.close();
    }
}
