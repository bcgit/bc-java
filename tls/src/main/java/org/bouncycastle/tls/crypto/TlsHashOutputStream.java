package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public class TlsHashOutputStream
    extends OutputStream
{
    protected TlsHash hash;

    public TlsHashOutputStream(TlsHash hash)
    {
        this.hash = hash;
    }

    public void write(int b) throws IOException
    {
        hash.update(new byte[]{ (byte)b }, 0, 1);
    }

    public void write(byte[] buf, int off, int len) throws IOException
    {
        hash.update(buf, off, len);
    }
}
