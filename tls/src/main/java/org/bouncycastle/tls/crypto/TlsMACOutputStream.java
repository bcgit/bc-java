package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public class TlsMACOutputStream
    extends OutputStream
{
    protected TlsMAC mac;

    public TlsMACOutputStream(TlsMAC mac)
    {
        this.mac = mac;
    }

    public void write(int b) throws IOException
    {
        mac.update(new byte[]{ (byte)b }, 0, 1);
    }

    public void write(byte[] buf, int off, int len) throws IOException
    {
        mac.update(buf, off, len);
    }
}
