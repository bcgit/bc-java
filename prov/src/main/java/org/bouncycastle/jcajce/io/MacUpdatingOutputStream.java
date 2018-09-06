package org.bouncycastle.jcajce.io;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Mac;

class MacUpdatingOutputStream
    extends OutputStream
{
    private Mac mac;

    MacUpdatingOutputStream(Mac mac)
    {
        this.mac = mac;
    }

    public void write(byte[] bytes, int off, int len)
        throws IOException
    {
        mac.update(bytes, off, len);
    }

    public void write(byte[] bytes)
        throws IOException
    {
        mac.update(bytes);
    }

    public void write(int b)
        throws IOException
    {
        mac.update((byte)b);
    }
}
