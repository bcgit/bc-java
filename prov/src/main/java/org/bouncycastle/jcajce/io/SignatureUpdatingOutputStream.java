package org.bouncycastle.jcajce.io;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

class SignatureUpdatingOutputStream
    extends OutputStream
{
    private Signature sig;

    SignatureUpdatingOutputStream(Signature sig)
    {
        this.sig = sig;
    }

    public void write(byte[] bytes, int off, int len)
        throws IOException
    {
        try
        {
            sig.update(bytes, off, len);
        }
        catch (SignatureException e)
        {
            throw new IOException(e.getMessage());
        }
    }

    public void write(byte[] bytes)
        throws IOException
    {
        try
        {
            sig.update(bytes);
        }
        catch (SignatureException e)
        {
            throw new IOException(e.getMessage());
        }
    }

    public void write(int b)
        throws IOException
    {
        try
        {
            sig.update((byte)b);
        }
        catch (SignatureException e)
        {
            throw new IOException(e.getMessage());
        }
    }
}
