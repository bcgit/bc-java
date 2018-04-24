package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

class SignatureOutputStream extends OutputStream
{
    protected final Signature s;

    SignatureOutputStream(Signature s)
    {
        this.s = s;
    }

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

    public void write(byte[] buf, int off, int len) throws IOException
    {
        try
        {
            s.update(buf, off, len);
        }
        catch (SignatureException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
