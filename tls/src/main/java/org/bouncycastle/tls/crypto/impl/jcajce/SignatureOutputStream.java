package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

class SignatureOutputStream extends SimpleOutputStream
{
    protected final Signature s;

    SignatureOutputStream(Signature s)
    {
        this.s = s;
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
