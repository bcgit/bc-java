package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Signer;

class SignerOutputStream
    extends OutputStream
{
    private Signer sig;

    SignerOutputStream(Signer sig)
    {
        this.sig = sig;
    }

    public void write(byte[] bytes, int off, int len)
        throws IOException
    {
        sig.update(bytes, off, len);
    }

    public void write(byte[] bytes)
        throws IOException
    {
        sig.update(bytes, 0, bytes.length);
    }

    public void write(int b)
        throws IOException
    {
        sig.update((byte)b);
    }
}
