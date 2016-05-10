package com.github.gv2011.bcasn.crypto.io;

import java.io.IOException;
import java.io.OutputStream;

import com.github.gv2011.bcasn.crypto.Signer;

public class SignerOutputStream
    extends OutputStream
{
    protected Signer signer;

    public SignerOutputStream(
        Signer          Signer)
    {
        this.signer = Signer;
    }

    public void write(int b)
        throws IOException
    {
        signer.update((byte)b);
    }

    public void write(
        byte[] b,
        int off,
        int len)
        throws IOException
    {
        signer.update(b, off, len);
    }

    public Signer getSigner()
    {
        return signer;
    }
}
