package org.bouncycastle.jcajce.io;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

class DigestUpdatingOutputStream
    extends OutputStream
{
    private MessageDigest digest;

    DigestUpdatingOutputStream(MessageDigest digest)
    {
        this.digest = digest;
    }

    public void write(byte[] bytes, int off, int len)
        throws IOException
    {
        digest.update(bytes, off, len);
    }

    public void write(byte[] bytes)
        throws IOException
    {
        digest.update(bytes);
    }

    public void write(int b)
        throws IOException
    {
        digest.update((byte)b);
    }
}
