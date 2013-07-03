package org.bouncycastle.util.io;

import java.io.ByteArrayOutputStream;

/**
 * {@link ByteArrayOutputStream} that allows access to the internal byte buffer.
 */
public class AccessibleByteArrayOutputStream extends ByteArrayOutputStream
{

    public AccessibleByteArrayOutputStream()
    {
    }

    public AccessibleByteArrayOutputStream(int size)
    {
        super(size);
    }

    public byte[] getBuffer()
    {
        return this.buf;
    }

}
