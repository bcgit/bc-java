package org.bouncycastle.pkcs;

import java.io.IOException;

/**
 * Specialised {@link IOException} thrown by classes in {@link org.bouncycastle.pkcs} and its
 * sub-packages to signal malformed or corrupted PKCS encodings.
 */
public class PKCSIOException
    extends IOException
{
    private Throwable cause;

    public PKCSIOException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public PKCSIOException(String msg)
    {
        super(msg);
    }

    public Throwable getCause()
    {
        return cause;
    }
}
