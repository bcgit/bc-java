package org.bouncycastle.tsp;

import java.io.IOException;

/**
 * IOException subclass for I/O and encoding failures arising while processing RFC 3161
 * time-stamp protocol objects. Any underlying cause is available through {@link #getCause()}.
 */
public class TSPIOException
    extends IOException
{
    Throwable underlyingException;

    public TSPIOException(String message)
    {
        super(message);
    }

    public TSPIOException(String message, Throwable e)
    {
        super(message);
        underlyingException = e;
    }

    public Exception getUnderlyingException()
    {
        return (Exception)underlyingException;
    }

    public Throwable getCause()
    {
        return underlyingException;
    }
}
