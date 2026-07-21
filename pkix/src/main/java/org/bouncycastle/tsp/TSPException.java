package org.bouncycastle.tsp;

/**
 * General checked exception for failures arising while processing RFC 3161 time-stamp
 * protocol objects. Any underlying cause is available through {@link #getCause()}.
 */
public class TSPException
    extends Exception
{
    Throwable underlyingException;

    public TSPException(String message)
    {
        super(message);
    }

    public TSPException(String message, Throwable e)
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
