package org.bouncycastle.tsp.ers;

/**
 * Base exception for errors in the RFC 4998 Evidence Record Syntax (ERS) layer.
 */
public class ERSException
    extends Exception
{
    private final Throwable cause;

    public ERSException(final String message)
    {
        this(message, null);
    }

    public ERSException(final String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}

