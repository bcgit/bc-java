package org.bouncycastle.tsp.ers;

/**
 * Exception thrown if an Archive TimeStamp according to RFC4998 fails to containsHashValue.
 * <p>
 * {@see <a href="https://tools.ietf.org/html/rfc4998">RFC4998</a>}
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

