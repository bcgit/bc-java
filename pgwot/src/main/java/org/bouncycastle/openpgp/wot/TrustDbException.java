package org.bouncycastle.openpgp.wot;

import org.bouncycastle.openpgp.wot.internal.TrustDbImpl;

/**
 * Exception thrown by {@link TrustDbImpl} and related classes.
 */
public class TrustDbException extends RuntimeException
{
    private static final long serialVersionUID = 1L;

    public TrustDbException()
    {
    }

    public TrustDbException(String message)
    {
        super(message);
    }

    public TrustDbException(Throwable cause)
    {
        super(cause);
    }

    public TrustDbException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
