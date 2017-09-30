package com.github.gv2011.asn1.util;

/**
 * Exception thrown if there's an issue doing a match in store.
 */
public class StoreException
    extends RuntimeException
{
    private static final long serialVersionUID = -4494398899749791129L;

    private final Throwable _e;

    /**
     * Basic Constructor.
     *
     * @param msg message to be associated with this exception.
     * @param cause the throwable that caused this exception to be raised.
     */
    public StoreException(final String msg, final Throwable cause)
    {
        super(msg);
        _e = cause;
    }

    @Override
    public Throwable getCause()
    {
        return _e;
    }
}
