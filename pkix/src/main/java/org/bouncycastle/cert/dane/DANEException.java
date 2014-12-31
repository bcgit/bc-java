package org.bouncycastle.cert.dane;

/**
 * General checked Exception thrown in the DANE package.
 */
public class DANEException
    extends Exception
{
    private Throwable cause;

    public DANEException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public DANEException(String msg)
    {
        super(msg);
    }

    public Throwable getCause()
    {
        return cause;
    }
}
