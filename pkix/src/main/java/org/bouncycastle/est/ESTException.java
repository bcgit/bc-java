package org.bouncycastle.est;

public class ESTException
    extends Exception
{
    private final Throwable cause;

    public ESTException(String msg)
    {
        this(msg, null);
    }

    public ESTException(String msg, Throwable cause)
    {
        super(msg);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
