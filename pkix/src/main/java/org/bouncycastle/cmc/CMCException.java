package org.bouncycastle.cmc;

public class CMCException
    extends Exception
{
    private final Throwable cause;

    public CMCException(String msg)
    {
        this(msg, null);
    }

    public CMCException(String msg, Throwable cause)
    {
        super(msg);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
