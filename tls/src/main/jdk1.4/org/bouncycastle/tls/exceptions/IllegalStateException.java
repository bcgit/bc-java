package org.bouncycastle.tls.exceptions;

public class IllegalStateException
    extends java.lang.IllegalArgumentException
{
    final Throwable cause;

    public IllegalStateException(Throwable cause)
    {
        this.cause = cause;
    }

    public IllegalStateException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }


    public IllegalStateException(String s)
    {
        super(s);
        this.cause = null;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
