package org.bouncycastle.tls.exception;

public class IllegalArgumentException
    extends java.lang.IllegalArgumentException
{
    final Throwable cause;

    public IllegalArgumentException(Throwable cause)
    {
        this.cause = cause;
    }

    public IllegalArgumentException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }
    

    public IllegalArgumentException(String s)
    {
        super(s);
        this.cause = null;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
