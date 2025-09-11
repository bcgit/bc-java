package org.bouncycastle.tls.exception;

public class IOException
    extends java.io.IOException
{
    final Throwable cause;

    public IOException(Throwable cause)
    {
        this.cause = cause;
    }

    public IOException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }
    

    public IOException(String s)
    {
        super(s);
        this.cause = null;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
