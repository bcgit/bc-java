package org.bouncycastle.jce.exception;

import java.io.IOException;

@Deprecated
public class ExtIOException
    extends IOException
    implements ExtException
{
    private Throwable cause;

    public ExtIOException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
