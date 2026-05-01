package org.bouncycastle.bcpg;

import java.io.IOException;

public class MalformedPacketException
    extends IOException
{
    private final Throwable cause;

    public MalformedPacketException(String message)
    {
        this(message, null);
    }

    public MalformedPacketException(Throwable cause)
    {
        this(cause.getMessage(), cause);
    }

    public MalformedPacketException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
