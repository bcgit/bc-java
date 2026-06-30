package org.bouncycastle.bcpg;

import java.io.IOException;

public class MalformedPacketException
    extends IOException
{

    public MalformedPacketException(String message)
    {
        super(message);
    }

    public MalformedPacketException(Throwable cause)
    {
        this(cause == null ? null : cause.getMessage(), cause);
    }

    public MalformedPacketException(String message, Throwable cause)
    {
        super(message);
        if (cause != null)
        {
            initCause(cause);
        }
    }
}
