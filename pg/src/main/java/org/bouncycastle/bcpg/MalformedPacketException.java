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
        super(cause);
    }

    public MalformedPacketException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
