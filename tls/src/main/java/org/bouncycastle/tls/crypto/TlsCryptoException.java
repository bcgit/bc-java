package org.bouncycastle.tls.crypto;

import java.io.IOException;


/**
 * Basic exception class for crypto services to pass back a cause.
 */
public class TlsCryptoException
    extends IOException
{
    private final Throwable cause;

    public TlsCryptoException(String msg, Throwable cause)
    {
        super(msg);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
