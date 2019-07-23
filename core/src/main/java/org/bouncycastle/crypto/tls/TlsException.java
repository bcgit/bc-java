package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class TlsException
    extends IOException
{
    // TODO Some day we might be able to just pass this down to IOException (1.6+)
    protected Throwable cause;

    public TlsException(String message, Throwable cause)
    {
        super(message);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
