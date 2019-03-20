package org.bouncycastle.tls;

import java.io.IOException;

/**
 * This exception will be thrown (only) when the connection is closed by the peer without sending a
 * {@link AlertDescription#close_notify close_notify} warning alert. If this happens, the TLS
 * protocol cannot rule out truncation of the connection data (potentially malicious). It may be
 * possible to check for truncation via some property of a higher level protocol built upon TLS,
 * e.g. the Content-Length header for HTTPS.
 */
public class TlsTimeoutException
    extends IOException
{
    public TlsTimeoutException(String message)
    {
        super(message);
    }
}
