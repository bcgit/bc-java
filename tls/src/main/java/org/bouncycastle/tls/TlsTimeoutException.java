package org.bouncycastle.tls;

import java.io.IOException;

public class TlsTimeoutException
    extends IOException
{
    public TlsTimeoutException(String message)
    {
        super(message);
    }
}
