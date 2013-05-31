package org.bouncycastle.crypto.tls.test;

import java.io.IOException;

import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.TlsAuthentication;

public class TestTlsClient
    extends DefaultTlsClient
{
    private final TlsAuthentication authentication;

    TestTlsClient(TlsAuthentication authentication)
    {
        this.authentication = authentication;
    }

    public TlsAuthentication getAuthentication()
        throws IOException
    {
        return authentication;
    }
}
