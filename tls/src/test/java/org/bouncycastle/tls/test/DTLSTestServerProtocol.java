package org.bouncycastle.tls.test;

import org.bouncycastle.tls.DTLSServerProtocol;

class DTLSTestServerProtocol extends DTLSServerProtocol
{
    protected final TlsTestConfig config;

    public DTLSTestServerProtocol(TlsTestConfig config)
    {
        super();

        this.config = config;
    }
}
