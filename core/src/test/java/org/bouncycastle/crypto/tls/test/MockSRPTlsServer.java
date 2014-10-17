package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.SRPTlsParameters;
import org.bouncycastle.crypto.tls.SRPTlsServer;

public class MockSRPTlsServer extends SRPTlsServer
{

    private SRPTlsParameters params;
    
    public MockSRPTlsServer(SRPTlsParameters params)
    {
        this.params = params;
    }

    @Override
    protected SRPTlsParameters getClientParameters()
    {
        return params;
    }

}
