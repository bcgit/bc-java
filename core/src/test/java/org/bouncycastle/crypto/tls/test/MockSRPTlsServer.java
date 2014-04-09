package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.SRPTlsParameters;
import org.bouncycastle.crypto.tls.SRPTlsServer;
import org.bouncycastle.util.Arrays;

public class MockSRPTlsServer extends SRPTlsServer implements ITestTlsServer
{

    private SRPTlsParameters params;
    byte[] receivedAppData;
    
    public MockSRPTlsServer(SRPTlsParameters params)
    {
        this.params = params;
    }

    @Override
    protected SRPTlsParameters getClientParameters()
    {
        return params;
    }
    
    public void notifyApplicationDataReceived(byte[] data)
    {
        receivedAppData = Arrays.concatenate(receivedAppData, data);
    }
    
    public byte[] getReceivedAppData()
    {
        return receivedAppData;
    }

}
