package org.bouncycastle.crypto.tls.test;

import java.io.IOException;

import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.SRPTlsClient;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsSRPKeyExchange;
import org.bouncycastle.util.Arrays;

public class MockSRPTlsClient extends SRPTlsClient implements ITestTlsClient
{

    byte[] receivedAppData;
    TlsSRPKeyExchange keyExchange;
    
    public MockSRPTlsClient(byte[] identity, byte[] password)
    {
        super(identity, password);
    }

    public int[] getCipherSuites()
    {
        return new int[] {CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA};
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        keyExchange = (TlsSRPKeyExchange) super.getKeyExchange();
        return keyExchange;
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
