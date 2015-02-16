package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.SRPTlsClient;

public class MockSRPTlsClient extends SRPTlsClient
{

    public MockSRPTlsClient(byte[] identity, byte[] password)
    {
        super(identity, password);
    }

    public int[] getCipherSuites()
    {
        return new int[] {CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA};
    }

}
