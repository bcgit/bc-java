package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.TlsClient;

public interface ITestTlsClient extends TlsClient
{

    byte[] getReceivedAppData();
    
}
