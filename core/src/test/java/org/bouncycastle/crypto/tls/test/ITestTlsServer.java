package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.TlsServer;

public interface ITestTlsServer extends TlsServer
{

    byte[] getReceivedAppData();
    
}
