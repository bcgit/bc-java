package org.bouncycastle.crypto.tls;

public interface TlsSession
{
    void close();

    byte[] getSessionID();

    SecurityParameters getSecurityParameters();
}
