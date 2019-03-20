package org.bouncycastle.tls;

public interface TlsHeartbeat
{
    byte[] generatePayload();

    int getIdleMillis();

    int getTimeoutMillis();
}
