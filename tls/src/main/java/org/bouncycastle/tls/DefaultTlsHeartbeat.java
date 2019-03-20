package org.bouncycastle.tls;

import org.bouncycastle.util.Pack;

public class DefaultTlsHeartbeat
    implements TlsHeartbeat
{
    private final int idleMillis, timeoutMillis;

    private int counter = 0;

    public DefaultTlsHeartbeat(int idleMillis, int timeoutMillis)
    {
        if (idleMillis <= 0)
        {
            throw new IllegalArgumentException("'idleMillis' must be > 0");
        }
        if (timeoutMillis <= 0)
        {
            throw new IllegalArgumentException("'timeoutMillis' must be > 0");
        }

        this.idleMillis = idleMillis;
        this.timeoutMillis = timeoutMillis;
    }

    public synchronized byte[] generatePayload()
    {
        // NOTE: The counter naturally wraps back to 0
        return Pack.intToBigEndian(++counter);
    }

    public int getIdleMillis()
    {
        return idleMillis;
    }

    public int getTimeoutMillis()
    {
        return timeoutMillis;
    }
}
