package org.bouncycastle.tls.crypto;

public class TlsKemConfig
{
    protected final int namedGroup;
    protected final boolean isServer;

    public TlsKemConfig(int namedGroup, boolean isServer)
    {
        this.namedGroup = namedGroup;
        this.isServer = isServer;
    }

    public int getNamedGroup()
    {
        return namedGroup;
    }

    public boolean isServer()
    {
        return isServer;
    }
}
