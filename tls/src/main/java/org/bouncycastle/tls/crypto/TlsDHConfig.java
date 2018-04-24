package org.bouncycastle.tls.crypto;

/**
 * Basic config for Diffie-Hellman.
 */
public class TlsDHConfig
{
    protected final DHGroup explicitGroup;
    protected final int namedGroup;

    public TlsDHConfig(DHGroup explicitGroup)
    {
        this.explicitGroup = explicitGroup;
        this.namedGroup = -1;
    }

    public TlsDHConfig(int namedGroup)
    {
        this.explicitGroup = null;
        this.namedGroup = namedGroup;
    }

    public DHGroup getExplicitGroup()
    {
        return explicitGroup;
    }

    public int getNamedGroup()
    {
        return namedGroup;
    }
}
