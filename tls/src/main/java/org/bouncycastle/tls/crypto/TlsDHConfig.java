package org.bouncycastle.tls.crypto;

/**
 * Basic config for Diffie-Hellman.
 */
public class TlsDHConfig
{
    protected final DHGroup explicitGroup;
    protected final int namedGroup;
    protected final boolean padded;

    public TlsDHConfig(DHGroup explicitGroup)
    {
        this.explicitGroup = explicitGroup;
        this.namedGroup = -1;
        this.padded = false;
    }

    public TlsDHConfig(int namedGroup, boolean padded)
    {
        this.explicitGroup = null;
        this.namedGroup = namedGroup;
        this.padded = padded;
    }

    public DHGroup getExplicitGroup()
    {
        return explicitGroup;
    }

    public int getNamedGroup()
    {
        return namedGroup;
    }

    public boolean isPadded()
    {
        return padded;
    }
}
