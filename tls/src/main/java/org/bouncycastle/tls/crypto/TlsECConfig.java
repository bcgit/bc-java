package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.NamedGroup;

/**
 * Carrier class for Elliptic Curve parameter configuration.
 */
public class TlsECConfig
{
    protected final int namedGroup;

    public TlsECConfig(int namedGroup)
    {
        this.namedGroup = namedGroup;
    }

    /**
     * Return the group used.
     *
     * @return the {@link NamedGroup named group} used.
     */
    public int getNamedGroup()
    {
        return namedGroup;
    }
}
