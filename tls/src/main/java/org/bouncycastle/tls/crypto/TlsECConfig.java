package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.NamedGroup;

/**
 * Carrier class for Elliptic Curve parameter configuration.
 */
public class TlsECConfig
{
    protected int namedGroup;

    /**
     * Return the group used.
     *
     * @return the {@link NamedGroup named group} used.
     */
    public int getNamedGroup()
    {
        return namedGroup;
    }

    /**
     * Set the group to use.
     *
     * @param namedGroup the {@link NamedGroup named group} to use.
     */
    public void setNamedGroup(int namedGroup)
    {
        this.namedGroup = namedGroup;
    }
}
