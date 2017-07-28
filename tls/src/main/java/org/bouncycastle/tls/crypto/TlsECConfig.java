package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.NamedGroup;

/**
 * Carrier class for Elliptic Curve parameter configuration.
 */
public class TlsECConfig
{
    protected int namedGroup;
    protected boolean pointCompression;

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

    /**
     * Return whether or not point compression is enabled for this config.
     *
     * @return true if point compression is enabled, false otherwise.
     */
    public boolean getPointCompression()
    {
        return pointCompression;
    }

    /**
     * Set whether point compression should be enabled for this config.
     *
     * @param pointCompression true if point compression should be enabled.
     */
    public void setPointCompression(boolean pointCompression)
    {
        this.pointCompression = pointCompression;
    }
}
