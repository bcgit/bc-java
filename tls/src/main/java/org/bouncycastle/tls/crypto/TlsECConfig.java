package org.bouncycastle.tls.crypto;

/**
 * Carrier class for Elliptic Curve parameter configuration.
 */
public class TlsECConfig
{
    protected int namedCurve;
    protected boolean pointCompression;

    /**
     * Return the TLS identifier of the named curve associated with this config.
     *
     * @return the TLS ID for the curve this config is for.
     */
    public int getNamedCurve()
    {
        return namedCurve;
    }

    /**
     * Set the curve to use.
     *
     * @param namedCurve the TLS ID for the curve to use.
     */
    public void setNamedCurve(int namedCurve)
    {
        this.namedCurve = namedCurve;
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
