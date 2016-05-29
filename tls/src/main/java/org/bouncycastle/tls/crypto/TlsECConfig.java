package org.bouncycastle.tls.crypto;

public class TlsECConfig
{
    protected int namedCurve;
    protected boolean pointCompression;

    public int getNamedCurve()
    {
        return namedCurve;
    }

    public void setNamedCurve(int namedCurve)
    {
        this.namedCurve = namedCurve;
    }

    public boolean getPointCompression()
    {
        return pointCompression;
    }

    public void setPointCompression(boolean pointCompression)
    {
        this.pointCompression = pointCompression;
    }
}
