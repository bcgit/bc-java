package org.bouncycastle.pqc.crypto.sqisign;

/** Even-degree (power-of-two) isogeny: domain curve + kernel generator + length. */
final class EcIsogEven
{
    public final EcCurve curve;
    public final EcPoint kernel;
    public int length;

    public EcIsogEven()
    {
        this.curve = new EcCurve();
        this.kernel = new EcPoint();
        this.length = 0;
    }
}
