package org.bouncycastle.pqc.crypto.sqisign;

/** Kernel-point structure for a degree-4 isogeny: 3 auxiliary points. */
final class EcKps4
{
    public final EcPoint[] K;

    public EcKps4()
    {
        this.K = new EcPoint[]{new EcPoint(), new EcPoint(), new EcPoint()};
    }
}
