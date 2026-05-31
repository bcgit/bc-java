package org.bouncycastle.pqc.crypto.sqisign;

/** Kernel-point structure for a degree-2 isogeny. */
final class EcKps2
{
    public final EcPoint K;

    public EcKps2()
    {
        this.K = new EcPoint();
    }
}
