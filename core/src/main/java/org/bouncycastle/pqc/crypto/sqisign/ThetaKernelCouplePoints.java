package org.bouncycastle.pqc.crypto.sqisign;

/** Triple (T1, T2, T1 - T2) of theta couple points for the kernel of a (2,2)-isogeny. */
final class ThetaKernelCouplePoints
{
    public final ThetaCouplePoint T1;
    public final ThetaCouplePoint T2;
    public final ThetaCouplePoint T1m2;

    public ThetaKernelCouplePoints()
    {
        this.T1 = new ThetaCouplePoint();
        this.T2 = new ThetaCouplePoint();
        this.T1m2 = new ThetaCouplePoint();
    }
}
