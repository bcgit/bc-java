package org.bouncycastle.pqc.crypto.sqisign;


/** A pair of x-only points on an elliptic-curve product E1 × E2. */
final class ThetaCouplePoint
{
    public final EcPoint P1;
    public final EcPoint P2;

    public ThetaCouplePoint()
    {
        this.P1 = new EcPoint();
        this.P2 = new EcPoint();
    }

    public static void copy(ThetaCouplePoint dst, ThetaCouplePoint src)
    {
        EcPoint.copy(dst.P1, src.P1);
        EcPoint.copy(dst.P2, src.P2);
    }
}
