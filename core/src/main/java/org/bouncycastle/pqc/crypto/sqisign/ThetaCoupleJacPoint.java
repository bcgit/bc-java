package org.bouncycastle.pqc.crypto.sqisign;


/** A pair of Jacobian points on E1 × E2. */
final class ThetaCoupleJacPoint
{
    public final JacPoint P1;
    public final JacPoint P2;

    public ThetaCoupleJacPoint()
    {
        this.P1 = new JacPoint();
        this.P2 = new JacPoint();
    }

    public static void copy(ThetaCoupleJacPoint dst, ThetaCoupleJacPoint src)
    {
        JacPoint.copy(dst.P1, src.P1);
        JacPoint.copy(dst.P2, src.P2);
    }
}
