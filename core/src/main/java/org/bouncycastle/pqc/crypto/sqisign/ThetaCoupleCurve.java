package org.bouncycastle.pqc.crypto.sqisign;


/** Pair of Montgomery curves (E1, E2) forming a product. */
final class ThetaCoupleCurve
{
    public final EcCurve E1;
    public final EcCurve E2;

    public ThetaCoupleCurve()
    {
        this.E1 = new EcCurve();
        this.E2 = new EcCurve();
    }
}
