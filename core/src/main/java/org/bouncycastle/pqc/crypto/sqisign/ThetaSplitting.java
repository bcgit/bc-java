package org.bouncycastle.pqc.crypto.sqisign;

/** Theta splitting isomorphism: basis-change matrix M and target theta structure B. */
final class ThetaSplitting
{
    public final BasisChangeMatrix M;
    public final ThetaStructure B;

    public ThetaSplitting()
    {
        this.M = new BasisChangeMatrix();
        this.B = new ThetaStructure();
    }
}
