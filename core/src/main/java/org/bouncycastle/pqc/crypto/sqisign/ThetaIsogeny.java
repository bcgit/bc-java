package org.bouncycastle.pqc.crypto.sqisign;

/** Standard (2, 2) theta isogeny: two 8-torsion theta points, hadamard flags,
 * domain/codomain theta structures, and a precomputation point. */
final class ThetaIsogeny
{
    public final ThetaPoint T1_8;
    public final ThetaPoint T2_8;
    public boolean hadamardBool1;
    public boolean hadamardBool2;
    public final ThetaStructure domain;
    public final ThetaPoint precomputation;
    public final ThetaStructure codomain;

    public ThetaIsogeny()
    {
        this.T1_8 = new ThetaPoint();
        this.T2_8 = new ThetaPoint();
        this.hadamardBool1 = false;
        this.hadamardBool2 = false;
        this.domain = new ThetaStructure();
        this.precomputation = new ThetaPoint();
        this.codomain = new ThetaStructure();
    }
}
