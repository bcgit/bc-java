package org.bouncycastle.pqc.crypto.sqisign;

/** Basis of a torsion subgroup: a pair of generators and their difference. */
final class EcBasis
{
    public final EcPoint P;
    public final EcPoint Q;
    public final EcPoint PmQ;

    public EcBasis()
    {
        this.P = new EcPoint();
        this.Q = new EcPoint();
        this.PmQ = new EcPoint();
    }

    public static void copy(EcBasis dst, EcBasis src)
    {
        EcPoint.copy(dst.P, src.P);
        EcPoint.copy(dst.Q, src.Q);
        EcPoint.copy(dst.PmQ, src.PmQ);
    }
}
