package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Montgomery curve isomorphism (X : Z) ↦ ((Nx X + Nz Z) : (D Z)).
 * Mirrors C {@code ec_isom_t}.
 */
final class EcIsom
{
    public final Fp2 Nx;
    public final Fp2 Nz;
    public final Fp2 D;

    public EcIsom()
    {
        this.Nx = Fp2.zero();
        this.Nz = Fp2.zero();
        this.D = Fp2.zero();
    }
}
