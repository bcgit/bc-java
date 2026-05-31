package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Gluing (2, 2) theta isogeny structure: domain elliptic-curve product, the
 * 8-torsion couple-jac point K1_8 and its theta image, the basis-change
 * matrix M, the precomputation theta point, and the codomain theta point.
 *
 * <p>Mirrors C {@code theta_gluing_t}.</p>
 */
final class ThetaGluing
{
    public final ThetaCoupleCurve domain;
    public final ThetaCoupleJacPoint xyK1_8;
    public final ThetaPointCompact imageK1_8;
    public final BasisChangeMatrix M;
    public final ThetaPoint precomputation;
    public final ThetaPoint codomain;

    public ThetaGluing()
    {
        this.domain = new ThetaCoupleCurve();
        this.xyK1_8 = new ThetaCoupleJacPoint();
        this.imageK1_8 = new ThetaPointCompact();
        this.M = new BasisChangeMatrix();
        this.precomputation = new ThetaPoint();
        this.codomain = new ThetaPoint();
    }
}
