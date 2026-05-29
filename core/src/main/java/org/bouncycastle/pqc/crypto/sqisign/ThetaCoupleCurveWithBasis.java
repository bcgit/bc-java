package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of C {@code theta_couple_curve_with_basis_t}: a product
 * {@code E1 × E2} together with bases on each factor.
 *
 * <p>From {@code src/hd/ref/include/hd.h}.</p>
 */
final class ThetaCoupleCurveWithBasis
{
    public final EcCurve E1;
    public final EcCurve E2;
    public final EcBasis B1;
    public final EcBasis B2;

    public ThetaCoupleCurveWithBasis()
    {
        this.E1 = new EcCurve();
        this.E2 = new EcCurve();
        this.B1 = new EcBasis();
        this.B2 = new EcBasis();
    }
}
