package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Theta structure: null point plus 8 precomputed values used for theta-point
 * doubling and (2,2)-isogenies. Carries a {@link GfField} tag so theta-side
 * convenience overloads can dispatch arithmetic to the correct prime without
 * an external field parameter — mirrors the {@link EcCurve#field} tagging on
 * the elliptic side.
 */
final class ThetaStructure
{
    public final ThetaPoint nullPoint;
    public boolean precomputation;

    public final Fp2 XYZ0;
    public final Fp2 YZT0;
    public final Fp2 XZT0;
    public final Fp2 XYT0;
    public final Fp2 xyz0;
    public final Fp2 yzt0;
    public final Fp2 xzt0;
    public final Fp2 xyt0;
    public GfField field;

    public ThetaStructure()
    {
        this.nullPoint = new ThetaPoint();
        this.precomputation = false;
        this.XYZ0 = Fp2.zero();
        this.YZT0 = Fp2.zero();
        this.XZT0 = Fp2.zero();
        this.XYT0 = Fp2.zero();
        this.xyz0 = Fp2.zero();
        this.yzt0 = Fp2.zero();
        this.xzt0 = Fp2.zero();
        this.xyt0 = Fp2.zero();
        this.field = GfFieldLvl1.INSTANCE;
    }
}
