package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Montgomery elliptic curve {@code y² = x³ + (A/C)·x² + x}, projective in
 * (A : C). Includes the cached point {@code A24 = (A + 2C : 4C)} used by the
 * doubling primitives.
 *
 * <p>The {@link #field} member tags the curve with its GF(p²) arithmetic
 * implementation. It defaults to {@link GfFieldLvl1#INSTANCE} so legacy lvl1
 * paths (which were written before this tag existed) keep working unchanged.
 * Level-3 and level-5 precomp loaders re-tag the curves they construct so that
 * arithmetic-dispatching helpers route through the correct prime.</p>
 */
final class EcCurve
{
    public final Fp2 A;
    public final Fp2 C;
    public final EcPoint A24;
    public boolean isA24ComputedAndNormalized;
    /**
     * GF(p²) implementation backing this curve's coordinates. Defaults to
     * lvl1; precomp tables for higher levels must set this explicitly.
     */
    public GfField field;

    public EcCurve()
    {
        this.A = Fp2.zero();
        this.C = Fp2.one();
        this.A24 = new EcPoint();
        this.isA24ComputedAndNormalized = false;
        this.field = GfFieldLvl1.INSTANCE;
    }

    public EcCurve copy()
    {
        EcCurve out = new EcCurve();
        Fp2.copy(out.A, this.A);
        Fp2.copy(out.C, this.C);
        EcPoint.copy(out.A24, this.A24);
        out.isA24ComputedAndNormalized = this.isA24ComputedAndNormalized;
        out.field = this.field;
        return out;
    }

    /** Mirrors the inline {@code copy_curve}. */
    public static void copy(EcCurve dst, EcCurve src)
    {
        Fp2.copy(dst.A, src.A);
        Fp2.copy(dst.C, src.C);
        EcPoint.copy(dst.A24, src.A24);
        dst.isA24ComputedAndNormalized = src.isA24ComputedAndNormalized;
        dst.field = src.field;
    }
}
