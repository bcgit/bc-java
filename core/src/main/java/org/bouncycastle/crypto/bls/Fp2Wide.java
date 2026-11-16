package org.bouncycastle.crypto.bls;

/**
 * An unreduced element of Fp^2: both components are wide values of
 * {@link Fp#WIDE}, integers, possibly negative, standing for their
 * Montgomery reductions. Products of {@link Fp2Element}s are formed here in
 * full, summed, and reduced once by {@link #reduce()}: "lazy reduction". In
 * the Fp^6 / Fp^12 tower each output coefficient is a sum of several Fp^2
 * products, so this halves the number of reductions there.
 * <p>
 * Bounds: a product of two elements has components in {@code (-2p^2, 2p^2)};
 * the tower formulas add at most a handful of such terms, staying far inside
 * the {@code |x| < 2^768} (about 97 p^2) that {@link Fp#reduceWide} accepts.
 * It checks that bound rather than assume it.
 */
final class Fp2Wide
{
    private static final int S = Fp.SIZE;
    private static final int W = Fp.WIDE;

    /** c0 at 0, c1 at {@link Fp#WIDE}. */
    private final int[] w;

    private Fp2Wide(int[] w)
    {
        this.w = w;
    }

    /**
     * {@code a * b}, unreduced, by Karatsuba: three products,
     * {@code a0 b0 - a1 b1} and {@code (a0 + a1)(b0 + b1) - a0 b0 - a1 b1}.
     */
    static Fp2Wide mul(Fp2Element a, Fp2Element b)
    {
        int[] x = a.v, y = b.v;
        int[] s = new int[2 * S];
        Fp.add(x, 0, x, S, s, 0);
        Fp.add(y, 0, y, S, s, S);
        int[] t = new int[3 * W];
        Fp.mulWide(x, 0, y, 0, t, 0);
        Fp.mulWide(x, S, y, S, t, W);
        Fp.mulWide(s, 0, s, S, t, 2 * W);
        int[] z = new int[2 * W];
        Fp.subWide(t, 0, t, W, z, 0);
        Fp.subWide2(t, 2 * W, t, 0, t, W, z, W);
        return new Fp2Wide(z);
    }

    /** {@code a^2 = (a0 + a1)(a0 - a1) + 2 a0 a1 * I}, unreduced: two products. */
    static Fp2Wide square(Fp2Element a)
    {
        int[] x = a.v;
        int[] s = new int[2 * S];
        Fp.add(x, 0, x, S, s, 0);
        Fp.sub(x, 0, x, S, s, S);
        int[] z = new int[2 * W];
        Fp.mulWide(s, 0, s, S, z, 0);
        Fp.mulWide(x, 0, x, S, z, W);
        Fp.addWide(z, W, z, W, z, W);
        return new Fp2Wide(z);
    }

    Fp2Wide add(Fp2Wide o)
    {
        int[] z = new int[2 * W];
        Fp.addWide(w, 0, o.w, 0, z, 0);
        Fp.addWide(w, W, o.w, W, z, W);
        return new Fp2Wide(z);
    }

    Fp2Wide sub(Fp2Wide o)
    {
        int[] z = new int[2 * W];
        Fp.subWide(w, 0, o.w, 0, z, 0);
        Fp.subWide(w, W, o.w, W, z, W);
        return new Fp2Wide(z);
    }

    /** Multiply by the Fp^6 non-residue {@code 1 + I}: {@code (c0 - c1) + (c0 + c1) * I}. */
    Fp2Wide mulByNonResidue()
    {
        int[] z = new int[2 * W];
        Fp.subWide(w, 0, w, W, z, 0);
        Fp.addWide(w, 0, w, W, z, W);
        return new Fp2Wide(z);
    }

    /** The reduced element: one reduction per component. */
    Fp2Element reduce()
    {
        int[] z = new int[2 * S];
        Fp.reduceWide(w, 0, z, 0);
        Fp.reduceWide(w, W, z, S);
        return new Fp2Element(z);
    }
}
