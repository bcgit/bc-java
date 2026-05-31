package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of {@code src/precomp/ref/lvl1/hd_splitting_transforms.c}.
 *
 * <p>The C reference stores {@code FP2_CONSTANTS[5]} as Montgomery-form
 * limb arrays for the five special values {0, 1, i, -1, -i}. In Java these
 * are constructible algebraically (no Montgomery decoding needed), so we
 * inline them. The {@code SPLITTING_TRANSFORMS[10]} and
 * {@code NORMALIZATION_TRANSFORMS[6]} tables in the C reference are
 * {@code precomp_basis_change_matrix_t} arrays of indices into
 * {@code FP2_CONSTANTS}; this port preserves that layout as
 * {@code int[10][4][4]} / {@code int[6][4][4]} of indices, plus a
 * {@link BasisChangeMatrix} on demand.</p>
 */
final class HdSplittingTransformsLvl1
{
    private static final org.bouncycastle.pqc.crypto.sqisign.GfField field = org.bouncycastle.pqc.crypto.sqisign.GfFieldLvl1.INSTANCE;

    /** Indices into {@link #FP2_CONSTANTS}. */
    public static final int FP2_ZERO = 0;
    public static final int FP2_ONE = 1;
    public static final int FP2_I = 2;
    public static final int FP2_MINUS_ONE = 3;
    public static final int FP2_MINUS_I = 4;

    /**
     * The 5 special Fp² values referenced by the splitting tables.
     * {0, 1, i, -1, -i}.
     */
    public static final Fp2[] FP2_CONSTANTS = buildFp2Constants();

    private static Fp2[] buildFp2Constants()
    {
        Fp2[] c = new Fp2[5];
        c[FP2_ZERO] = Fp2.zero();
        c[FP2_ONE] = Fp2.one();

        // i = (0, 1)
        Fp2 i = new Fp2();
        Fp.setSmall(i.im, 1);
        c[FP2_I] = i;

        // -1 = (p-1, 0)
        Fp2 minusOne = new Fp2();
        field.fpNeg(minusOne.re, new Fp(java.math.BigInteger.ONE));
        c[FP2_MINUS_ONE] = minusOne;

        // -i = (0, p-1)
        Fp2 minusI = new Fp2();
        field.fpNeg(minusI.im, new Fp(java.math.BigInteger.ONE));
        c[FP2_MINUS_I] = minusI;

        return c;
    }

    /** Mirror of the 10-entry {@code EVEN_INDEX[10][2]} table. */
    public static final int[][] EVEN_INDEX = {
        {0, 0}, {0, 1}, {0, 2}, {0, 3},
        {1, 0}, {1, 2}, {2, 0}, {2, 1},
        {3, 0}, {3, 3}
    };

    /** Mirror of the 4x4 character-evaluation table {@code CHI_EVAL[4][4]}. */
    public static final int[][] CHI_EVAL = {
        {1, 1, 1, 1},
        {1, -1, 1, -1},
        {1, 1, -1, -1},
        {1, -1, -1, 1}
    };

    /**
     * Mirror of {@code SPLITTING_TRANSFORMS[10]}: each entry is a 4×4 matrix
     * of indices into {@link #FP2_CONSTANTS}.
     */
    public static final int[][][] SPLITTING_TRANSFORM_INDICES = {
        // 0: {{1,i,1,i}, {1,-i,-1,i}, {1,i,-1,-i}, {-1,i,-1,i}}
        {{FP2_ONE, FP2_I, FP2_ONE, FP2_I},
         {FP2_ONE, FP2_MINUS_I, FP2_MINUS_ONE, FP2_I},
         {FP2_ONE, FP2_I, FP2_MINUS_ONE, FP2_MINUS_I},
         {FP2_MINUS_ONE, FP2_I, FP2_MINUS_ONE, FP2_I}},
        // 1: 1, 0, 0, 0; 0, 0, 0, 1; 0, 0, 1, 0; 0, -1, 0, 0
        {{FP2_ONE, FP2_ZERO, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ZERO, FP2_ONE},
         {FP2_ZERO, FP2_ZERO, FP2_ONE, FP2_ZERO},
         {FP2_ZERO, FP2_MINUS_ONE, FP2_ZERO, FP2_ZERO}},
        // 2:
        {{FP2_ONE, FP2_ZERO, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ONE, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ZERO, FP2_ONE},
         {FP2_ZERO, FP2_ZERO, FP2_MINUS_ONE, FP2_ZERO}},
        // 3:
        {{FP2_ONE, FP2_ZERO, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ONE, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ONE, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ZERO, FP2_MINUS_ONE}},
        // 4: Hadamard with signs (1,1,1,1;1,-1,-1,1;1,1,-1,-1;-1,1,-1,1)
        {{FP2_ONE, FP2_ONE, FP2_ONE, FP2_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE, FP2_ONE},
         {FP2_ONE, FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE},
         {FP2_MINUS_ONE, FP2_ONE, FP2_MINUS_ONE, FP2_ONE}},
        // 5:
        {{FP2_ONE, FP2_ZERO, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ONE, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ZERO, FP2_ONE},
         {FP2_ZERO, FP2_ZERO, FP2_ONE, FP2_ZERO}},
        // 6:
        {{FP2_ONE, FP2_ONE, FP2_ONE, FP2_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_ONE, FP2_MINUS_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE, FP2_ONE},
         {FP2_MINUS_ONE, FP2_MINUS_ONE, FP2_ONE, FP2_ONE}},
        // 7:
        {{FP2_ONE, FP2_ONE, FP2_ONE, FP2_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_ONE, FP2_MINUS_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE, FP2_ONE},
         {FP2_ONE, FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE}},
        // 8:
        {{FP2_ONE, FP2_ONE, FP2_ONE, FP2_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_ONE, FP2_MINUS_ONE},
         {FP2_ONE, FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE},
         {FP2_MINUS_ONE, FP2_ONE, FP2_ONE, FP2_MINUS_ONE}},
        // 9: identity
        {{FP2_ONE, FP2_ZERO, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ONE, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ONE, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ZERO, FP2_ONE}}
    };

    /** Mirror of {@code NORMALIZATION_TRANSFORMS[6]}. */
    public static final int[][][] NORMALIZATION_TRANSFORM_INDICES = {
        // 0: identity
        {{FP2_ONE, FP2_ZERO, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ONE, FP2_ZERO, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ONE, FP2_ZERO},
         {FP2_ZERO, FP2_ZERO, FP2_ZERO, FP2_ONE}},
        // 1: anti-diagonal
        {{FP2_ZERO, FP2_ZERO, FP2_ZERO, FP2_ONE},
         {FP2_ZERO, FP2_ZERO, FP2_ONE, FP2_ZERO},
         {FP2_ZERO, FP2_ONE, FP2_ZERO, FP2_ZERO},
         {FP2_ONE, FP2_ZERO, FP2_ZERO, FP2_ZERO}},
        // 2:
        {{FP2_ONE, FP2_ONE, FP2_ONE, FP2_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_ONE, FP2_MINUS_ONE},
         {FP2_ONE, FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE},
         {FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE, FP2_ONE}},
        // 3:
        {{FP2_ONE, FP2_MINUS_ONE, FP2_MINUS_ONE, FP2_ONE},
         {FP2_MINUS_ONE, FP2_MINUS_ONE, FP2_ONE, FP2_ONE},
         {FP2_MINUS_ONE, FP2_ONE, FP2_MINUS_ONE, FP2_ONE},
         {FP2_ONE, FP2_ONE, FP2_ONE, FP2_ONE}},
        // 4:
        {{FP2_MINUS_ONE, FP2_I, FP2_I, FP2_ONE},
         {FP2_I, FP2_MINUS_ONE, FP2_ONE, FP2_I},
         {FP2_I, FP2_ONE, FP2_MINUS_ONE, FP2_I},
         {FP2_ONE, FP2_I, FP2_I, FP2_MINUS_ONE}},
        // 5:
        {{FP2_ONE, FP2_I, FP2_I, FP2_MINUS_ONE},
         {FP2_I, FP2_ONE, FP2_MINUS_ONE, FP2_I},
         {FP2_I, FP2_MINUS_ONE, FP2_ONE, FP2_I},
         {FP2_MINUS_ONE, FP2_I, FP2_I, FP2_ONE}}
    };

    private HdSplittingTransformsLvl1()
    {
    }
}
