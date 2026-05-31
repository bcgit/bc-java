package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of {@code CONNECTING_IDEALS[7]} from
 * {@code src/precomp/ref/lvl1/quaternion_data.c}.
 *
 * <p>Each entry is a {@link QuatLeftIdeal} of the standard maximal order O₀
 * connecting it to one of the seven extremal orders (O₀ itself at index 0,
 * plus the six alternate extremal orders at indices 1..6). Used by
 * {@code dim2id2iso_ideal_to_isogeny_clapotis} when scaling β1 by
 * {@code (u·d1·N(CONNECTING_IDEALS[index_order1]))^{-1} mod 2^TORSION_EVEN_POWER}.</p>
 *
 * <p>The raw constants are mechanically extracted from the C reference via
 * {@code core/src/tools/python/extract_sqisign_precomp.py} and pasted as
 * {@link Ibz#fromMpLimbs} calls below — see that script for the
 * extract/verify workflow.</p>
 */
final class ConnectingIdealsLvl1
{
    /** Number of connecting ideals (1 standard + 6 alternates). */
    public static final int COUNT = 7;

    /** The seven connecting ideals, indexed [0..6]. Lazily initialized. */
    public static final QuatLeftIdeal[] CONNECTING_IDEALS;

    /**
     * Length-6 view of the alternate connecting ideals — mirrors the C
     * {@code #define ALTERNATE_CONNECTING_IDEALS (CONNECTING_IDEALS+1)}
     * (so {@code ALTERNATE_CONNECTING_IDEALS[i] = CONNECTING_IDEALS[i+1]}).
     * Used by {@code find_uv} when iterating over alternate orders.
     */
    public static final QuatLeftIdeal[] ALTERNATE_CONNECTING_IDEALS;

    static
    {
        CONNECTING_IDEALS = new QuatLeftIdeal[COUNT];
        for (int i = 0; i < COUNT; i++)
        {
            CONNECTING_IDEALS[i] = new QuatLeftIdeal();
        }
        populateAll();

        // Alias: skip the trivial CONNECTING_IDEALS[0] (= O₀ itself).
        ALTERNATE_CONNECTING_IDEALS = new QuatLeftIdeal[COUNT - 1];
        System.arraycopy(CONNECTING_IDEALS, 1, ALTERNATE_CONNECTING_IDEALS, 0, COUNT - 1);
    }

    /**
     * Fill {@code ideal} from {@code denom}, sixteen basis entries (row-major
     * 4×4), and {@code norm}. Mirrors the C struct initializer order:
     * {@code lattice.denom}, then {@code lattice.basis[row][col]}, then
     * {@code norm}.
     */
    private static void populate(QuatLeftIdeal ideal,
                                 Ibz denom,
                                 Ibz r0c0, Ibz r0c1, Ibz r0c2, Ibz r0c3,
                                 Ibz r1c0, Ibz r1c1, Ibz r1c2, Ibz r1c3,
                                 Ibz r2c0, Ibz r2c1, Ibz r2c2, Ibz r2c3,
                                 Ibz r3c0, Ibz r3c1, Ibz r3c2, Ibz r3c3,
                                 Ibz norm)
    {
        Ibz.copy(ideal.lattice.denom, denom);
        Ibz.copy(ideal.lattice.basis[0][0], r0c0);
        Ibz.copy(ideal.lattice.basis[0][1], r0c1);
        Ibz.copy(ideal.lattice.basis[0][2], r0c2);
        Ibz.copy(ideal.lattice.basis[0][3], r0c3);
        Ibz.copy(ideal.lattice.basis[1][0], r1c0);
        Ibz.copy(ideal.lattice.basis[1][1], r1c1);
        Ibz.copy(ideal.lattice.basis[1][2], r1c2);
        Ibz.copy(ideal.lattice.basis[1][3], r1c3);
        Ibz.copy(ideal.lattice.basis[2][0], r2c0);
        Ibz.copy(ideal.lattice.basis[2][1], r2c1);
        Ibz.copy(ideal.lattice.basis[2][2], r2c2);
        Ibz.copy(ideal.lattice.basis[2][3], r2c3);
        Ibz.copy(ideal.lattice.basis[3][0], r3c0);
        Ibz.copy(ideal.lattice.basis[3][1], r3c1);
        Ibz.copy(ideal.lattice.basis[3][2], r3c2);
        Ibz.copy(ideal.lattice.basis[3][3], r3c3);
        Ibz.copy(ideal.norm, norm);
    }

    private static void populateAll()
    {
        // CONNECTING_IDEALS[0]: the trivial connecting ideal (= O₀).
        populate(CONNECTING_IDEALS[0],
            /* denom */ Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
            /* r0 */ Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
                     Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            /* r1 */ Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
                     Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
                     Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            /* r2 */ Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
                     Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            /* r3 */ Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
                     Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            /* norm */ Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }));

        // CONNECTING_IDEALS[1].
        populate(CONNECTING_IDEALS[1],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000002L, 0x6000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000001L, 0x1000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000002L, 0x6000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000001L, 0x5000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000001L, 0x3000000000000000L }));

        // CONNECTING_IDEALS[2].
        populate(CONNECTING_IDEALS[2],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x7f90157b8673f5feL, 0x78f4a646d00bd2c5L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xe65cd6d8002bfee5L, 0x05b1373de72d68a3L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x7f90157b8673f5feL, 0x78f4a646d00bd2c5L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x99333ea38647f719L, 0x73436f08e8de6a21L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xbfc80abdc339faffL, 0x3c7a53236805e962L }));

        // CONNECTING_IDEALS[3].
        populate(CONNECTING_IDEALS[3],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x3c6fa8e67715e5e2L, 0x17949bec872b9078L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xbb290a5a3af78597L, 0x084ff561d2d977c0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x3c6fa8e67715e5e2L, 0x17949bec872b9078L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x81469e8c3c1e604bL, 0x0f44a68ab45218b7L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x1e37d4733b8af2f1L, 0x0bca4df64395c83cL }));

        // CONNECTING_IDEALS[4].
        populate(CONNECTING_IDEALS[4],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xde33c5116deeafa2L, 0x2df94f97c89ec8ceL }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xd5f5cdcaa90b519bL, 0x0e59b35483dd757aL }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xde33c5116deeafa2L, 0x2df94f97c89ec8ceL }),
            Ibz.fromMpLimbs(2, new long[]{ 0x083df746c4e35e07L, 0x1f9f9c4344c15354L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x6f19e288b6f757d1L, 0x16fca7cbe44f6467L }));

        // CONNECTING_IDEALS[5].
        populate(CONNECTING_IDEALS[5],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x52a2ee77559419f2L, 0xb348218745c9f459L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x1df48a96967adbd3L, 0x0222419a0d707845L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x52a2ee77559419f2L, 0xb348218745c9f459L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x34ae63e0bf193e1fL, 0xb125dfed38597c14L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xa951773baaca0cf9L, 0x59a410c3a2e4fa2cL }));

        // CONNECTING_IDEALS[6].
        populate(CONNECTING_IDEALS[6],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xd0316ad767cfaa3aL, 0x2996d852ebca0701L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xbc67edebd7ab0275L, 0x148ef2e5aeb5ad41L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xd0316ad767cfaa3aL, 0x2996d852ebca0701L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x13c97ceb9024a7c5L, 0x1507e56d3d1459c0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xe818b56bb3e7d51dL, 0x14cb6c2975e50380L }));
    }

    private ConnectingIdealsLvl1()
    {
    }
}
