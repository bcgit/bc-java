package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of {@code EXTREMAL_ORDERS[7]} from
 * {@code src/precomp/ref/lvl1/quaternion_data.c}.
 *
 * <p>Index 0 is the standard extremal maximal order (the one with order
 * O₀, z = i, t = j, q = 1). Indices 1..6 are alternate extremal orders for
 * the six alternate starting curves, with q = (5, 17, 37, 41, 53, 97).</p>
 *
 * <p>Limb constants for entries 1..6 are mechanically extracted from the
 * C reference via {@code core/src/tools/python/extract_sqisign_precomp.py}
 * — see that script's README for the workflow.</p>
 */
final class ExtremalOrdersLvl1
{
    public static final int NUM_EXTREMAL_ORDERS = 7;
    /**
     * {@code QUAT_prime_cofactor}: the odd cofactor of p+1. For lvl1,
     * p+1 = 5·2^248, so the cofactor is 5. From quaternion_data.c lvl1
     * (mp_size=4, mp_d={0x41, 0, 0, 0x800000000000000}).
     */
    public static final Ibz QUAT_PRIME_COFACTOR =
        Ibz.fromMpLimbs(4, new long[]{
            0x41L, 0L, 0L, 0x800000000000000L
        });

    /** The seven extremal maximal orders. Index 0 is the standard one (E₀-side). */
    public static final QuatExtremalMaximalOrder[] EXTREMAL_ORDERS;

    /** Alias for {@code EXTREMAL_ORDERS[0]} (the "standard" extremal order). */
    public static final QuatExtremalMaximalOrder STANDARD_EXTREMAL_ORDER;

    /** Alias for {@code EXTREMAL_ORDERS[0].order} (the maximal order O₀). */
    public static final QuatLattice MAXORD_O0;

    static
    {
        EXTREMAL_ORDERS = new QuatExtremalMaximalOrder[NUM_EXTREMAL_ORDERS];

        // Entry 0: the standard extremal maximal order. Canonical setter in
        // Normeq (z = i, t = j, q = 1, order = O₀).
        EXTREMAL_ORDERS[0] = new QuatExtremalMaximalOrder();
        Normeq.lattice00SetExtremal(EXTREMAL_ORDERS[0]);

        // Entries 1..6: alternate extremal orders.
        for (int i = 1; i < NUM_EXTREMAL_ORDERS; i++)
        {
            EXTREMAL_ORDERS[i] = new QuatExtremalMaximalOrder();
        }
        populateAlternates();

        STANDARD_EXTREMAL_ORDER = EXTREMAL_ORDERS[0];
        MAXORD_O0 = EXTREMAL_ORDERS[0].order;
    }

    /**
     * Fill an extremal-order entry from explicit constants. Mirrors the C
     * struct initializer order: {@code lattice.denom}, then
     * {@code lattice.basis[row][col]} row-major, then {@code z.denom},
     * {@code z.coord[0..3]}, {@code t.denom}, {@code t.coord[0..3]}, then
     * the scalar {@code q}.
     */
    private static void populateExtremal(QuatExtremalMaximalOrder order, int q,
                                         Ibz latDenom,
                                         Ibz b00, Ibz b01, Ibz b02, Ibz b03,
                                         Ibz b10, Ibz b11, Ibz b12, Ibz b13,
                                         Ibz b20, Ibz b21, Ibz b22, Ibz b23,
                                         Ibz b30, Ibz b31, Ibz b32, Ibz b33,
                                         Ibz zDenom, Ibz z0, Ibz z1, Ibz z2, Ibz z3,
                                         Ibz tDenom, Ibz t0, Ibz t1, Ibz t2, Ibz t3)
    {
        order.q = q;
        Ibz.copy(order.order.denom, latDenom);
        Ibz.copy(order.order.basis[0][0], b00);
        Ibz.copy(order.order.basis[0][1], b01);
        Ibz.copy(order.order.basis[0][2], b02);
        Ibz.copy(order.order.basis[0][3], b03);
        Ibz.copy(order.order.basis[1][0], b10);
        Ibz.copy(order.order.basis[1][1], b11);
        Ibz.copy(order.order.basis[1][2], b12);
        Ibz.copy(order.order.basis[1][3], b13);
        Ibz.copy(order.order.basis[2][0], b20);
        Ibz.copy(order.order.basis[2][1], b21);
        Ibz.copy(order.order.basis[2][2], b22);
        Ibz.copy(order.order.basis[2][3], b23);
        Ibz.copy(order.order.basis[3][0], b30);
        Ibz.copy(order.order.basis[3][1], b31);
        Ibz.copy(order.order.basis[3][2], b32);
        Ibz.copy(order.order.basis[3][3], b33);
        Ibz.copy(order.z.denom, zDenom);
        Ibz.copy(order.z.coord[0], z0);
        Ibz.copy(order.z.coord[1], z1);
        Ibz.copy(order.z.coord[2], z2);
        Ibz.copy(order.z.coord[3], z3);
        Ibz.copy(order.t.denom, tDenom);
        Ibz.copy(order.t.coord[0], t0);
        Ibz.copy(order.t.coord[1], t1);
        Ibz.copy(order.t.coord[2], t2);
        Ibz.copy(order.t.coord[3], t3);
    }

    /** Reference-equality wrapper to suppress an unused-import diagnostic on QuatAlg. */
    @SuppressWarnings("unused")
    private static final Class<QuatAlg> UNUSED_ALG_REF = QuatAlg.class;

    private static void populateAlternates()
    {
        // EXTREMAL_ORDERS[1] (q = 5)
        populateExtremal(EXTREMAL_ORDERS[1], 5,
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000000L, 0x1000000000000000L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000000L, 0x1000000000000000L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000000L, 0x0800000000000000L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-1, new long[]{ 0x1L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-4, new long[]{ 0L, 0L, 0L, 0x0080000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000000L, 0x0800000000000000L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-1, new long[]{ 0x1L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x0000000000000000L, 0x1000000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-1, new long[]{ 0x1L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-1, new long[]{ 0x1L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x1L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(1, new long[]{ 0x1L }), Ibz.fromMpLimbs(0, new long[]{ 0L }));

        // EXTREMAL_ORDERS[2] (q = 17)
        populateExtremal(EXTREMAL_ORDERS[2], 17,
            Ibz.fromMpLimbs(2, new long[]{ 0xf5f27a647b8578d4L, 0xb8746101369629b9L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xf5f27a647b8578d4L, 0xb8746101369629b9L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0xfaf93d323dc2bc6aL, 0x5c3a30809b4b14dcL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(3, new long[]{ 0x95ad2ad56fa47d47L, 0xc89877e749be8a4bL, 0x0000000000000001L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(4, new long[]{ 0x3e355e2970603f47L, 0x78dd10ae2a1bd950L, 0L, 0x0280000000000000L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0xfaf93d323dc2bc6aL, 0x5c3a30809b4b14dcL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x11L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-2, new long[]{ 0xb19426e828ee3fe7L, 0x0d6de568af586d7aL }),
            Ibz.fromMpLimbs(2, new long[]{ 0xf5f27a647b8578d4L, 0xb8746101369629b9L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(3, new long[]{ 0x95ad2ad56fa47d47L, 0xc89877e749be8a4bL, 0x0000000000000001L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x11L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x1L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(1, new long[]{ 0x1L }), Ibz.fromMpLimbs(0, new long[]{ 0L }));

        // EXTREMAL_ORDERS[3] (q = 37)
        populateExtremal(EXTREMAL_ORDERS[3], 37,
            Ibz.fromMpLimbs(2, new long[]{ 0x3c6fa8e67715e5e2L, 0x17949bec872b9078L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x3c6fa8e67715e5e2L, 0x17949bec872b9078L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x1e37d4733b8af2f1L, 0x0bca4df64395c83cL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-2, new long[]{ 0xb034808274c8307aL, 0x09ab399ac43a4e8aL }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(4, new long[]{
                    0x3d25ca466bc9954fL, 0x04f5822946ed431bL,
                    0xeb3e45306eb3e453L, 0x0045306eb3e45306L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x1e37d4733b8af2f1L, 0x0bca4df64395c83cL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x4L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0xbd312454ca3a0e7fL, 0x002172f0cb4ce562L }),
            Ibz.fromMpLimbs(2, new long[]{ 0x3c6fa8e67715e5e2L, 0x17949bec872b9078L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-2, new long[]{ 0xb034808274c8307aL, 0x09ab399ac43a4e8aL }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x4L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x1L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(1, new long[]{ 0x1L }), Ibz.fromMpLimbs(0, new long[]{ 0L }));

        // EXTREMAL_ORDERS[4] (q = 41)
        populateExtremal(EXTREMAL_ORDERS[4], 41,
            Ibz.fromMpLimbs(2, new long[]{ 0xde33c5116deeafa2L, 0x2df94f97c89ec8ceL }),
            Ibz.fromMpLimbs(2, new long[]{ 0xde33c5116deeafa2L, 0x2df94f97c89ec8ceL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x6f19e288b6f757d1L, 0x16fca7cbe44f6467L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0xd17aa943da6bdd36L, 0x44d44b0c564ce307L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-4, new long[]{
                    0xa0a2047cc4063a03L, 0x6cee07961df46dbcL,
                    0xc7ce0c7ce0c7ce0cL, 0x007ce0c7ce0c7ce0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x6f19e288b6f757d1L, 0x16fca7cbe44f6467L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-1, new long[]{ 0x8L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-2, new long[]{ 0xd9f82148a1e2188fL, 0x00d6e1b21a072e79L }),
            Ibz.fromMpLimbs(2, new long[]{ 0xde33c5116deeafa2L, 0x2df94f97c89ec8ceL }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0xd17aa943da6bdd36L, 0x44d44b0c564ce307L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(-1, new long[]{ 0x8L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x1L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(1, new long[]{ 0x1L }), Ibz.fromMpLimbs(0, new long[]{ 0L }));

        // EXTREMAL_ORDERS[5] (q = 53)
        populateExtremal(EXTREMAL_ORDERS[5], 53,
            Ibz.fromMpLimbs(3, new long[]{ 0x380014f2025b96a4L, 0x7bbeab7f79584e7cL, 0x0000000000000001L }),
            Ibz.fromMpLimbs(3, new long[]{ 0x380014f2025b96a4L, 0x7bbeab7f79584e7cL, 0x0000000000000001L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x1c000a79012dcb52L, 0xbddf55bfbcac273eL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-3, new long[]{ 0x4ba119e7333973e3L, 0xdbd0ee6227026ebcL, 0x0000000000000007L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(4, new long[]{
                    0x09f01d923dd0ca33L, 0x83f7e395afe92f81L,
                    0xfffffffffffffffcL, 0x027fffffffffffffL }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x1c000a79012dcb52L, 0xbddf55bfbcac273eL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x35L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x87f571c0f93ceb73L, 0x12fab9cbcb3c667aL }),
            Ibz.fromMpLimbs(3, new long[]{ 0x380014f2025b96a4L, 0x7bbeab7f79584e7cL, 0x0000000000000001L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-3, new long[]{ 0x4ba119e7333973e3L, 0xdbd0ee6227026ebcL, 0x0000000000000007L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x35L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x1L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(1, new long[]{ 0x1L }), Ibz.fromMpLimbs(0, new long[]{ 0L }));

        // EXTREMAL_ORDERS[6] (q = 97)
        populateExtremal(EXTREMAL_ORDERS[6], 97,
            Ibz.fromMpLimbs(3, new long[]{ 0xe2b97b9e55af7ffaL, 0xc227f76b578ca7afL, 0x000000000000000fL }),
            Ibz.fromMpLimbs(3, new long[]{ 0xe2b97b9e55af7ffaL, 0xc227f76b578ca7afL, 0x000000000000000fL }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(3, new long[]{ 0xf15cbdcf2ad7bffdL, 0xe113fbb5abc653d7L, 0x0000000000000007L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-3, new long[]{ 0xa2ef1ce7f02b0d16L, 0x066759632c56054bL, 0x000000000000006fL }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(4, new long[]{
                    0x84ac06ea9d3bf0abL, 0xd021882bdde962e5L,
                    0xffffffffffffffe2L, 0x13ffffffffffffffL }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(3, new long[]{ 0xf15cbdcf2ad7bffdL, 0xe113fbb5abc653d7L, 0x0000000000000007L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x308L }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(2, new long[]{ 0x077013f15c4a1f37L, 0x9281da3156007183L }),
            Ibz.fromMpLimbs(3, new long[]{ 0xe2b97b9e55af7ffaL, 0xc227f76b578ca7afL, 0x000000000000000fL }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(-3, new long[]{ 0xa2ef1ce7f02b0d16L, 0x066759632c56054bL, 0x000000000000006fL }),
                Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(1, new long[]{ 0x308L }),
            Ibz.fromMpLimbs(1, new long[]{ 0x1L }),
            Ibz.fromMpLimbs(0, new long[]{ 0L }), Ibz.fromMpLimbs(0, new long[]{ 0L }),
                Ibz.fromMpLimbs(1, new long[]{ 0x1L }), Ibz.fromMpLimbs(0, new long[]{ 0L }));
    }

    private ExtremalOrdersLvl1()
    {
    }
}
