package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of {@code EXTREMAL_ORDERS[7]} from
 * {@code src/precomp/ref/lvl3/quaternion_data.c}.
 *
 * <p>Lvl5 has 7 entries (matching lvl1): index 0 is the standard
 * extremal maximal order, indices 1..7 are alternates with
 * {@code q ∈ {5, 37, 61, 97, 113, 149}}.</p>
 *
 * <p>Limbs mechanically extracted from the C reference via
 * {@code core/src/tools/python/extract_sqisign_precomp.py}.</p>
 */
final class ExtremalOrdersLvl5
{
    public static final int NUM_EXTREMAL_ORDERS = 7;
    public static final QuatExtremalMaximalOrder[] EXTREMAL_ORDERS;
    public static final QuatExtremalMaximalOrder STANDARD_EXTREMAL_ORDER;
    public static final QuatLattice MAXORD_O0;

    static
    {
        EXTREMAL_ORDERS = new QuatExtremalMaximalOrder[NUM_EXTREMAL_ORDERS];
        for (int i = 0; i < NUM_EXTREMAL_ORDERS; i++)
        {
            EXTREMAL_ORDERS[i] = new QuatExtremalMaximalOrder();
        }
        populateAll();
        STANDARD_EXTREMAL_ORDER = EXTREMAL_ORDERS[0];
        MAXORD_O0 = EXTREMAL_ORDERS[0].order;
    }

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

    private static void populateAll()
    {


        // EXTREMAL_ORDERS[0] (q = 1)
        populateExtremal(EXTREMAL_ORDERS[0], 1,
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // lat.denom
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[1] (q = 5)
        populateExtremal(EXTREMAL_ORDERS[1], 5,
            Ibz.fromMpLimbs(4, new long[]{ 0xb9c2992410dcc584L, 0xe941bdfbfbc85a67L, 0xc570cd5cdee20c61L, 0x49272e51b3ffa2d4L }),  // lat.denom
            Ibz.fromMpLimbs(4, new long[]{ 0xb9c2992410dcc584L, 0xe941bdfbfbc85a67L, 0xc570cd5cdee20c61L, 0x49272e51b3ffa2d4L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xdce14c92086e62c2L, 0xf4a0defdfde42d33L, 0x62b866ae6f710630L, 0x24939728d9ffd16aL }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(-4, new long[]{ 0x353f4632d6340c93L, 0x31875084220d76baL, 0xa3e468600fc8b121L, 0x7e5205e073881368L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(8, new long[]{ 0xbcd36af0bfbd2f6dL, 0xd78a9b0b8f625c61L, 0x0208471661aa3142L, 0xda1a97d643bd93c7L, 0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL, 0x00d7ffffffffffffL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xdce14c92086e62c2L, 0xf4a0defdfde42d33L, 0x62b866ae6f710630L, 0x24939728d9ffd16aL }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000005L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(4, new long[]{ 0x6bb98705156b9addL, 0xb82721a6d0348bdfL, 0xa9fd3da334c744e9L, 0x0ca1cd633ec0cebdL }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0xb9c2992410dcc584L, 0xe941bdfbfbc85a67L, 0xc570cd5cdee20c61L, 0x49272e51b3ffa2d4L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(-4, new long[]{ 0x353f4632d6340c93L, 0x31875084220d76baL, 0xa3e468600fc8b121L, 0x7e5205e073881368L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000005L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[2] (q = 37)
        populateExtremal(EXTREMAL_ORDERS[2], 37,
            Ibz.fromMpLimbs(5, new long[]{ 0x4089bfd70d34169aL, 0x6efdfefbc17d1be8L, 0xd204fedb58ea76e0L, 0xdf2847d63b9a01e3L, 0x0000000000000002L }),  // lat.denom
            Ibz.fromMpLimbs(5, new long[]{ 0x4089bfd70d34169aL, 0x6efdfefbc17d1be8L, 0xd204fedb58ea76e0L, 0xdf2847d63b9a01e3L, 0x0000000000000002L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(5, new long[]{ 0x2044dfeb869a0b4dL, 0x377eff7de0be8df4L, 0xe9027f6dac753b70L, 0x6f9423eb1dcd00f1L, 0x0000000000000001L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(-5, new long[]{ 0x2cde4dda6ec42412L, 0xc1d63a33aaa7281dL, 0x13fb816d22e35c26L, 0xadaad1a758e8ac81L, 0x000000000000000cL }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(8, new long[]{ 0x9cc7d52656301f45L, 0xbb2787b3114d1aabL, 0x813f8bb40e50c6b6L, 0x66eea8d3f810ff7aL, 0xfffffffffffffffcL, 0xffffffffffffffffL, 0xffffffffffffffffL, 0x035fffffffffffffL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(5, new long[]{ 0x2044dfeb869a0b4dL, 0x377eff7de0be8df4L, 0xe9027f6dac753b70L, 0x6f9423eb1dcd00f1L, 0x0000000000000001L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000094L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(4, new long[]{ 0xa3336fc138d9233fL, 0xa1c12a4cce6a0aebL, 0xb0b3d4c6a9fc274cL, 0x2bdc411a7a48555bL }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(5, new long[]{ 0x4089bfd70d34169aL, 0x6efdfefbc17d1be8L, 0xd204fedb58ea76e0L, 0xdf2847d63b9a01e3L, 0x0000000000000002L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(-5, new long[]{ 0x2cde4dda6ec42412L, 0xc1d63a33aaa7281dL, 0x13fb816d22e35c26L, 0xadaad1a758e8ac81L, 0x000000000000000cL }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000094L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[3] (q = 61)
        populateExtremal(EXTREMAL_ORDERS[3], 61,
            Ibz.fromMpLimbs(5, new long[]{ 0x25c2e2a5416ec31eL, 0xf395578b45faa926L, 0xd089d14d79016ac9L, 0x583b0bc4e0629e5cL, 0x0000000000000003L }),  // lat.denom
            Ibz.fromMpLimbs(5, new long[]{ 0x25c2e2a5416ec31eL, 0xf395578b45faa926L, 0xd089d14d79016ac9L, 0x583b0bc4e0629e5cL, 0x0000000000000003L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(5, new long[]{ 0x12e17152a0b7618fL, 0xf9caabc5a2fd5493L, 0x6844e8a6bc80b564L, 0xac1d85e270314f2eL, 0x0000000000000001L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(5, new long[]{ 0xf8ca5829146704c2L, 0x434aa4a1b6612d31L, 0x8565e232bffa25cbL, 0x07103f640e422305L, 0x0000000000000011L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(-8, new long[]{ 0x06f96454e5413b03L, 0x2b5275090b933808L, 0x48698961f4fe0ed1L, 0x70b04c4cdd214671L, 0xfffffffffffffff9L, 0xffffffffffffffffL, 0xffffffffffffffffL, 0x035fffffffffffffL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(5, new long[]{ 0x12e17152a0b7618fL, 0xf9caabc5a2fd5493L, 0x6844e8a6bc80b564L, 0xac1d85e270314f2eL, 0x0000000000000001L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(-1, new long[]{ 0x00000000000000f4L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(-4, new long[]{ 0xc9622ee2f5ace953L, 0x7c5ad761d9a0459dL, 0xb7a69b08cf368268L, 0x23bae3247e04bd23L }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(5, new long[]{ 0x25c2e2a5416ec31eL, 0xf395578b45faa926L, 0xd089d14d79016ac9L, 0x583b0bc4e0629e5cL, 0x0000000000000003L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(5, new long[]{ 0xf8ca5829146704c2L, 0x434aa4a1b6612d31L, 0x8565e232bffa25cbL, 0x07103f640e422305L, 0x0000000000000011L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(-1, new long[]{ 0x00000000000000f4L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[4] (q = 97)
        populateExtremal(EXTREMAL_ORDERS[4], 97,
            Ibz.fromMpLimbs(5, new long[]{ 0xb7aa895528f00f94L, 0xd3b45a1565b6538fL, 0x11f83554cba49667L, 0x083d196a626525a9L, 0x0000000000000001L }),  // lat.denom
            Ibz.fromMpLimbs(5, new long[]{ 0xb7aa895528f00f94L, 0xd3b45a1565b6538fL, 0x11f83554cba49667L, 0x083d196a626525a9L, 0x0000000000000001L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xdbd544aa947807caL, 0xe9da2d0ab2db29c7L, 0x88fc1aaa65d24b33L, 0x841e8cb5313292d4L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(-5, new long[]{ 0xcbe77339ed375409L, 0xcc9d18fa258295abL, 0xb168aefd254313aeL, 0x6d9dc9af068bfdbcL, 0x0000000000000006L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(-8, new long[]{ 0x3f3d42b7423f7013L, 0xfede52bf9883082aL, 0x0b8af571a4498018L, 0x9e1f439d0be73139L, 0x0000000000000002L, 0x0000000000000000L, 0x0000000000000000L, 0x00d8000000000000L }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xdbd544aa947807caL, 0xe9da2d0ab2db29c7L, 0x88fc1aaa65d24b33L, 0x841e8cb5313292d4L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000061L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(4, new long[]{ 0x177bea2934afca2dL, 0xe94d588a86ca91edL, 0x67d7a1e4462155dfL, 0x087b88f506a1b617L }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(5, new long[]{ 0xb7aa895528f00f94L, 0xd3b45a1565b6538fL, 0x11f83554cba49667L, 0x083d196a626525a9L, 0x0000000000000001L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(-5, new long[]{ 0xcbe77339ed375409L, 0xcc9d18fa258295abL, 0xb168aefd254313aeL, 0x6d9dc9af068bfdbcL, 0x0000000000000006L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000061L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[5] (q = 113)
        populateExtremal(EXTREMAL_ORDERS[5], 113,
            Ibz.fromMpLimbs(4, new long[]{ 0xa203cfa6df451e34L, 0x7a301d42d8c5e18aL, 0x741df9337a1286ceL, 0x1854bf65e48e6b48L }),  // lat.denom
            Ibz.fromMpLimbs(4, new long[]{ 0xa203cfa6df451e34L, 0x7a301d42d8c5e18aL, 0x741df9337a1286ceL, 0x1854bf65e48e6b48L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x5101e7d36fa28f1aL, 0x3d180ea16c62f0c5L, 0x3a0efc99bd094367L, 0x0c2a5fb2f24735a4L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x093d8523a322cf03L, 0x56b533ca4b5003bcL, 0x98c638bf87c8863fL, 0x78edfc02fab78ce8L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(8, new long[]{ 0x131074a1140024edL, 0x3500512a1c0dce8aL, 0x3cdb892c69922451L, 0xf11f0420052045d8L, 0xcbe4d06cbe4d06cbL, 0x06cbe4d06cbe4d06L, 0x4d06cbe4d06cbe4dL, 0x001506cbe4d06cbeL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x5101e7d36fa28f1aL, 0x3d180ea16c62f0c5L, 0x3a0efc99bd094367L, 0x0c2a5fb2f24735a4L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x000000000000000bL }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(-4, new long[]{ 0x5199314c0d2e98b3L, 0x1ef7bd65b5927a5aL, 0x68e36cfe94fd7d32L, 0x0088fb738d91cda6L }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0xa203cfa6df451e34L, 0x7a301d42d8c5e18aL, 0x741df9337a1286ceL, 0x1854bf65e48e6b48L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(4, new long[]{ 0x093d8523a322cf03L, 0x56b533ca4b5003bcL, 0x98c638bf87c8863fL, 0x78edfc02fab78ce8L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(1, new long[]{ 0x000000000000000bL }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[6] (q = 149)
        populateExtremal(EXTREMAL_ORDERS[6], 149,
            Ibz.fromMpLimbs(5, new long[]{ 0x2e513c7fdc0d779cL, 0xd38cb29efb7d85b9L, 0x79a3a4fa9ea564bbL, 0xa977ca21f359df70L, 0x0000000000000006L }),  // lat.denom
            Ibz.fromMpLimbs(5, new long[]{ 0x2e513c7fdc0d779cL, 0xd38cb29efb7d85b9L, 0x79a3a4fa9ea564bbL, 0xa977ca21f359df70L, 0x0000000000000006L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(5, new long[]{ 0x97289e3fee06bbceL, 0xe9c6594f7dbec2dcL, 0x3cd1d27d4f52b25dL, 0x54bbe510f9acefb8L, 0x0000000000000003L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(-5, new long[]{ 0x727a1944aa9d8db1L, 0x564339b4ffc0c6c3L, 0x5371c0a9b5342de0L, 0x5a83a6c480df8e58L, 0x0000000000000036L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(-8, new long[]{ 0x67c5f8155de89c90L, 0x180b7c9e00c90989L, 0xea883386df5a526dL, 0x3bad550724c5580aL, 0x0000000000000010L, 0x0000000000000000L, 0x0000000000000000L, 0x0438000000000000L }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(5, new long[]{ 0x97289e3fee06bbceL, 0xe9c6594f7dbec2dcL, 0x3cd1d27d4f52b25dL, 0x54bbe510f9acefb8L, 0x0000000000000003L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(-1, new long[]{ 0x00000000000002e9L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(4, new long[]{ 0x126ca6be1530a1f8L, 0x8495b3bcbdd9fd3bL, 0xf440cfae19855457L, 0x2eb1688184ba4ea6L }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(5, new long[]{ 0x2e513c7fdc0d779cL, 0xd38cb29efb7d85b9L, 0x79a3a4fa9ea564bbL, 0xa977ca21f359df70L, 0x0000000000000006L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(-5, new long[]{ 0x727a1944aa9d8db1L, 0x564339b4ffc0c6c3L, 0x5371c0a9b5342de0L, 0x5a83a6c480df8e58L, 0x0000000000000036L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(-1, new long[]{ 0x00000000000002e9L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]
    }

    /**
     * Odd cofactor used by quat_represent_integer for lvl5. From
     * {@code src/precomp/ref/lvl5/quaternion_data.c} (GMP_LIMB_BITS == 64
     * branch): mp_size = 8, limbs {0x33, 0, 0, 0, 0, 0, 0, 0x200000000000000}.
     */
    public static final Ibz QUAT_PRIME_COFACTOR =
        Ibz.fromMpLimbs(8, new long[]{
            0x0000000000000033L, 0L, 0L, 0L, 0L, 0L, 0L, 0x0200000000000000L
        });

    private ExtremalOrdersLvl5()
    {
    }
}
