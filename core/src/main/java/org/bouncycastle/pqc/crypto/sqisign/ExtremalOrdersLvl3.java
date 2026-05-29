package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of {@code EXTREMAL_ORDERS[8]} from
 * {@code src/precomp/ref/lvl3/quaternion_data.c}.
 *
 * <p>Lvl3 has 8 entries (one more than lvl1's 7): index 0 is the standard
 * extremal maximal order, indices 1..7 are alternates with
 * {@code q ∈ {5, 13, 17, 41, 73, 89, 97}}.</p>
 *
 * <p>Limbs mechanically extracted from the C reference via
 * {@code core/src/tools/python/extract_sqisign_precomp.py}.</p>
 */
final class ExtremalOrdersLvl3
{
    public static final int NUM_EXTREMAL_ORDERS = 8;
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
            Ibz.fromMpLimbs(3, new long[]{ 0x3e5958f3e7edafccL, 0x4a6df2c588d69763L, 0x3c317d27f44b3afeL }),  // lat.denom
            Ibz.fromMpLimbs(3, new long[]{ 0x3e5958f3e7edafccL, 0x4a6df2c588d69763L, 0x3c317d27f44b3afeL }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(3, new long[]{ 0x9f2cac79f3f6d7e6L, 0x2536f962c46b4bb1L, 0x1e18be93fa259d7fL }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(3, new long[]{ 0x2a21a3eaea912fb7L, 0xa2d3de7326b39cd1L, 0x266bc96320a1ceccL }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(6, new long[]{ 0x843690644aa81e5fL, 0xdd152fd850ab8faeL, 0x03d794238343617aL, 0x0000000000000000L, 0x0000000000000000L, 0x0680000000000000L }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(3, new long[]{ 0x9f2cac79f3f6d7e6L, 0x2536f962c46b4bb1L, 0x1e18be93fa259d7fL }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(-3, new long[]{ 0x843690644aa81e5fL, 0xdd152fd850ab8faeL, 0x03d794238343617aL }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0x3e5958f3e7edafccL, 0x4a6df2c588d69763L, 0x3c317d27f44b3afeL }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(3, new long[]{ 0x2a21a3eaea912fb7L, 0xa2d3de7326b39cd1L, 0x266bc96320a1ceccL }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[2] (q = 13)
        populateExtremal(EXTREMAL_ORDERS[2], 13,
            Ibz.fromMpLimbs(3, new long[]{ 0x8dca5bc7b21f0c40L, 0xbdddc8b1ca0ac2a2L, 0x3cc00a9dc9d5cb7dL }),  // lat.denom
            Ibz.fromMpLimbs(3, new long[]{ 0x8dca5bc7b21f0c40L, 0xbdddc8b1ca0ac2a2L, 0x3cc00a9dc9d5cb7dL }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(3, new long[]{ 0x46e52de3d90f8620L, 0xdeeee458e5056151L, 0x1e60054ee4eae5beL }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(3, new long[]{ 0xbd0b4e1e9f6f6801L, 0x3849b4c6aa125c5eL, 0xb10632272d76d6c7L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(6, new long[]{ 0xa4cf343c41358400L, 0x5ac7c207a4146603L, 0x06cf01edd084921bL, 0x0000000000000000L, 0x0000000000000000L, 0x0280000000000000L }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(3, new long[]{ 0x46e52de3d90f8620L, 0xdeeee458e5056151L, 0x1e60054ee4eae5beL }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(-3, new long[]{ 0xa4cf343c41358400L, 0x5ac7c207a4146603L, 0x06cf01edd084921bL }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0x8dca5bc7b21f0c40L, 0xbdddc8b1ca0ac2a2L, 0x3cc00a9dc9d5cb7dL }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(3, new long[]{ 0xbd0b4e1e9f6f6801L, 0x3849b4c6aa125c5eL, 0xb10632272d76d6c7L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[3] (q = 17)
        populateExtremal(EXTREMAL_ORDERS[3], 17,
            Ibz.fromMpLimbs(4, new long[]{ 0x5357db3873285b40L, 0x85cf01f331d8465bL, 0x3dab6f6dd8dc32b9L, 0x0000000000000002L }),  // lat.denom
            Ibz.fromMpLimbs(4, new long[]{ 0x5357db3873285b40L, 0x85cf01f331d8465bL, 0x3dab6f6dd8dc32b9L, 0x0000000000000002L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xa9abed9c39942da0L, 0xc2e780f998ec232dL, 0x1ed5b7b6ec6e195cL, 0x0000000000000001L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(-4, new long[]{ 0xe28458cc4ddcb7efL, 0xc383dca9b9edc4a7L, 0x7663d2bc5a13c3ddL, 0x0000000000000003L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(6, new long[]{ 0x9489605a925adc07L, 0x65fa880f7944475bL, 0x78f213f8329ced5aL, 0xfffffffffffffffeL, 0xffffffffffffffffL, 0x207fffffffffffffL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xa9abed9c39942da0L, 0xc2e780f998ec232dL, 0x1ed5b7b6ec6e195cL, 0x0000000000000001L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000011L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(3, new long[]{ 0xc2e5c6605ca49c07L, 0xa3de3b322b1d94d7L, 0x1a11feab2fd367a4L }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0x5357db3873285b40L, 0x85cf01f331d8465bL, 0x3dab6f6dd8dc32b9L, 0x0000000000000002L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(-4, new long[]{ 0xe28458cc4ddcb7efL, 0xc383dca9b9edc4a7L, 0x7663d2bc5a13c3ddL, 0x0000000000000003L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000011L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[4] (q = 41)
        populateExtremal(EXTREMAL_ORDERS[4], 41,
            Ibz.fromMpLimbs(3, new long[]{ 0x7c1cd4b8abc3dfdaL, 0x79cc21da66b24727L, 0xa12d9b8d553de3a3L }),  // lat.denom
            Ibz.fromMpLimbs(3, new long[]{ 0x7c1cd4b8abc3dfdaL, 0x79cc21da66b24727L, 0xa12d9b8d553de3a3L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xbe0e6a5c55e1efedL, 0xbce610ed33592393L, 0x5096cdc6aa9ef1d1L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(-3, new long[]{ 0x2e5272f1ea6fe8e2L, 0xfd0e5fe4c137152aL, 0x0c6bfa3d07a19736L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(6, new long[]{ 0x0a4216ae48a09a15L, 0x2f5e26a7534a3772L, 0x745ca36539ebce7cL, 0x576a2576a2576a25L, 0x2576a2576a2576a2L, 0x06576a2576a2576aL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xbe0e6a5c55e1efedL, 0xbce610ed33592393L, 0x5096cdc6aa9ef1d1L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000008L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(3, new long[]{ 0x2c45b03b253350e5L, 0x8c73afffaaf10fdeL, 0x0026c7bc0fb3ebfdL }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0x7c1cd4b8abc3dfdaL, 0x79cc21da66b24727L, 0xa12d9b8d553de3a3L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(-3, new long[]{ 0x2e5272f1ea6fe8e2L, 0xfd0e5fe4c137152aL, 0x0c6bfa3d07a19736L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000008L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[5] (q = 73)
        populateExtremal(EXTREMAL_ORDERS[5], 73,
            Ibz.fromMpLimbs(3, new long[]{ 0x950c56e76067b000L, 0xb9901bfb28e60b3dL, 0x29aa227371840eb8L }),  // lat.denom
            Ibz.fromMpLimbs(3, new long[]{ 0x950c56e76067b000L, 0xb9901bfb28e60b3dL, 0x29aa227371840eb8L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xca862b73b033d800L, 0x5cc80dfd9473059eL, 0x14d51139b8c2075cL }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0xdec96120ef7fffffL, 0x2d72e8d7fcb43d80L, 0x4bc9cd2aeecc4077L, 0x0000000000000001L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(-6, new long[]{ 0xedfb9519122773baL, 0xf0b21a200e80605bL, 0xefd6b325a90cb418L, 0x8fc7e3f1f8fc7e3eL, 0xc7e3f1f8fc7e3f1fL, 0x0071f8fc7e3f1f8fL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xca862b73b033d800L, 0x5cc80dfd9473059eL, 0x14d51139b8c2075cL }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000001L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(-3, new long[]{ 0x130f681e08a773baL, 0xf78b4ebed966eee3L, 0x0245c4090fa9ba4dL }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0x950c56e76067b000L, 0xb9901bfb28e60b3dL, 0x29aa227371840eb8L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(4, new long[]{ 0xdec96120ef7fffffL, 0x2d72e8d7fcb43d80L, 0x4bc9cd2aeecc4077L, 0x0000000000000001L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000001L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[6] (q = 89)
        populateExtremal(EXTREMAL_ORDERS[6], 89,
            Ibz.fromMpLimbs(3, new long[]{ 0x97d3c8dc37a07b26L, 0x1df20931d6bd7f2fL, 0x6ee725914a3e2918L }),  // lat.denom
            Ibz.fromMpLimbs(3, new long[]{ 0x97d3c8dc37a07b26L, 0x1df20931d6bd7f2fL, 0x6ee725914a3e2918L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xcbe9e46e1bd03d93L, 0x0ef90498eb5ebf97L, 0x377392c8a51f148cL }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(3, new long[]{ 0x6a692b8a9faa4faeL, 0x301c7892633a436cL, 0xac500e41cb54ec62L }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(-6, new long[]{ 0x617e87b7eb6630b3L, 0x90c8dcf40fa7027cL, 0xb7baaf369e3c7e8bL, 0x75eebdd7baf75eebL, 0xd7baf75eebdd7bafL, 0x02ebdd7baf75eebdL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xcbe9e46e1bd03d93L, 0x0ef90498eb5ebf97L, 0x377392c8a51f148cL }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000008L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(-3, new long[]{ 0x51231b920986b5abL, 0xc0fd4896653b4b2aL, 0x00f7d20ec06c579eL }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0x97d3c8dc37a07b26L, 0x1df20931d6bd7f2fL, 0x6ee725914a3e2918L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(3, new long[]{ 0x6a692b8a9faa4faeL, 0x301c7892633a436cL, 0xac500e41cb54ec62L }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000008L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]

        // EXTREMAL_ORDERS[7] (q = 97)
        populateExtremal(EXTREMAL_ORDERS[7], 97,
            Ibz.fromMpLimbs(4, new long[]{ 0xf8744b4c6df0a194L, 0x84f211bb362ab43eL, 0xe5017d4261a2c623L, 0x0000000000000030L }),  // lat.denom
            Ibz.fromMpLimbs(4, new long[]{ 0xf8744b4c6df0a194L, 0x84f211bb362ab43eL, 0xe5017d4261a2c623L, 0x0000000000000030L }),  // lat.basis[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x7c3a25a636f850caL, 0xc27908dd9b155a1fL, 0x7280bea130d16311L, 0x0000000000000018L }),  // lat.basis[0][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x2154245e63ae83f7L, 0x1b2d8f96544b883cL, 0x118e7bdd8d73cc0cL, 0x00000000000001dfL }),  // lat.basis[1][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[1][2]
            Ibz.fromMpLimbs(-6, new long[]{ 0xce46bd84489cbd79L, 0x3c5a642ab1949344L, 0x4dcb6e1f96f5db04L, 0xffffffffffffff6eL, 0xffffffffffffffffL, 0x207fffffffffffffL }),  // lat.basis[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x7c3a25a636f850caL, 0xc27908dd9b155a1fL, 0x7280bea130d16311L, 0x0000000000000018L }),  // lat.basis[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][0]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000061L }),  // lat.basis[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // lat.basis[3][2]
            Ibz.fromMpLimbs(-4, new long[]{ 0x71a805773fdaa1c9L, 0x2a5decf24269f4d3L, 0x782c47e56e4141b6L, 0x0000000000000002L }),  // lat.basis[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0xf8744b4c6df0a194L, 0x84f211bb362ab43eL, 0xe5017d4261a2c623L, 0x0000000000000030L }),  // z.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[0]
            Ibz.fromMpLimbs(4, new long[]{ 0x2154245e63ae83f7L, 0x1b2d8f96544b883cL, 0x118e7bdd8d73cc0cL, 0x00000000000001dfL }),  // z.coord[1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // z.coord[2]
            Ibz.fromMpLimbs(-1, new long[]{ 0x0000000000000061L }),  // z.coord[3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.denom
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // t.coord[1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // t.coord[2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }));  // t.coord[3]
    }

    /**
     * Odd cofactor used by quat_represent_integer for lvl3. From
     * {@code src/precomp/ref/lvl3/quaternion_data.c} (GMP_LIMB_BITS == 64
     * branch): mp_size = 6, limbs {0x171, 0, 0, 0, 0, 0x8000000000000000}.
     */
    public static final Ibz QUAT_PRIME_COFACTOR =
        Ibz.fromMpLimbs(6, new long[]{
            0x0000000000000171L, 0L, 0L, 0L, 0L, 0x8000000000000000L
        });

    private ExtremalOrdersLvl3()
    {
    }
}
