package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of {@code CONNECTING_IDEALS[7]} from
 * {@code src/precomp/ref/lvl5/quaternion_data.c}.
 *
 * <p>Lvl5 has 7 entries (1 standard O₀ + 6 alternate extremal orders),
 * matching lvl1's count. Each is a {@link QuatLeftIdeal} with its
 * lattice (denom + 4×4 basis) and norm.</p>
 *
 * <p>Limbs mechanically extracted from the C reference via
 * {@code core/src/tools/python/extract_sqisign_precomp.py}.</p>
 */
final class ConnectingIdealsLvl5
{
    public static final int COUNT = 7;

    public static final QuatLeftIdeal[] CONNECTING_IDEALS;
    public static final QuatLeftIdeal[] ALTERNATE_CONNECTING_IDEALS;

    static
    {
        CONNECTING_IDEALS = new QuatLeftIdeal[COUNT];
        for (int i = 0; i < COUNT; i++)
        {
            CONNECTING_IDEALS[i] = new QuatLeftIdeal();
        }
        populateAll();

        ALTERNATE_CONNECTING_IDEALS = new QuatLeftIdeal[COUNT - 1];
        System.arraycopy(CONNECTING_IDEALS, 1, ALTERNATE_CONNECTING_IDEALS, 0, COUNT - 1);
    }

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

        // CONNECTING_IDEALS[0]
        populate(CONNECTING_IDEALS[0],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // b[1][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }));  // norm

        // CONNECTING_IDEALS[1]
        populate(CONNECTING_IDEALS[1],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0x9669cee3be8db4caL, 0x374bf6f986eb09cbL, 0xab5f3315d1f22e68L, 0x2541686ea9c92208L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(4, new long[]{ 0x4be5bc362777db03L, 0x41a783b4d47438ddL, 0xc6171f00a3615426L, 0x0aa22b1c8cb4e350L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x9669cee3be8db4caL, 0x374bf6f986eb09cbL, 0xab5f3315d1f22e68L, 0x2541686ea9c92208L }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x4a8412ad9715d9c7L, 0xf5a47344b276d0eeL, 0xe54814152e90da41L, 0x1a9f3d521d143eb7L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0xcb34e771df46da65L, 0x1ba5fb7cc37584e5L, 0x55af998ae8f91734L, 0x12a0b43754e49104L }));  // norm

        // CONNECTING_IDEALS[2]
        populate(CONNECTING_IDEALS[2],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0x7e48e9825a4d8412L, 0x2598297c6d03619eL, 0x51c8c89e24ff6affL, 0x13de7e7b696506f8L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(4, new long[]{ 0xf2e308bed8b26e7dL, 0xf4ae760915727c3eL, 0x9b0353ecb93e8366L, 0x070741b0ae186573L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x7e48e9825a4d8412L, 0x2598297c6d03619eL, 0x51c8c89e24ff6affL, 0x13de7e7b696506f8L }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x8b65e0c3819b1595L, 0x30e9b3735790e55fL, 0xb6c574b16bc0e798L, 0x0cd73ccabb4ca184L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0x3f2474c12d26c209L, 0x92cc14be3681b0cfL, 0x28e4644f127fb57fL, 0x09ef3f3db4b2837cL }));  // norm

        // CONNECTING_IDEALS[3]
        populate(CONNECTING_IDEALS[3],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0xf407643d7694b376L, 0x5c1fd3456e430f5cL, 0x24fe1005777decc4L, 0x0e095c85536a88e4L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(4, new long[]{ 0xb3a7da24a69c9427L, 0xcb05a39a22fc4f9aL, 0xad95b97d923dd93eL, 0x0051bdeb96bd3374L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0xf407643d7694b376L, 0x5c1fd3456e430f5cL, 0x24fe1005777decc4L, 0x0e095c85536a88e4L }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x405f8a18cff81f4fL, 0x911a2fab4b46bfc2L, 0x77685687e5401385L, 0x0db79e99bcad556fL }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0x7a03b21ebb4a59bbL, 0x2e0fe9a2b72187aeL, 0x127f0802bbbef662L, 0x0704ae42a9b54472L }));  // norm

        // CONNECTING_IDEALS[4]
        populate(CONNECTING_IDEALS[4],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0x5b4e1fb9cc347a2aL, 0x211dbb684f0f6acfL, 0xa5120782ae74a57bL, 0xa0355af5b576d75cL }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(4, new long[]{ 0xb40f32f312fba3e3L, 0xdda9befc537d4bbeL, 0xc020aaf3aca98954L, 0x021a88fdf48f17daL }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x5b4e1fb9cc347a2aL, 0x211dbb684f0f6acfL, 0xa5120782ae74a57bL, 0xa0355af5b576d75cL }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xa73eecc6b938d647L, 0x4373fc6bfb921f10L, 0xe4f15c8f01cb1c26L, 0x9e1ad1f7c0e7bf81L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0xada70fdce61a3d15L, 0x908eddb42787b567L, 0x528903c1573a52bdL, 0x501aad7adabb6baeL }));  // norm

        // CONNECTING_IDEALS[5]
        populate(CONNECTING_IDEALS[5],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0x365e0f1a1f2981d6L, 0x87f138b195c88f4aL, 0x1cb182399ccab9ffL, 0x25be5f3f8fde070fL }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(4, new long[]{ 0x48f9a49c7c4cbe61L, 0xd427f823b80a3fb4L, 0xda063a569ec7593eL, 0x0fb0c2cb2875551eL }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x365e0f1a1f2981d6L, 0x87f138b195c88f4aL, 0x1cb182399ccab9ffL, 0x25be5f3f8fde070fL }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xed646a7da2dcc375L, 0xb3c9408dddbe4f95L, 0x42ab47e2fe0360c0L, 0x160d9c746768b1f0L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0x1b2f078d0f94c0ebL, 0xc3f89c58cae447a5L, 0x8e58c11cce655cffL, 0x12df2f9fc7ef0387L }));  // norm

        // CONNECTING_IDEALS[6]
        populate(CONNECTING_IDEALS[6],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0x82808ced17295a86L, 0x24b35e391e0fd48fL, 0x4e2ed9f3a29474baL, 0x30790dd2ee6b8cc1L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(4, new long[]{ 0xdf50386757ee9203L, 0x7a779e30be9cd8adL, 0x65f1bb7f77d9cd0fL, 0x2563e5c0bbf51b16L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x82808ced17295a86L, 0x24b35e391e0fd48fL, 0x4e2ed9f3a29474baL, 0x30790dd2ee6b8cc1L }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xa3305485bf3ac883L, 0xaa3bc0085f72fbe1L, 0xe83d1e742abaa7aaL, 0x0b152812327671aaL }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(4, new long[]{ 0xc14046768b94ad43L, 0x1259af1c8f07ea47L, 0xa7176cf9d14a3a5dL, 0x183c86e97735c660L }));  // norm
    }

    private ConnectingIdealsLvl5()
    {
    }
}
