package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of {@code CONNECTING_IDEALS[8]} from
 * {@code src/precomp/ref/lvl3/quaternion_data.c}.
 *
 * <p>Lvl3 has 8 entries (1 standard O₀ + 7 alternate extremal orders),
 * one more than lvl1. Each is a {@link QuatLeftIdeal} with its lattice
 * (denom + 4×4 basis) and norm.</p>
 *
 * <p>Limbs mechanically extracted from the C reference via
 * {@code core/src/tools/python/extract_sqisign_precomp.py}.</p>
 */
final class ConnectingIdealsLvl3
{
    public static final int COUNT = 8;

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
            Ibz.fromMpLimbs(4, new long[]{ 0x21d4cde19a6fbf5aL, 0x78ebf3bae7a052b1L, 0x1c515c29787fc45cL, 0x0000000000000001L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(3, new long[]{ 0x1437b508fd5c8015L, 0xa79a14526222fa92L, 0x15c5b3c4d3a96c31L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0x21d4cde19a6fbf5aL, 0x78ebf3bae7a052b1L, 0x1c515c29787fc45cL, 0x0000000000000001L }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0x0d9d18d89d133f45L, 0xd151df68857d581fL, 0x068ba864a4d6582aL, 0x0000000000000001L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0x90ea66f0cd37dfadL, 0x3c75f9dd73d02958L, 0x8e28ae14bc3fe22eL }));  // norm

        // CONNECTING_IDEALS[2]
        populate(CONNECTING_IDEALS[2],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0xc1200e71920e9d7aL, 0xff55029f607e8fbfL, 0x125bbca447967422L, 0x0000000000000001L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(3, new long[]{ 0xec53c53876edbcbfL, 0x014fa54eb40deb88L, 0x0539edb2300a8bb2L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0xc1200e71920e9d7aL, 0xff55029f607e8fbfL, 0x125bbca447967422L, 0x0000000000000001L }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xd4cc49391b20e0bbL, 0xfe055d50ac70a436L, 0x0d21cef2178be870L, 0x0000000000000001L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0xe0900738c9074ebdL, 0x7faa814fb03f47dfL, 0x892dde5223cb3a11L }));  // norm

        // CONNECTING_IDEALS[3]
        populate(CONNECTING_IDEALS[3],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0xe33e6532cb1fd282L, 0x2b6242750fd8153dL, 0xf7223f12db04f17dL, 0x0000000000000001L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(3, new long[]{ 0xea4de944eebf50bfL, 0x12b04919cbc5076dL, 0x126533049e3071f3L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0xe33e6532cb1fd282L, 0x2b6242750fd8153dL, 0xf7223f12db04f17dL, 0x0000000000000001L }),  // b[1][1]
            Ibz.fromMpLimbs(4, new long[]{ 0xf8f07beddc6081c3L, 0x18b1f95b44130dcfL, 0xe4bd0c0e3cd47f8aL, 0x0000000000000001L }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0xf19f3299658fe941L, 0x95b1213a87ec0a9eL, 0xfb911f896d8278beL }));  // norm

        // CONNECTING_IDEALS[4]
        populate(CONNECTING_IDEALS[4],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(3, new long[]{ 0x7c1cd4b8abc3dfdaL, 0x79cc21da66b24727L, 0xa12d9b8d553de3a3L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(3, new long[]{ 0xd263887fd39960fbL, 0xea34699bb202e0e7L, 0x8e9567634b8a5a15L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(3, new long[]{ 0x7c1cd4b8abc3dfdaL, 0x79cc21da66b24727L, 0xa12d9b8d553de3a3L }),  // b[1][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xa9b94c38d82a7edfL, 0x8f97b83eb4af663fL, 0x1298342a09b3898dL }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0xbe0e6a5c55e1efedL, 0xbce610ed33592393L, 0x5096cdc6aa9ef1d1L }));  // norm

        // CONNECTING_IDEALS[5]
        populate(CONNECTING_IDEALS[5],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(4, new long[]{ 0xd8de1a76d869e00eL, 0xf26499e1abc5fe4cL, 0xb60b32ab09c37d83L, 0x0000000000000001L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(4, new long[]{ 0x0d6b19a98bbfb00fL, 0xd7e274e7cd5c0f7bL, 0x8de856a83593a419L, 0x0000000000000001L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(4, new long[]{ 0xd8de1a76d869e00eL, 0xf26499e1abc5fe4cL, 0xb60b32ab09c37d83L, 0x0000000000000001L }),  // b[1][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xcb7300cd4caa2fffL, 0x1a8224f9de69eed1L, 0x2822dc02d42fd96aL }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0x6c6f0d3b6c34f007L, 0xf9324cf0d5e2ff26L, 0xdb05995584e1bec1L }));  // norm

        // CONNECTING_IDEALS[6]
        populate(CONNECTING_IDEALS[6],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(3, new long[]{ 0x97d3c8dc37a07b26L, 0x1df20931d6bd7f2fL, 0x6ee725914a3e2918L }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(3, new long[]{ 0x9a52ac55cd013a91L, 0x42454dec118f9887L, 0x07ad1d161022d869L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(3, new long[]{ 0x97d3c8dc37a07b26L, 0x1df20931d6bd7f2fL, 0x6ee725914a3e2918L }),  // b[1][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xfd811c866a9f4095L, 0xdbacbb45c52de6a7L, 0x673a087b3a1b50aeL }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0xcbe9e46e1bd03d93L, 0x0ef90498eb5ebf97L, 0x377392c8a51f148cL }));  // norm

        // CONNECTING_IDEALS[7]
        populate(CONNECTING_IDEALS[7],
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000002L }),  // denom
            Ibz.fromMpLimbs(3, new long[]{ 0x430fb04b3b34e5caL, 0xec478c7da04ae795L, 0xd31fb71e8e5c77dfL }),  // b[0][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[0][2]
            Ibz.fromMpLimbs(3, new long[]{ 0x83ff383998d54d27L, 0xbe45c95b4d5b48b7L, 0x6c264d5736f39d44L }),  // b[0][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][0]
            Ibz.fromMpLimbs(3, new long[]{ 0x430fb04b3b34e5caL, 0xec478c7da04ae795L, 0xd31fb71e8e5c77dfL }),  // b[1][1]
            Ibz.fromMpLimbs(3, new long[]{ 0xbf107811a25f98a3L, 0x2e01c32252ef9eddL, 0x66f969c75768da9bL }),  // b[1][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[1][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][1]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[2][2]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[2][3]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][0]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][1]
            Ibz.fromMpLimbs(0, new long[]{ 0x0000000000000000L }),  // b[3][2]
            Ibz.fromMpLimbs(1, new long[]{ 0x0000000000000001L }),  // b[3][3]
            Ibz.fromMpLimbs(3, new long[]{ 0xa187d8259d9a72e5L, 0xf623c63ed02573caL, 0x698fdb8f472e3befL }));  // norm
    }

    private ConnectingIdealsLvl3()
    {
    }
}
