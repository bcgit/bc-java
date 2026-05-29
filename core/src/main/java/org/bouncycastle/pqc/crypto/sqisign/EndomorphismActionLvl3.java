package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Java mirror of {@code CURVES_WITH_ENDOMORPHISMS[8]} from
 * {@code src/precomp/ref/lvl3/endomorphism_action.c}.
 *
 * <p>This level holds 8 entries (primary curve E₀ at index 0 plus
 * 7 alternate starting curves). Each entry contains 20 GF(p²)
 * field elements (curve A/C, A24 point, and basis_even P/Q/PmQ) plus 24
 * integer matrix entries (the six 2×2 action matrices for i, j, k, and
 * the three order generators).</p>
 *
 * <p>Fp values are stored as canonical {@link BigInteger} in {@code [0, p)},
 * having been mechanically Montgomery-decoded from the C reference's
 * 7-limb-of-55-bit representation at extractor time.</p>
 *
 * <p>Data layout per entry (index {@code i}):</p>
 * <pre>
 *   CURVE_FP[i][ 0..1] = A.re, A.im
 *   CURVE_FP[i][ 2..3] = C.re, C.im
 *   CURVE_FP[i][ 4..5] = A24.x.re, A24.x.im
 *   CURVE_FP[i][ 6..7] = A24.z.re, A24.z.im
 *   CURVE_FP[i][ 8..9] = P.x.re, P.x.im
 *   CURVE_FP[i][10..11] = P.z.re, P.z.im
 *   CURVE_FP[i][12..13] = Q.x.re, Q.x.im
 *   CURVE_FP[i][14..15] = Q.z.re, Q.z.im
 *   CURVE_FP[i][16..17] = PmQ.x.re, PmQ.x.im
 *   CURVE_FP[i][18..19] = PmQ.z.re, PmQ.z.im
 *
 *   CURVE_IBZ[i][ 0.. 3] = action_i  [0][0], [0][1], [1][0], [1][1]
 *   CURVE_IBZ[i][ 4.. 7] = action_j  ...
 *   CURVE_IBZ[i][ 8..11] = action_k  ...
 *   CURVE_IBZ[i][12..15] = action_gen2 ...
 *   CURVE_IBZ[i][16..19] = action_gen3 ...
 *   CURVE_IBZ[i][20..23] = action_gen4 ...
 * </pre>
 */
final class EndomorphismActionLvl3
{
    public static final int NUM_CURVES = 8;
    public static final int FP_PER_ENTRY = 20;
    public static final int IBZ_PER_ENTRY = 24;

    public static final BigInteger[][] CURVE_FP = new BigInteger[NUM_CURVES][FP_PER_ENTRY];
    public static final Ibz[][] CURVE_IBZ = new Ibz[NUM_CURVES][IBZ_PER_ENTRY];

    static
    {
        // ---- Entry [0] ----
        CURVE_FP[0][0] = BigInteger.ZERO;
        CURVE_FP[0][1] = BigInteger.ZERO;
        CURVE_FP[0][2] = BigInteger.ONE;
        CURVE_FP[0][3] = BigInteger.ZERO;
        CURVE_FP[0][4] = new BigInteger("208000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16);
        CURVE_FP[0][5] = BigInteger.ZERO;
        CURVE_FP[0][6] = BigInteger.ONE;
        CURVE_FP[0][7] = BigInteger.ZERO;
        CURVE_FP[0][8] = new BigInteger("1798a1c27fb6dbff48e2f771d26ec456d059a73a5b5d2c853fb73a87d77bc2c5dbd311c20c76dbc43ea2ed69d1d24317", 16);
        CURVE_FP[0][9] = new BigInteger("2cb19c5d827d348a69cd0e002c4665c2aed0cf6c1fcdf1a1afa3773ad7512fddf4b5201c5623521faafc461b9ddd11f0", 16);
        CURVE_FP[0][10] = BigInteger.ONE;
        CURVE_FP[0][11] = BigInteger.ZERO;
        CURVE_FP[0][12] = new BigInteger("129213ad6e31d1c94a24ad066819aff34be5b9ecf412164a24d8d0bc9570ff6cd67adb66e57db8685bc56017c110a723", 16);
        CURVE_FP[0][13] = new BigInteger("32a595cb10fd42a35f44f05ea57dc0431817aba97f782a74cb79a068d58e35e22f24b1bfb2677cd995fcb7e977b9335", 16);
        CURVE_FP[0][14] = BigInteger.ONE;
        CURVE_FP[0][15] = BigInteger.ZERO;
        CURVE_FP[0][16] = new BigInteger("2c77a65f9b26a43afc8d22b66c49f132404092121d2a63be2927381af6668f9c55f905b2630d2650179deba81085beaa", 16);
        CURVE_FP[0][17] = new BigInteger("39d755e84591ff8dd7d943e9d470b80906cd789cd2c1a4e9270871eb0e4bc392fc0e02727177434263fbd3d2011e1580", 16);
        CURVE_FP[0][18] = BigInteger.ONE;
        CURVE_FP[0][19] = BigInteger.ZERO;
        CURVE_IBZ[0][0] = Ibz.fromMpLimbs(6, new long[]{ 0x003a84778f9c97d1L, 0x13daabd666ae39d2L, 0x5f9ff8dbb9e7f153L, 0x62b9a4f0fcb236f7L, 0xe8c5539d36945c07L, 0x009ac691f16c7631L });
        CURVE_IBZ[0][1] = Ibz.fromMpLimbs(6, new long[]{ 0x76df4a43bac61ac2L, 0xd32d1cf84a2de925L, 0xdf8bc02f1dc07867L, 0x4a9ee07d4f0cf122L, 0x357087917ce20a97L, 0x006634cc519b1749L });
        CURVE_IBZ[0][2] = Ibz.fromMpLimbs(6, new long[]{ 0x9c61a4810234fb0fL, 0xe38c3a72cd584bd1L, 0xdc99f1020ea3be7bL, 0xef915d86b229f180L, 0xf66fa9d5883146c4L, 0x00fc9ebd6c02a451L });
        CURVE_IBZ[0][3] = Ibz.fromMpLimbs(6, new long[]{ 0xffc57b887063682fL, 0xec2554299951c62dL, 0xa060072446180eacL, 0x9d465b0f034dc908L, 0x173aac62c96ba3f8L, 0x0065396e0e9389ceL });
        CURVE_IBZ[0][4] = Ibz.fromMpLimbs(6, new long[]{ 0xc3b21abbc7426f75L, 0xc51b066bf0154bffL, 0x625bf64130c2acd6L, 0xbe4051210be52e88L, 0x4eb6b8c9755b8ac2L, 0x004784cf46b60b07L });
        CURVE_IBZ[0][5] = Ibz.fromMpLimbs(6, new long[]{ 0xae1ee350479b9db8L, 0x89ed60a465724f92L, 0xf9ca64b6b88d12f4L, 0xb2c783b8c086026bL, 0x901757b3e99b88a8L, 0x00375de69d5de033L });
        CURVE_IBZ[0][6] = Ibz.fromMpLimbs(6, new long[]{ 0x354e34311d0223f7L, 0x6a9ce6c423a4ba31L, 0xe54f419f0ea8064cL, 0xe7a33cafc02d3cb9L, 0x47d9ed8031d42d32L, 0x002580d369f42086L });
        CURVE_IBZ[0][7] = Ibz.fromMpLimbs(6, new long[]{ 0x3c4de54438bd908bL, 0x3ae4f9940feab400L, 0x9da409becf3d5329L, 0x41bfaedef41ad177L, 0xb14947368aa4753dL, 0x00b87b30b949f4f8L });
        CURVE_IBZ[0][8] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[0][9] = Ibz.fromMpLimbs(6, new long[]{ 0x1f58fab72e0af28eL, 0x28d439c3024311eaL, 0x4d873aec1878e1baL, 0x7416a312354af832L, 0x78d2162768ee0b5bL, 0x00d11cb2152ffbbcL });
        CURVE_IBZ[0][10] = Ibz.fromMpLimbs(6, new long[]{ 0xdd4b424688763134L, 0x2d3371e886b187d0L, 0xf6d66377e6d8fe04L, 0x521e29d48b91dd4fL, 0x8c9c2eb9a1d53822L, 0x00112d4cab9f35a1L });
        CURVE_IBZ[0][11] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[0][12] = Ibz.fromMpLimbs(6, new long[]{ 0x003a84778f9c97d1L, 0x13daabd666ae39d2L, 0x5f9ff8dbb9e7f153L, 0x62b9a4f0fcb236f7L, 0xe8c5539d36945c07L, 0x009ac691f16c7631L });
        CURVE_IBZ[0][13] = Ibz.fromMpLimbs(6, new long[]{ 0x76df4a43bac61ac2L, 0xd32d1cf84a2de925L, 0xdf8bc02f1dc07867L, 0x4a9ee07d4f0cf122L, 0x357087917ce20a97L, 0x006634cc519b1749L });
        CURVE_IBZ[0][14] = Ibz.fromMpLimbs(6, new long[]{ 0x9c61a4810234fb0fL, 0xe38c3a72cd584bd1L, 0xdc99f1020ea3be7bL, 0xef915d86b229f180L, 0xf66fa9d5883146c4L, 0x00fc9ebd6c02a451L });
        CURVE_IBZ[0][15] = Ibz.fromMpLimbs(6, new long[]{ 0xffc57b887063682fL, 0xec2554299951c62dL, 0xa060072446180eacL, 0x9d465b0f034dc908L, 0x173aac62c96ba3f8L, 0x0065396e0e9389ceL });
        CURVE_IBZ[0][16] = Ibz.fromMpLimbs(6, new long[]{ 0xe1f64f99ab6f83a3L, 0xec7ad9212b61c2e8L, 0xe0fdf78e75554f14L, 0x107cfb09044bb2bfL, 0x9bbe063355f7f365L, 0x00f125b09c11409cL });
        CURVE_IBZ[0][17] = Ibz.fromMpLimbs(6, new long[]{ 0x127f16ca0130dc3dL, 0x2e8d3ece57d01c5cL, 0x6cab1272eb26c5aeL, 0xfeb3321b07c979c7L, 0x62c3efa2b33ec99fL, 0x004ec959777c7bbeL });
        CURVE_IBZ[0][18] = Ibz.fromMpLimbs(6, new long[]{ 0x68d7ec590f9b8f83L, 0x2714909b787e8301L, 0x60f499508ea5e264L, 0xeb9a4d1b392b971dL, 0x1f24cbaadd02b9fbL, 0x00910fc86afb626cL });
        CURVE_IBZ[0][19] = Ibz.fromMpLimbs(6, new long[]{ 0x1e09b06654907c5dL, 0x138526ded49e3d17L, 0x1f0208718aaab0ebL, 0xef8304f6fbb44d40L, 0x6441f9ccaa080c9aL, 0x000eda4f63eebf63L });
        CURVE_IBZ[0][20] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[0][21] = Ibz.fromMpLimbs(6, new long[]{ 0x0fac7d5b97057947L, 0x146a1ce1812188f5L, 0x26c39d760c3c70ddL, 0xba0b51891aa57c19L, 0x3c690b13b47705adL, 0x00688e590a97fddeL });
        CURVE_IBZ[0][22] = Ibz.fromMpLimbs(6, new long[]{ 0x6ea5a123443b189aL, 0x1699b8f44358c3e8L, 0xfb6b31bbf36c7f02L, 0x290f14ea45c8eea7L, 0xc64e175cd0ea9c11L, 0x000896a655cf9ad0L });
        CURVE_IBZ[0][23] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });

        // ---- Entry [1] ----
        CURVE_FP[1][0] = new BigInteger("c9d4efdd8d3f82d1e124146e0650f4cbfa6daf5c9d300581cd2511fcb8ca3639e067b8c634e8e805e624cf62687089b", 16);
        CURVE_FP[1][1] = BigInteger.ZERO;
        CURVE_FP[1][2] = BigInteger.ONE;
        CURVE_FP[1][3] = BigInteger.ZERO;
        CURVE_FP[1][4] = new BigInteger("136753bf7634fe0b47849051b81943d32fe9b6bd7274c01607349447f2e328d8e7819ee318d3a3a01798933d89a1c227", 16);
        CURVE_FP[1][5] = BigInteger.ZERO;
        CURVE_FP[1][6] = BigInteger.ONE;
        CURVE_FP[1][7] = BigInteger.ZERO;
        CURVE_FP[1][8] = new BigInteger("1819eef28811cf99591526c470ce12ae5072492b8dd19b7e3d5d1bc8864878064bc3bc865f4d8182f86bcb3ef667c19d", 16);
        CURVE_FP[1][9] = new BigInteger("262afa922201f77221c7aac05e6b12a2f3a03ed4b0b0d5a1cdbb0a978a6783d9c303beb9f1df13c5a30e42bf79fa1113", 16);
        CURVE_FP[1][10] = BigInteger.ONE;
        CURVE_FP[1][11] = BigInteger.ZERO;
        CURVE_FP[1][12] = new BigInteger("1e8cfb20de9fdf367e4bc42895dd7be717c5e6398f893d9612a7ecfdcaf6eec52f5a5e07fef3a8576403db4b9ef28f89", 16);
        CURVE_FP[1][13] = new BigInteger("4066d4323ed5e4927a0df69c5898b59c37c6ba0d604d8e73dccda61d47c30e7ec3162d576b8ebccbe9f88d05d234dbec", 16);
        CURVE_FP[1][14] = BigInteger.ONE;
        CURVE_FP[1][15] = BigInteger.ZERO;
        CURVE_FP[1][16] = new BigInteger("19b6ed182c76abdbcedcb31aaa71bf92990af28a7a2a3c9473b92704d705db67e524a3c0d2b21f34daed539825a8f2c7", 16);
        CURVE_FP[1][17] = new BigInteger("8aaf7aeb82929743dfae1879de9cf5c90b5f23195a54d9ee2ac05cb27cf7e240ceadc6bb468ddd4f815212a698b4d90", 16);
        CURVE_FP[1][18] = BigInteger.ONE;
        CURVE_FP[1][19] = BigInteger.ZERO;
        CURVE_IBZ[1][0] = Ibz.fromMpLimbs(6, new long[]{ 0x0ce2d4d0fa2a8d4fL, 0x2c18be5f80797436L, 0xe1067ecd35695699L, 0x7293cc957d910ea0L, 0x9858b900d8125f1dL, 0x000a1d4ac80ed95aL });
        CURVE_IBZ[1][1] = Ibz.fromMpLimbs(6, new long[]{ 0x93f2f18970271ecaL, 0x9e7dabbc5a6f1c1fL, 0x8db062a80c45a00aL, 0xffaa400a413f70cdL, 0x69c4cb0ed8a82ae6L, 0x00ada6797a257d9aL });
        CURVE_IBZ[1][2] = Ibz.fromMpLimbs(6, new long[]{ 0xc6579be5fec58949L, 0xc0f703ee2df6ab10L, 0xb50c03b3328e1a64L, 0xb10308aba23d650aL, 0xc702708ab27df6e6L, 0x002f99912f005301L });
        CURVE_IBZ[1][3] = Ibz.fromMpLimbs(6, new long[]{ 0xf31d2b2f05d572b1L, 0xd3e741a07f868bc9L, 0x1ef98132ca96a966L, 0x8d6c336a826ef15fL, 0x67a746ff27eda0e2L, 0x00f5e2b537f126a5L });
        CURVE_IBZ[1][4] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[1][5] = Ibz.fromMpLimbs(6, new long[]{ 0xe0a70548d1f50d72L, 0xd72bc63cfdbcee15L, 0xb278c513e7871e45L, 0x8be95cedcab507cdL, 0x872de9d89711f4a4L, 0x002ee34dead00443L });
        CURVE_IBZ[1][6] = Ibz.fromMpLimbs(6, new long[]{ 0x22b4bdb97789ceccL, 0xd2cc8e17794e782fL, 0x09299c88192701fbL, 0xade1d62b746e22b0L, 0x7363d1465e2ac7ddL, 0x00eed2b35460ca5eL });
        CURVE_IBZ[1][7] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[1][8] = Ibz.fromMpLimbs(6, new long[]{ 0x20e335fce1201ebbL, 0x62f62ef4ff68ba01L, 0x804c3f9394c15e93L, 0xf6731d315b3dddc5L, 0x6f7e242c3d326e47L, 0x00f70bf463cb764bL });
        CURVE_IBZ[1][9] = Ibz.fromMpLimbs(6, new long[]{ 0x0ee5068434d0e76cL, 0x28674bd55a3843c6L, 0x18bff7902ee1d3c5L, 0xe0bc7d253924bb64L, 0x709150e91355913aL, 0x00aac02721b26724L });
        CURVE_IBZ[1][10] = Ibz.fromMpLimbs(6, new long[]{ 0x800758bc45bbbd01L, 0x07f9440b0fd7bf5bL, 0xcd7b2ba9e5db54edL, 0x9e9b14701314fc98L, 0x4cc973c6944c0ca3L, 0x00468b4045fea757L });
        CURVE_IBZ[1][11] = Ibz.fromMpLimbs(6, new long[]{ 0xdf1cca031edfe145L, 0x9d09d10b009745feL, 0x7fb3c06c6b3ea16cL, 0x098ce2cea4c2223aL, 0x9081dbd3c2cd91b8L, 0x0008f40b9c3489b4L });
        CURVE_IBZ[1][12] = Ibz.fromMpLimbs(6, new long[]{ 0x0ce2d4d0fa2a8d4fL, 0x2c18be5f80797436L, 0xe1067ecd35695699L, 0x7293cc957d910ea0L, 0x9858b900d8125f1dL, 0x000a1d4ac80ed95aL });
        CURVE_IBZ[1][13] = Ibz.fromMpLimbs(6, new long[]{ 0x93f2f18970271ecaL, 0x9e7dabbc5a6f1c1fL, 0x8db062a80c45a00aL, 0xffaa400a413f70cdL, 0x69c4cb0ed8a82ae6L, 0x00ada6797a257d9aL });
        CURVE_IBZ[1][14] = Ibz.fromMpLimbs(6, new long[]{ 0xc6579be5fec58949L, 0xc0f703ee2df6ab10L, 0xb50c03b3328e1a64L, 0xb10308aba23d650aL, 0xc702708ab27df6e6L, 0x002f99912f005301L });
        CURVE_IBZ[1][15] = Ibz.fromMpLimbs(6, new long[]{ 0xf31d2b2f05d572b1L, 0xd3e741a07f868bc9L, 0x1ef98132ca96a966L, 0x8d6c336a826ef15fL, 0x67a746ff27eda0e2L, 0x00f5e2b537f126a5L });
        CURVE_IBZ[1][16] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });
        CURVE_IBZ[1][17] = Ibz.fromMpLimbs(6, new long[]{ 0xf05382a468fa86b9L, 0xeb95e31e7ede770aL, 0xd93c6289f3c38f22L, 0x45f4ae76e55a83e6L, 0xc396f4ec4b88fa52L, 0x009771a6f5680221L });
        CURVE_IBZ[1][18] = Ibz.fromMpLimbs(6, new long[]{ 0x915a5edcbbc4e766L, 0xe966470bbca73c17L, 0x0494ce440c9380fdL, 0xd6f0eb15ba371158L, 0x39b1e8a32f1563eeL, 0x00f76959aa30652fL });
        CURVE_IBZ[1][19] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[1][20] = Ibz.fromMpLimbs(6, new long[]{ 0x4accc31535b43e42L, 0x941d0e57734e7905L, 0x567906529010cc00L, 0x593677f069d51e7cL, 0x8415dbaedc499815L, 0x00351b55706d2381L });
        CURVE_IBZ[1][21] = Ibz.fromMpLimbs(6, new long[]{ 0x8d4e311a1f889f23L, 0x8bcf0997199f15a2L, 0x254b3de8c956c7a0L, 0x9cb1604a1a691224L, 0x65b85903c6eea8f7L, 0x00b37d6ea271e8a5L });
        CURVE_IBZ[1][22] = Ibz.fromMpLimbs(6, new long[]{ 0xba3b39ea9280fad4L, 0x2c195ffd1c9cb12bL, 0x30c1af34214513bfL, 0xb50a653927ea70d8L, 0xa5d27fad36383106L, 0x00fdb4a1b0e6912aL });
        CURVE_IBZ[1][23] = Ibz.fromMpLimbs(6, new long[]{ 0xb5333ceaca4bc1beL, 0x6be2f1a88cb186faL, 0xa986f9ad6fef33ffL, 0xa6c9880f962ae183L, 0x7bea245123b667eaL, 0x00cae4aa8f92dc7eL });

        // ---- Entry [2] ----
        CURVE_FP[2][0] = new BigInteger("145cdd1acd032dd67057fa3e060d466a38ccbefea1559121a8ed1b68b620064a767f378f17ef668a9498eb82fb8eed4d", 16);
        CURVE_FP[2][1] = BigInteger.ZERO;
        CURVE_FP[2][2] = BigInteger.ONE;
        CURVE_FP[2][3] = BigInteger.ZERO;
        CURVE_FP[2][4] = new BigInteger("35d73746b340cb759c15fe8f8183519a8e332fbfa85564486a3b46da2d8801929d9fcde3c5fbd9a2a5263ae0bee3bb53", 16);
        CURVE_FP[2][5] = BigInteger.ZERO;
        CURVE_FP[2][6] = BigInteger.ONE;
        CURVE_FP[2][7] = BigInteger.ZERO;
        CURVE_FP[2][8] = new BigInteger("1ee562bf891f4e5a5175a1a5d8dafd8435d36b3868b7f5ca4c4687c1be3b42e2a8e7556d9066f649077f8f3c2a8b0596", 16);
        CURVE_FP[2][9] = new BigInteger("351d6de132af1edabde0163acee4d045e63fc17844173eacc90d23c2738789d85b79ffecab3c965cda624ad21a959b47", 16);
        CURVE_FP[2][10] = BigInteger.ONE;
        CURVE_FP[2][11] = BigInteger.ZERO;
        CURVE_FP[2][12] = new BigInteger("37f3d42a7a9a64153e0ecf94bf49d787633945f153f5f5e60880ab6cddc575a975828c074d3fae7804aee4bffb224830", 16);
        CURVE_FP[2][13] = new BigInteger("23ea89be0e325e378762a0d1bfa29726f6b594df3101be077e902b8f9e18b43920688e4fc13949e3132111889f90fd65", 16);
        CURVE_FP[2][14] = BigInteger.ONE;
        CURVE_FP[2][15] = BigInteger.ZERO;
        CURVE_FP[2][16] = new BigInteger("b4a0e06acbba7c401a3c28969b899e5e569d1ee014fdfcf2f9c84b382856efe474f7fa9ae165b54d12c3a0859e52db9", 16);
        CURVE_FP[2][17] = new BigInteger("bf1e96089a5a7d58c4a99666afe76f1b62016397971e33251ea92ba86a4cb7c875832b402a1dc7c479463f58cbea23b", 16);
        CURVE_FP[2][18] = BigInteger.ONE;
        CURVE_FP[2][19] = BigInteger.ZERO;
        CURVE_IBZ[2][0] = Ibz.fromMpLimbs(6, new long[]{ 0x17cca5a7a64cb089L, 0x932886e8aa34e580L, 0xd6e52dbc66ce2d1eL, 0xc3418c7aaf97068fL, 0x580fe0a34e1c4b41L, 0x000f8ad38f21e796L });
        CURVE_IBZ[2][1] = Ibz.fromMpLimbs(6, new long[]{ 0xef29cd8cec570ebeL, 0x715ca791d391f13aL, 0x5a37f950194ce58eL, 0x5cce82c8dab6db9eL, 0x0ad4a700339a3197L, 0x00b05cff91c1cd5bL });
        CURVE_IBZ[2][2] = Ibz.fromMpLimbs(6, new long[]{ 0xc9a04b2c8fac3b4fL, 0xe41b3480e4fa69a2L, 0x2f67a965d68b5801L, 0x535293a77ac03134L, 0x044f33e6200e9612L, 0x004de41182f1bca8L });
        CURVE_IBZ[2][3] = Ibz.fromMpLimbs(6, new long[]{ 0xe8335a5859b34f77L, 0x6cd7791755cb1a7fL, 0x291ad2439931d2e1L, 0x3cbe73855068f970L, 0xa7f01f5cb1e3b4beL, 0x00f0752c70de1869L });
        CURVE_IBZ[2][4] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[2][5] = Ibz.fromMpLimbs(6, new long[]{ 0x1f58fab72e0af28eL, 0x28d439c3024311eaL, 0x4d873aec1878e1baL, 0x7416a312354af832L, 0x78d2162768ee0b5bL, 0x00d11cb2152ffbbcL });
        CURVE_IBZ[2][6] = Ibz.fromMpLimbs(6, new long[]{ 0xdd4b424688763134L, 0x2d3371e886b187d0L, 0xf6d66377e6d8fe04L, 0x521e29d48b91dd4fL, 0x8c9c2eb9a1d53822L, 0x00112d4cab9f35a1L });
        CURVE_IBZ[2][7] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[2][8] = Ibz.fromMpLimbs(6, new long[]{ 0xb87200313132e463L, 0x62c52b881045dbeeL, 0xa84fb179de5cee3cL, 0xbef89a0f355e18e5L, 0xaa316d1c35b5783aL, 0x008aa0f6ed813024L });
        CURVE_IBZ[2][9] = Ibz.fromMpLimbs(6, new long[]{ 0xd2f9e08bdac2cf24L, 0xfa7c95170f1f013aL, 0x3e594d0b581ea1c5L, 0xa48eee19750697ccL, 0x4b1db5a750c2b1b0L, 0x0085ab65ee682fcdL });
        CURVE_IBZ[2][10] = Ibz.fromMpLimbs(6, new long[]{ 0x9c91df287be58b69L, 0x4f816c507c60f929L, 0x3c71274159da714aL, 0xa26f14bd79bf223aL, 0xef81c74c606dc787L, 0x006a55ff032ad1c4L });
        CURVE_IBZ[2][11] = Ibz.fromMpLimbs(6, new long[]{ 0x478dffcececd1b9dL, 0x9d3ad477efba2411L, 0x57b04e8621a311c3L, 0x410765f0caa1e71aL, 0x55ce92e3ca4a87c5L, 0x00755f09127ecfdbL });
        CURVE_IBZ[2][12] = Ibz.fromMpLimbs(6, new long[]{ 0x17cca5a7a64cb089L, 0x932886e8aa34e580L, 0xd6e52dbc66ce2d1eL, 0xc3418c7aaf97068fL, 0x580fe0a34e1c4b41L, 0x000f8ad38f21e796L });
        CURVE_IBZ[2][13] = Ibz.fromMpLimbs(6, new long[]{ 0xef29cd8cec570ebeL, 0x715ca791d391f13aL, 0x5a37f950194ce58eL, 0x5cce82c8dab6db9eL, 0x0ad4a700339a3197L, 0x00b05cff91c1cd5bL });
        CURVE_IBZ[2][14] = Ibz.fromMpLimbs(6, new long[]{ 0xc9a04b2c8fac3b4fL, 0xe41b3480e4fa69a2L, 0x2f67a965d68b5801L, 0x535293a77ac03134L, 0x044f33e6200e9612L, 0x004de41182f1bca8L });
        CURVE_IBZ[2][15] = Ibz.fromMpLimbs(6, new long[]{ 0xe8335a5859b34f77L, 0x6cd7791755cb1a7fL, 0x291ad2439931d2e1L, 0x3cbe73855068f970L, 0xa7f01f5cb1e3b4beL, 0x00f0752c70de1869L });
        CURVE_IBZ[2][16] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[2][17] = Ibz.fromMpLimbs(6, new long[]{ 0x0fac7d5b97057947L, 0x146a1ce1812188f5L, 0x26c39d760c3c70ddL, 0xba0b51891aa57c19L, 0x3c690b13b47705adL, 0x00688e590a97fddeL });
        CURVE_IBZ[2][18] = Ibz.fromMpLimbs(6, new long[]{ 0x6ea5a123443b189aL, 0x1699b8f44358c3e8L, 0xfb6b31bbf36c7f02L, 0x290f14ea45c8eea7L, 0xc64e175cd0ea9c11L, 0x000896a655cf9ad0L });
        CURVE_IBZ[2][19] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });
        CURVE_IBZ[2][20] = Ibz.fromMpLimbs(6, new long[]{ 0x48972dbfa20ad69fL, 0x293ee5f9de893199L, 0x508f9878b67a826bL, 0xa78ca6dcbfc71cd5L, 0x9a612bd3f717a5a7L, 0x005dba39b7727d35L });
        CURVE_IBZ[2][21] = Ibz.fromMpLimbs(6, new long[]{ 0x9e9f61bb1e36eec1L, 0xb5cd8a8e9166e1d8L, 0xc5feb7db4281c787L, 0xdfb3ad1a7038029bL, 0xe9d5ce34a6435d88L, 0x00bcb80fc15c0fe7L });
        CURVE_IBZ[2][22] = Ibz.fromMpLimbs(6, new long[]{ 0x5a592b8a00c2b7ffL, 0xad199b6452cad318L, 0x9d097b28c9b808dfL, 0xcbb9fb090009e309L, 0x0aa5707c11376a67L, 0x00b9fb9e3ffdcdf5L });
        CURVE_IBZ[2][23] = Ibz.fromMpLimbs(6, new long[]{ 0xb768d2405df52961L, 0xd6c11a062176ce66L, 0xaf70678749857d94L, 0x587359234038e32aL, 0x659ed42c08e85a58L, 0x00a245c6488d82caL });

        // ---- Entry [3] ----
        CURVE_FP[3][0] = new BigInteger("a349003bbd506e614c98d57af0210a0b8f5f698d2d2f170b223631a5ffb96dce23ac19fd61e8e34b2db51755907fb6", 16);
        CURVE_FP[3][1] = BigInteger.ZERO;
        CURVE_FP[3][2] = BigInteger.ONE;
        CURVE_FP[3][3] = BigInteger.ZERO;
        CURVE_FP[3][4] = new BigInteger("28d2400eef541b985326355ebc084282e3d7da634b4bc5c2c88d8c697fee5b7388eb067f587a38d2cb6d45d5641fee", 16);
        CURVE_FP[3][5] = BigInteger.ZERO;
        CURVE_FP[3][6] = BigInteger.ONE;
        CURVE_FP[3][7] = BigInteger.ZERO;
        CURVE_FP[3][8] = new BigInteger("42791d37e032456cd40f3daa4e50adf280510c1a08ef210ad5b39cb133f3b9f7a7844404c311ea5b8a095afdc35616c", 16);
        CURVE_FP[3][9] = new BigInteger("1d42953fa4693d1abd3e43851484c988854866056ffd5d3b6f7b8a7dfe1d1e6a78056b4a3ef0c7a412101b906e7b9a73", 16);
        CURVE_FP[3][10] = BigInteger.ONE;
        CURVE_FP[3][11] = BigInteger.ZERO;
        CURVE_FP[3][12] = new BigInteger("31905ef13e903eb5de78959b0fa6cc43045471e18f28daac75e31d2606990f2c57a310265e91388c070707e4bf4f5512", 16);
        CURVE_FP[3][13] = new BigInteger("2076105bcb430812e89628e2bad41e29c7c7eee9c43c58c5d0765b3173ec9fae8ce7e651675940a8d8922b85bb2889a6", 16);
        CURVE_FP[3][14] = BigInteger.ONE;
        CURVE_FP[3][15] = BigInteger.ZERO;
        CURVE_FP[3][16] = new BigInteger("1e4b2387573a1f0daea122979855ef90cae95a2ff2e481106d6d7bfa81349f1444ab7f2dd5bab8fd8c08930b3358bc16", 16);
        CURVE_FP[3][17] = new BigInteger("1444d9c818ec66ad08588b7a47921f0cc565247be155e58ed1825d976340429e806e674d4a0a9f6b9f9e5bb2e569dfdc", 16);
        CURVE_FP[3][18] = BigInteger.ONE;
        CURVE_FP[3][19] = BigInteger.ZERO;
        CURVE_IBZ[3][0] = Ibz.fromMpLimbs(6, new long[]{ 0x0aeeb451e9164fffL, 0x199ab766fa2cc580L, 0x47ddaa1b36f2a8a0L, 0xc4c1b1ba26f5b34fL, 0x0f7a21fdfcf8ad4dL, 0x00942b084cd22a36L });
        CURVE_IBZ[3][1] = Ibz.fromMpLimbs(6, new long[]{ 0xe2aee09f5176f16eL, 0xbd66c9bd6925a46dL, 0x9ad3e98d51cedd5cL, 0xa088bec844766815L, 0x1d16f16417336799L, 0x00843b5b4af3c914L });
        CURVE_IBZ[3][2] = Ibz.fromMpLimbs(6, new long[]{ 0x9620bc14408822c1L, 0xda12008977ec7d53L, 0x6092b925380654dfL, 0x9617341959e3d1b4L, 0xb452f00848a99ae6L, 0x00499c5d35cb9756L });
        CURVE_IBZ[3][3] = Ibz.fromMpLimbs(6, new long[]{ 0xf5114bae16e9b001L, 0xe665489905d33a7fL, 0xb82255e4c90d575fL, 0x3b3e4e45d90a4cb0L, 0xf085de02030752b2L, 0x006bd4f7b32dd5c9L });
        CURVE_IBZ[3][4] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[3][5] = Ibz.fromMpLimbs(6, new long[]{ 0x1f58fab72e0af28eL, 0x28d439c3024311eaL, 0x4d873aec1878e1baL, 0x7416a312354af832L, 0x78d2162768ee0b5bL, 0x00d11cb2152ffbbcL });
        CURVE_IBZ[3][6] = Ibz.fromMpLimbs(6, new long[]{ 0xdd4b424688763134L, 0x2d3371e886b187d0L, 0xf6d66377e6d8fe04L, 0x521e29d48b91dd4fL, 0x8c9c2eb9a1d53822L, 0x00112d4cab9f35a1L });
        CURVE_IBZ[3][7] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[3][8] = Ibz.fromMpLimbs(6, new long[]{ 0xdd24bb2d4195afa5L, 0x2ccbf995c678a3caL, 0x1f9b0d06f9ff5c3bL, 0x24f228814e3b926dL, 0x24cba38d8e9acf4cL, 0x00de581c28a1e8f2L });
        CURVE_IBZ[3][9] = Ibz.fromMpLimbs(6, new long[]{ 0xb5a8593c9ceacd88L, 0xfb85496fc07c79c6L, 0xfa59f4f8381c5ac9L, 0x67c824c25caab7a3L, 0xb89fbe8a758531b3L, 0x0025c1566cd5a29fL });
        CURVE_IBZ[3][10] = Ibz.fromMpLimbs(6, new long[]{ 0x73de9200d2979627L, 0x2d4599c7f44faa89L, 0x976f4168ab2bb1ebL, 0x66482f3977771e88L, 0x861bb815d5a1c224L, 0x00be4123b476f76fL });
        CURVE_IBZ[3][11] = Ibz.fromMpLimbs(6, new long[]{ 0x22db44d2be6a505bL, 0xd334066a39875c35L, 0xe064f2f90600a3c4L, 0xdb0dd77eb1c46d92L, 0xdb345c72716530b3L, 0x0021a7e3d75e170dL });
        CURVE_IBZ[3][12] = Ibz.fromMpLimbs(6, new long[]{ 0x0aeeb451e9164fffL, 0x199ab766fa2cc580L, 0x47ddaa1b36f2a8a0L, 0xc4c1b1ba26f5b34fL, 0x0f7a21fdfcf8ad4dL, 0x00942b084cd22a36L });
        CURVE_IBZ[3][13] = Ibz.fromMpLimbs(6, new long[]{ 0xe2aee09f5176f16eL, 0xbd66c9bd6925a46dL, 0x9ad3e98d51cedd5cL, 0xa088bec844766815L, 0x1d16f16417336799L, 0x00843b5b4af3c914L });
        CURVE_IBZ[3][14] = Ibz.fromMpLimbs(6, new long[]{ 0x9620bc14408822c1L, 0xda12008977ec7d53L, 0x6092b925380654dfL, 0x9617341959e3d1b4L, 0xb452f00848a99ae6L, 0x00499c5d35cb9756L });
        CURVE_IBZ[3][15] = Ibz.fromMpLimbs(6, new long[]{ 0xf5114bae16e9b001L, 0xe665489905d33a7fL, 0xb82255e4c90d575fL, 0x3b3e4e45d90a4cb0L, 0xf085de02030752b2L, 0x006bd4f7b32dd5c9L });
        CURVE_IBZ[3][16] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[3][17] = Ibz.fromMpLimbs(6, new long[]{ 0x0fac7d5b97057947L, 0x146a1ce1812188f5L, 0x26c39d760c3c70ddL, 0xba0b51891aa57c19L, 0x3c690b13b47705adL, 0x00688e590a97fddeL });
        CURVE_IBZ[3][18] = Ibz.fromMpLimbs(6, new long[]{ 0x6ea5a123443b189aL, 0x1699b8f44358c3e8L, 0xfb6b31bbf36c7f02L, 0x290f14ea45c8eea7L, 0xc64e175cd0ea9c11L, 0x000896a655cf9ad0L });
        CURVE_IBZ[3][19] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });
        CURVE_IBZ[3][20] = Ibz.fromMpLimbs(6, new long[]{ 0xc215682a55d843c6L, 0x118205ceac4c706eL, 0x6a11f04f90e38b72L, 0x5d3f45b03488c345L, 0x8d467b209896556bL, 0x00bad4287b0ca9e3L });
        CURVE_IBZ[3][21] = Ibz.fromMpLimbs(6, new long[]{ 0xedb9243cf9ad91a5L, 0x3592d6d7ce5fc4f5L, 0xe2971489dead40dfL, 0x9e1fda9dee4d55b1L, 0xa5856c6bd99a4a5cL, 0x00c0c1ad438362fcL });
        CURVE_IBZ[3][22] = Ibz.fromMpLimbs(6, new long[]{ 0x2fc421816191f454L, 0x9b1c7bb6c44f66fbL, 0xf8f9b1a3ee09099fL, 0x4e44595c5151f234L, 0x25f69930305ca80aL, 0x00b8ff4db8128e50L });
        CURVE_IBZ[3][23] = Ibz.fromMpLimbs(6, new long[]{ 0x3dea97d5aa27bc3aL, 0xee7dfa3153b38f91L, 0x95ee0fb06f1c748dL, 0xa2c0ba4fcb773cbaL, 0x72b984df6769aa94L, 0x00452bd784f3561cL });

        // ---- Entry [4] ----
        CURVE_FP[4][0] = new BigInteger("1ddffea847f8d02445f39b0174d2ccb24bc27324f2afc77ddb7a466b42fb16bc69ed22f5c36a499bba42bcdd15a525e", 16);
        CURVE_FP[4][1] = BigInteger.ZERO;
        CURVE_FP[4][2] = BigInteger.ONE;
        CURVE_FP[4][3] = BigInteger.ZERO;
        CURVE_FP[4][4] = new BigInteger("777ffaa11fe3409117ce6c05d34b32c92f09cc93cabf1df76de919ad0bec5af1a7b48bd70da9266ee90af374569498", 16);
        CURVE_FP[4][5] = BigInteger.ZERO;
        CURVE_FP[4][6] = BigInteger.ONE;
        CURVE_FP[4][7] = BigInteger.ZERO;
        CURVE_FP[4][8] = new BigInteger("3d206f36d227c98a40efa13df8952c7c84e31747e50d48d22427c5504601860696cace60c6058a2014069ce4d4f7160b", 16);
        CURVE_FP[4][9] = new BigInteger("34780cd90a37be10f4ab9d8afe989a272f1ef463559b155e34bb3cf2a88931c5c87b0a931bc9a63491a1e10ddc4c9c4", 16);
        CURVE_FP[4][10] = BigInteger.ONE;
        CURVE_FP[4][11] = BigInteger.ZERO;
        CURVE_FP[4][12] = new BigInteger("9950940d79a3350da666608f70a6a78c2249d65691603129eb09d64491a521dbb1583862e7f2a2b5df531ebedf8d944", 16);
        CURVE_FP[4][13] = new BigInteger("15d5ffaa38e1333e641422b18c08568a73bce66d820bc8585ef92a5be9da5e668c801097e67bc68874188117510ac470", 16);
        CURVE_FP[4][14] = BigInteger.ONE;
        CURVE_FP[4][15] = BigInteger.ZERO;
        CURVE_FP[4][16] = new BigInteger("10dd167883dc0870d0841536bb71786ee68180dcb8befed140aab417c823b2932f0502476dc8fdbcb892cb51e519a964", 16);
        CURVE_FP[4][17] = new BigInteger("26316224245afc928a68473135dccfdc44cf12b3e7c8617ad63b20b2beefb00b2998276a8466d13bb6f7048b645142e3", 16);
        CURVE_FP[4][18] = BigInteger.ONE;
        CURVE_FP[4][19] = BigInteger.ZERO;
        CURVE_IBZ[4][0] = Ibz.fromMpLimbs(6, new long[]{ 0xb571a2d59ad4807fL, 0x2fdebc369682e39aL, 0x49c9209255a980a1L, 0xde6774117a754269L, 0x7b89af23968975d6L, 0x001a276f60e4819bL });
        CURVE_IBZ[4][1] = Ibz.fromMpLimbs(6, new long[]{ 0x49abd2f90218c876L, 0xf9814dc41ab33ef7L, 0xc5e112c5db9c381aL, 0x53699d31c1485b21L, 0x1c7dcf6322775706L, 0x004bcd50d481e151L });
        CURVE_IBZ[4][2] = Ibz.fromMpLimbs(6, new long[]{ 0x78cc570898ac2191L, 0x4c130168e9c963faL, 0xd629d010e2be19e6L, 0xed3e7c2b3b08f3ffL, 0xa0f5253b5d94356eL, 0x00639dac60d4c652L });
        CURVE_IBZ[4][3] = Ibz.fromMpLimbs(6, new long[]{ 0x4a8e5d2a652b7f81L, 0xd02143c9697d1c65L, 0xb636df6daa567f5eL, 0x21988bee858abd96L, 0x847650dc69768a29L, 0x00e5d8909f1b7e64L });
        CURVE_IBZ[4][4] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[4][5] = Ibz.fromMpLimbs(6, new long[]{ 0xe0a70548d1f50d72L, 0xd72bc63cfdbcee15L, 0xb278c513e7871e45L, 0x8be95cedcab507cdL, 0x872de9d89711f4a4L, 0x002ee34dead00443L });
        CURVE_IBZ[4][6] = Ibz.fromMpLimbs(6, new long[]{ 0x22b4bdb97789ceccL, 0xd2cc8e17794e782fL, 0x09299c88192701fbL, 0xade1d62b746e22b0L, 0x7363d1465e2ac7ddL, 0x00eed2b35460ca5eL });
        CURVE_IBZ[4][7] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[4][8] = Ibz.fromMpLimbs(6, new long[]{ 0x406d812ac18a313bL, 0xb0309f079fca472aL, 0x9e992af679248b7bL, 0x59c835ee8eb82b81L, 0x03265aaf34cc7655L, 0x006e969af8b7e58dL });
        CURVE_IBZ[4][9] = Ibz.fromMpLimbs(6, new long[]{ 0xcf39b147fd896610L, 0x8470ed644ccf2b02L, 0xf0748c781891aaf6L, 0xf52bd66cfaed8a4cL, 0x46f805cd0b0af1c5L, 0x00d9451d81de79a3L });
        CURVE_IBZ[4][10] = Ibz.fromMpLimbs(6, new long[]{ 0x7d0f425c2ce01869L, 0xfb41d5621c3e30c8L, 0xb2659c8aeccc3951L, 0x2cbf3c42d8790829L, 0x7fdfee28d9d3b1d2L, 0x003ba6d903adccddL });
        CURVE_IBZ[4][11] = Ibz.fromMpLimbs(6, new long[]{ 0xbf927ed53e75cec5L, 0x4fcf60f86035b8d5L, 0x6166d50986db7484L, 0xa637ca117147d47eL, 0xfcd9a550cb3389aaL, 0x0091696507481a72L });
        CURVE_IBZ[4][12] = Ibz.fromMpLimbs(6, new long[]{ 0xb571a2d59ad4807fL, 0x2fdebc369682e39aL, 0x49c9209255a980a1L, 0xde6774117a754269L, 0x7b89af23968975d6L, 0x001a276f60e4819bL });
        CURVE_IBZ[4][13] = Ibz.fromMpLimbs(6, new long[]{ 0x49abd2f90218c876L, 0xf9814dc41ab33ef7L, 0xc5e112c5db9c381aL, 0x53699d31c1485b21L, 0x1c7dcf6322775706L, 0x004bcd50d481e151L });
        CURVE_IBZ[4][14] = Ibz.fromMpLimbs(6, new long[]{ 0x78cc570898ac2191L, 0x4c130168e9c963faL, 0xd629d010e2be19e6L, 0xed3e7c2b3b08f3ffL, 0xa0f5253b5d94356eL, 0x00639dac60d4c652L });
        CURVE_IBZ[4][15] = Ibz.fromMpLimbs(6, new long[]{ 0x4a8e5d2a652b7f81L, 0xd02143c9697d1c65L, 0xb636df6daa567f5eL, 0x21988bee858abd96L, 0x847650dc69768a29L, 0x00e5d8909f1b7e64L });
        CURVE_IBZ[4][16] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });
        CURVE_IBZ[4][17] = Ibz.fromMpLimbs(6, new long[]{ 0xf05382a468fa86b9L, 0xeb95e31e7ede770aL, 0xd93c6289f3c38f22L, 0x45f4ae76e55a83e6L, 0xc396f4ec4b88fa52L, 0x009771a6f5680221L });
        CURVE_IBZ[4][18] = Ibz.fromMpLimbs(6, new long[]{ 0x915a5edcbbc4e766L, 0xe966470bbca73c17L, 0x0494ce440c9380fdL, 0xd6f0eb15ba371158L, 0x39b1e8a32f1563eeL, 0x00f76959aa30652fL });
        CURVE_IBZ[4][19] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[4][20] = Ibz.fromMpLimbs(6, new long[]{ 0x26a62ef17abe29a3L, 0xb56ff4c854e6a5a5L, 0x94edd9ba1aae2baeL, 0x6f64c686882c2df5L, 0x617c9eee850a29f7L, 0x00868ebe31085678L });
        CURVE_IBZ[4][21] = Ibz.fromMpLimbs(6, new long[]{ 0xaa2b37298ce6c2a5L, 0xaf25e2bebf43b9d2L, 0x94c6f85aec8e4ffbL, 0x0f63f4ad3c64e027L, 0x2390de0fa24486baL, 0x0033cd4cdd7c11e1L });
        CURVE_IBZ[4][22] = Ibz.fromMpLimbs(6, new long[]{ 0x9df01eb8a4bf1893L, 0x6ba1e4ae17b091b1L, 0x82a8c03fd56b35fdL, 0x181ef3a330be99cdL, 0xed0e03e80518879bL, 0x0001e29ce2d6c0ffL });
        CURVE_IBZ[4][23] = Ibz.fromMpLimbs(6, new long[]{ 0xd959d10e8541d65dL, 0x4a900b37ab195a5aL, 0x6b122645e551d451L, 0x909b397977d3d20aL, 0x9e8361117af5d608L, 0x00797141cef7a987L });

        // ---- Entry [5] ----
        CURVE_FP[5][0] = new BigInteger("18a728086916705f4fb8e0970e17813812b539bd3680ae650f17e2fc022640048b15c474fa2285288e865271744f3df7", 16);
        CURVE_FP[5][1] = BigInteger.ZERO;
        CURVE_FP[5][2] = BigInteger.ONE;
        CURVE_FP[5][3] = BigInteger.ZERO;
        CURVE_FP[5][4] = new BigInteger("1669ca021a459c17d3ee3825c385e04e04ad4e6f4da02b9943c5f8bf0089900122c5711d3e88a14a23a1949c5d13cf7e", 16);
        CURVE_FP[5][5] = BigInteger.ZERO;
        CURVE_FP[5][6] = BigInteger.ONE;
        CURVE_FP[5][7] = BigInteger.ZERO;
        CURVE_FP[5][8] = new BigInteger("104e91795ae4a93744887fb6776bb92d12a496cb05b9d9b61b08085bd48fc08a99dcc6ab8086c0e4aa9b08d3ad0aa476", 16);
        CURVE_FP[5][9] = new BigInteger("40d1a46611835e16268036ac2e29f714bf0870f43614cc16539d036753231f3358cb58af263c899c7fbe954be75ea70e", 16);
        CURVE_FP[5][10] = BigInteger.ONE;
        CURVE_FP[5][11] = BigInteger.ZERO;
        CURVE_FP[5][12] = new BigInteger("2fa8a3edd4e0837e45e2388b59aec31a017ea6928061e5275e9d158cbc2ad75b13bd7adfd160f02a51873acd7efbda88", 16);
        CURVE_FP[5][13] = new BigInteger("192b593c82766cfcaeda2fab695c4b3351158e6d45aa9d075e20d3e5f496058118288bff16230596cd8324a5c6441496", 16);
        CURVE_FP[5][14] = BigInteger.ONE;
        CURVE_FP[5][15] = BigInteger.ZERO;
        CURVE_FP[5][16] = new BigInteger("19acb9f3877b54480487eccfd9fc382fb47f619ac33bbc7c5344021fb906215c28b78eae3fcf9f475968ec2e4ae2c145", 16);
        CURVE_FP[5][17] = new BigInteger("116c21493a5e6cb459b1a4f312272d72bf60ce5b9ca77cc87b47fa2a725e0ffa131ea4f16bf0874d18585fbe8d7b1171", 16);
        CURVE_FP[5][18] = BigInteger.ONE;
        CURVE_FP[5][19] = BigInteger.ZERO;
        CURVE_IBZ[5][0] = Ibz.fromMpLimbs(6, new long[]{ 0x13678d5e8a5a5419L, 0xab31cf473903ae77L, 0x2055ed739219f30cL, 0x4d6f70464098cc84L, 0xd5ed0224e6415c68L, 0x00e415c8dfcd977aL });
        CURVE_IBZ[5][1] = Ibz.fromMpLimbs(6, new long[]{ 0x7e1741ba29a592eaL, 0x1b0d4b64aeb2033cL, 0x15542d2ee57e04beL, 0x7d2a4267ea1ee7f7L, 0x147ac388d23417cdL, 0x004f83bdaa6343e6L });
        CURVE_IBZ[5][2] = Ibz.fromMpLimbs(6, new long[]{ 0x465e819c5b17a8b7L, 0x095391c3b2a1a6fbL, 0x75bac3674ed40486L, 0xe751e242115fcc01L, 0x950a4ec0bf534748L, 0x007dec827ea2e08eL });
        CURVE_IBZ[5][3] = Ibz.fromMpLimbs(6, new long[]{ 0xec9872a175a5abe7L, 0x54ce30b8c6fc5188L, 0xdfaa128c6de60cf3L, 0xb2908fb9bf67337bL, 0x2a12fddb19bea397L, 0x001bea3720326885L });
        CURVE_IBZ[5][4] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[5][5] = Ibz.fromMpLimbs(6, new long[]{ 0x1f58fab72e0af28eL, 0x28d439c3024311eaL, 0x4d873aec1878e1baL, 0x7416a312354af832L, 0x78d2162768ee0b5bL, 0x00d11cb2152ffbbcL });
        CURVE_IBZ[5][6] = Ibz.fromMpLimbs(6, new long[]{ 0xdd4b424688763134L, 0x2d3371e886b187d0L, 0xf6d66377e6d8fe04L, 0x521e29d48b91dd4fL, 0x8c9c2eb9a1d53822L, 0x00112d4cab9f35a1L });
        CURVE_IBZ[5][7] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[5][8] = Ibz.fromMpLimbs(6, new long[]{ 0xbcf8e89ee86d0703L, 0xe8ec9f65e250675bL, 0x192a475111ca2c83L, 0x4f40eb89f46af9d8L, 0x13f9fff90dcf2a2cL, 0x0006b9af834824e7L });
        CURVE_IBZ[5][9] = Ibz.fromMpLimbs(6, new long[]{ 0x6598f9c7b5481e40L, 0x2ef26cbf25c67e33L, 0xf320aef2dd99a630L, 0x2f7c454193a704a2L, 0x52a924f41a7abf45L, 0x00b09d37a12ad3b4L });
        CURVE_IBZ[5][10] = Ibz.fromMpLimbs(6, new long[]{ 0x83d43774228301e1L, 0xde59279001fcf33fL, 0x65742c1bc942e89dL, 0xbb0a9f113a3c55b1L, 0xc94cff9d0a696813L, 0x00a918c6ce6bdedeL });
        CURVE_IBZ[5][11] = Ibz.fromMpLimbs(6, new long[]{ 0x430717611792f8fdL, 0x1713609a1daf98a4L, 0xe6d5b8aeee35d37cL, 0xb0bf14760b950627L, 0xec060006f230d5d3L, 0x00f946507cb7db18L });
        CURVE_IBZ[5][12] = Ibz.fromMpLimbs(6, new long[]{ 0x13678d5e8a5a5419L, 0xab31cf473903ae77L, 0x2055ed739219f30cL, 0x4d6f70464098cc84L, 0xd5ed0224e6415c68L, 0x00e415c8dfcd977aL });
        CURVE_IBZ[5][13] = Ibz.fromMpLimbs(6, new long[]{ 0x7e1741ba29a592eaL, 0x1b0d4b64aeb2033cL, 0x15542d2ee57e04beL, 0x7d2a4267ea1ee7f7L, 0x147ac388d23417cdL, 0x004f83bdaa6343e6L });
        CURVE_IBZ[5][14] = Ibz.fromMpLimbs(6, new long[]{ 0x465e819c5b17a8b7L, 0x095391c3b2a1a6fbL, 0x75bac3674ed40486L, 0xe751e242115fcc01L, 0x950a4ec0bf534748L, 0x007dec827ea2e08eL });
        CURVE_IBZ[5][15] = Ibz.fromMpLimbs(6, new long[]{ 0xec9872a175a5abe7L, 0x54ce30b8c6fc5188L, 0xdfaa128c6de60cf3L, 0xb2908fb9bf67337bL, 0x2a12fddb19bea397L, 0x001bea3720326885L });
        CURVE_IBZ[5][16] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[5][17] = Ibz.fromMpLimbs(6, new long[]{ 0x0fac7d5b97057947L, 0x146a1ce1812188f5L, 0x26c39d760c3c70ddL, 0xba0b51891aa57c19L, 0x3c690b13b47705adL, 0x00688e590a97fddeL });
        CURVE_IBZ[5][18] = Ibz.fromMpLimbs(6, new long[]{ 0x6ea5a123443b189aL, 0x1699b8f44358c3e8L, 0xfb6b31bbf36c7f02L, 0x290f14ea45c8eea7L, 0xc64e175cd0ea9c11L, 0x000896a655cf9ad0L });
        CURVE_IBZ[5][19] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });
        CURVE_IBZ[5][20] = Ibz.fromMpLimbs(6, new long[]{ 0x63b0421546e92d5dL, 0x697080aadc918358L, 0xe4eac13a266d4e7dL, 0x119bdbafbc38504eL, 0x7b9098db45d8a3ccL, 0x00083676de6a3a5bL });
        CURVE_IBZ[5][21] = Ibz.fromMpLimbs(6, new long[]{ 0x0c2e220b61ae1db1L, 0xf90c8697b16aa7eeL, 0xb6015cf8ced57505L, 0x57d09fdf27ad6235L, 0xb53a94dba6d20ca2L, 0x0092fe95a3ad8bd2L });
        CURVE_IBZ[5][22] = Ibz.fromMpLimbs(6, new long[]{ 0xf0abb393f0cfa809L, 0xb0ea1833b5bc181aL, 0x4f5cb2993088ff0eL, 0x9ffdad7b5b865a20L, 0x0989b8eb4e4c2216L, 0x00458e8fa798712fL });
        CURVE_IBZ[5][23] = Ibz.fromMpLimbs(6, new long[]{ 0x9c4fbdeab916d2a3L, 0x968f7f55236e7ca7L, 0x1b153ec5d992b182L, 0xee64245043c7afb1L, 0x846f6724ba275c33L, 0x00f7c9892195c5a4L });

        // ---- Entry [6] ----
        CURVE_FP[6][0] = new BigInteger("7b83c850b3a7c99a8e37049a0469a6881e923d3fb478c5ec76cd13eaf9e93524336d5945e6bb2558811f5f03e5dccf4", 16);
        CURVE_FP[6][1] = BigInteger.ZERO;
        CURVE_FP[6][2] = BigInteger.ONE;
        CURVE_FP[6][3] = BigInteger.ZERO;
        CURVE_FP[6][4] = new BigInteger("226e0f2142ce9f266a38dc126811a69a207a48f4fed1e317b1db344fabe7a4d490cdb565179aec9562047d7c0f97733d", 16);
        CURVE_FP[6][5] = BigInteger.ZERO;
        CURVE_FP[6][6] = BigInteger.ONE;
        CURVE_FP[6][7] = BigInteger.ZERO;
        CURVE_FP[6][8] = new BigInteger("3f4eab2e3ff47a9e48205072c7ca15d3df32e04926915a3bd76cac77b603bfc389f38d34aed22942558af2846f0643be", 16);
        CURVE_FP[6][9] = new BigInteger("cbb80bb3a02f4c433475bb0a2a5ca9feab29b7b2cc88a6c4e3fc10954318d2e7b38a1eeb6bbbc8c0f1492c80fcf1af2", 16);
        CURVE_FP[6][10] = BigInteger.ONE;
        CURVE_FP[6][11] = BigInteger.ZERO;
        CURVE_FP[6][12] = new BigInteger("ed1d6e8d4feae8a79364b2fc64fbfab8cd95483ed8cf54b71eafd9aa13801181acb59a76a85ef2298486b2bec6a494e", 16);
        CURVE_FP[6][13] = new BigInteger("840a5ac1e1721715139290efae097a0e67f90d40ec8f5e66de4e776168d5adc10cb3214d381974227520f9fd0fafe93", 16);
        CURVE_FP[6][14] = BigInteger.ONE;
        CURVE_FP[6][15] = BigInteger.ZERO;
        CURVE_FP[6][16] = new BigInteger("3fb170594ebc979e4aba0b0fc12b94874b8c6cb758b7bbccad1f88a2843694470ae021dd9c8e79fbc014849f2cbe7f11", 16);
        CURVE_FP[6][17] = new BigInteger("1dae099492f5d3573bd6554ca0f48360c7630806d4a4e5cad2558f7f59bc26a0c98eec2b9db72490095dd3ab7311e8ba", 16);
        CURVE_FP[6][18] = BigInteger.ONE;
        CURVE_FP[6][19] = BigInteger.ZERO;
        CURVE_IBZ[6][0] = Ibz.fromMpLimbs(6, new long[]{ 0xca8545c3a939c761L, 0x8e017d5be2f16b48L, 0x3fa131da1b34b824L, 0xe32fc0b8143aaae4L, 0x4e56d1422c290843L, 0x00c524cdc504d55cL });
        CURVE_IBZ[6][1] = Ibz.fromMpLimbs(6, new long[]{ 0x230889036127e87aL, 0xc898320912dcfbedL, 0x1078446f2ab80715L, 0xf92b34a924932808L, 0xd4adf8600a3a96f4L, 0x00e5626b410dc8a9L });
        CURVE_IBZ[6][2] = Ibz.fromMpLimbs(6, new long[]{ 0xdfff736ecd2ea06fL, 0xab167c39e69428f9L, 0xe8f648830bc421f5L, 0x8d46a9f1f3c3caaeL, 0x38385d95a8e216e4L, 0x00de94da34b7a6f1L });
        CURVE_IBZ[6][3] = Ibz.fromMpLimbs(6, new long[]{ 0x357aba3c56c6389fL, 0x71fe82a41d0e94b7L, 0xc05ece25e4cb47dbL, 0x1cd03f47ebc5551bL, 0xb1a92ebdd3d6f7bcL, 0x003adb323afb2aa3L });
        CURVE_IBZ[6][4] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[6][5] = Ibz.fromMpLimbs(6, new long[]{ 0xe0a70548d1f50d72L, 0xd72bc63cfdbcee15L, 0xb278c513e7871e45L, 0x8be95cedcab507cdL, 0x872de9d89711f4a4L, 0x002ee34dead00443L });
        CURVE_IBZ[6][6] = Ibz.fromMpLimbs(6, new long[]{ 0x22b4bdb97789ceccL, 0xd2cc8e17794e782fL, 0x09299c88192701fbL, 0xade1d62b746e22b0L, 0x7363d1465e2ac7ddL, 0x00eed2b35460ca5eL });
        CURVE_IBZ[6][7] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[6][8] = Ibz.fromMpLimbs(6, new long[]{ 0x7b39e1f06102ac65L, 0xd11b8256ff4d64beL, 0x66e7814c7a894645L, 0x1f42e691c4d8077aL, 0x18d90752547bfdb9L, 0x00ecbed4e6049279L });
        CURVE_IBZ[6][9] = Ibz.fromMpLimbs(6, new long[]{ 0x218d9e18e4773380L, 0x59e7b33f4cc5ddc6L, 0x92a28f77a1a1b291L, 0x5d4840f182af480eL, 0xff7acb9e422983b0L, 0x001671fc0a782e32L });
        CURVE_IBZ[6][10] = Ibz.fromMpLimbs(6, new long[]{ 0x2e59774eaa62bb17L, 0xbfdb874eebcee440L, 0x78aaded2a7ba3afdL, 0xa1de5633cfed7568L, 0xec25572757964c5eL, 0x00983f13ce9cac0aL });
        CURVE_IBZ[6][11] = Ibz.fromMpLimbs(6, new long[]{ 0x84c61e0f9efd539bL, 0x2ee47da900b29b41L, 0x99187eb38576b9baL, 0xe0bd196e3b27f885L, 0xe726f8adab840246L, 0x0013412b19fb6d86L });
        CURVE_IBZ[6][12] = Ibz.fromMpLimbs(6, new long[]{ 0xca8545c3a939c761L, 0x8e017d5be2f16b48L, 0x3fa131da1b34b824L, 0xe32fc0b8143aaae4L, 0x4e56d1422c290843L, 0x00c524cdc504d55cL });
        CURVE_IBZ[6][13] = Ibz.fromMpLimbs(6, new long[]{ 0x230889036127e87aL, 0xc898320912dcfbedL, 0x1078446f2ab80715L, 0xf92b34a924932808L, 0xd4adf8600a3a96f4L, 0x00e5626b410dc8a9L });
        CURVE_IBZ[6][14] = Ibz.fromMpLimbs(6, new long[]{ 0xdfff736ecd2ea06fL, 0xab167c39e69428f9L, 0xe8f648830bc421f5L, 0x8d46a9f1f3c3caaeL, 0x38385d95a8e216e4L, 0x00de94da34b7a6f1L });
        CURVE_IBZ[6][15] = Ibz.fromMpLimbs(6, new long[]{ 0x357aba3c56c6389fL, 0x71fe82a41d0e94b7L, 0xc05ece25e4cb47dbL, 0x1cd03f47ebc5551bL, 0xb1a92ebdd3d6f7bcL, 0x003adb323afb2aa3L });
        CURVE_IBZ[6][16] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });
        CURVE_IBZ[6][17] = Ibz.fromMpLimbs(6, new long[]{ 0xf05382a468fa86b9L, 0xeb95e31e7ede770aL, 0xd93c6289f3c38f22L, 0x45f4ae76e55a83e6L, 0xc396f4ec4b88fa52L, 0x009771a6f5680221L });
        CURVE_IBZ[6][18] = Ibz.fromMpLimbs(6, new long[]{ 0x915a5edcbbc4e766L, 0xe966470bbca73c17L, 0x0494ce440c9380fdL, 0xd6f0eb15ba371158L, 0x39b1e8a32f1563eeL, 0x00f76959aa30652fL });
        CURVE_IBZ[6][19] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[6][20] = Ibz.fromMpLimbs(6, new long[]{ 0x81f8eb7fcfadb919L, 0xdd384300f2724d97L, 0x3e43189408261b01L, 0x7c6341610a847310L, 0xadc9e47596250ec4L, 0x007eb7e3fa6a05a7L });
        CURVE_IBZ[6][21] = Ibz.fromMpLimbs(6, new long[]{ 0x2e519d21ade41e83L, 0xe0a8ac7900d342e5L, 0xc941b504fcf232e2L, 0x333154858016a0d0L, 0x0ef5f76ec296abd7L, 0x0056165c8e31ce39L });
        CURVE_IBZ[6][22] = Ibz.fromMpLimbs(6, new long[]{ 0xf5d9fbdb6e27dd11L, 0x07a4c59a9fefd6cbL, 0xd0910bc25c3e0fbdL, 0x93fa193ec9d06546L, 0xbbe3decd27630776L, 0x006690706abfcec1L });
        CURVE_IBZ[6][23] = Ibz.fromMpLimbs(6, new long[]{ 0x7e071480305246e7L, 0x22c7bcff0d8db268L, 0xc1bce76bf7d9e4feL, 0x839cbe9ef57b8cefL, 0x52361b8a69daf13bL, 0x0081481c0595fa58L });

        // ---- Entry [7] ----
        CURVE_FP[7][0] = new BigInteger("e1cf0b0f3aeffb184da40bde4de1b91090ddc4e9797214467bf39ef7ac742dcd42c57a75d8b6c74ee41fcdad41f7152", 16);
        CURVE_FP[7][1] = BigInteger.ZERO;
        CURVE_FP[7][2] = BigInteger.ONE;
        CURVE_FP[7][3] = BigInteger.ZERO;
        CURVE_FP[7][4] = new BigInteger("3873c2c3cebbfec6136902f793786e442437713a5e5c85119efce7bdeb1d0b7350b15e9d762db1d3b907f36b507dc55", 16);
        CURVE_FP[7][5] = BigInteger.ZERO;
        CURVE_FP[7][6] = BigInteger.ONE;
        CURVE_FP[7][7] = BigInteger.ZERO;
        CURVE_FP[7][8] = new BigInteger("14e0b6528a91049989ef7329b57e0a9f5fcc674cb5de18bcff8ef4ae58070856e575be90407c741a1838d61629f16a3e", 16);
        CURVE_FP[7][9] = new BigInteger("c3b3581fe4118059519fb35d768f5f6b9feaa0750ccb58f642d9ed7e8a26fde43d3707ea87469fa5e98e65d27e10547", 16);
        CURVE_FP[7][10] = BigInteger.ONE;
        CURVE_FP[7][11] = BigInteger.ZERO;
        CURVE_FP[7][12] = new BigInteger("33cdd71b63ffbc58f7745eab63a369034a234453b9b5ad5d88083237dc1e6d2f50da8e0bc18d7c5b18352770fedcda94", 16);
        CURVE_FP[7][13] = new BigInteger("14c27dd58f013621b008c02976a4295b1cdd078081e18c5c36b00dacf8e519e149981589ed672a45860a62bf8f43e15b", 16);
        CURVE_FP[7][14] = BigInteger.ONE;
        CURVE_FP[7][15] = BigInteger.ZERO;
        CURVE_FP[7][16] = new BigInteger("a3a209466a9e666cb657c98d95bede1b1f7c67939a3371862a2402be03db3d80c4dbdaa592d72b1d846e7a9cd0b3e6c", 16);
        CURVE_FP[7][17] = new BigInteger("401eed10c2d0fcca4b1eed924c85661a848de0a16051f1b83b09a9fa6eb4ea3455aa5cce2bcac6c43e1f4a48f6028e1d", 16);
        CURVE_FP[7][18] = BigInteger.ONE;
        CURVE_FP[7][19] = BigInteger.ZERO;
        CURVE_IBZ[7][0] = Ibz.fromMpLimbs(6, new long[]{ 0x986de2a736f400e7L, 0x49f77818f464214bL, 0x85a09e1773e75ea0L, 0xbb287833c33dd1ccL, 0x879ed73c69d5ba60L, 0x00c8eefd09056732L });
        CURVE_IBZ[7][1] = Ibz.fromMpLimbs(6, new long[]{ 0x2effa6dcff6f925eL, 0x6829ab24e88cb2a6L, 0x850677ac011891ebL, 0xfd155cac5a869934L, 0xcdefebcfc2325869L, 0x0096cc7bf9e40254L });
        CURVE_IBZ[7][2] = Ibz.fromMpLimbs(6, new long[]{ 0x7829178ced4dae19L, 0xebc6dab348087b15L, 0x3d5ee9bd329825cbL, 0xb3ea92e60960e9a4L, 0xbdb92343f491033eL, 0x0041767f63a5a17dL });
        CURVE_IBZ[7][3] = Ibz.fromMpLimbs(6, new long[]{ 0x67921d58c90bff19L, 0xb60887e70b9bdeb4L, 0x7a5f61e88c18a15fL, 0x44d787cc3cc22e33L, 0x786128c3962a459fL, 0x00371102f6fa98cdL });
        CURVE_IBZ[7][4] = Ibz.fromMpLimbs(6, new long[]{ 0x157d66706268a74dL, 0x62fb13f3bff536bfL, 0xada5b7a3863b404bL, 0x7d756b4cc945355fL, 0xba3e4c9089019efdL, 0x009349eb567748f0L });
        CURVE_IBZ[7][5] = Ibz.fromMpLimbs(6, new long[]{ 0xe0a70548d1f50d72L, 0xd72bc63cfdbcee15L, 0xb278c513e7871e45L, 0x8be95cedcab507cdL, 0x872de9d89711f4a4L, 0x002ee34dead00443L });
        CURVE_IBZ[7][6] = Ibz.fromMpLimbs(6, new long[]{ 0x22b4bdb97789ceccL, 0xd2cc8e17794e782fL, 0x09299c88192701fbL, 0xade1d62b746e22b0L, 0x7363d1465e2ac7ddL, 0x00eed2b35460ca5eL });
        CURVE_IBZ[7][7] = Ibz.fromMpLimbs(6, new long[]{ 0xea82998f9d9758b3L, 0x9d04ec0c400ac940L, 0x525a485c79c4bfb4L, 0x828a94b336bacaa0L, 0x45c1b36f76fe6102L, 0x006cb614a988b70fL });
        CURVE_IBZ[7][8] = Ibz.fromMpLimbs(6, new long[]{ 0xd58ff501dad13d63L, 0xb3b9f8bdd2658741L, 0xbcdf45abfc8bac08L, 0x102f10ed09f70501L, 0x8db4f892dc57c6e3L, 0x008e2bc321ab2c76L });
        CURVE_IBZ[7][9] = Ibz.fromMpLimbs(6, new long[]{ 0x2354a8e4418cc998L, 0xdad95487b76d622aL, 0xdfa5a00f522b1672L, 0x91e1595ee17c296bL, 0x9288904ce126a22dL, 0x00b161b0c6c55075L });
        CURVE_IBZ[7][10] = Ibz.fromMpLimbs(6, new long[]{ 0x35fa16ee594e1271L, 0x24b71fca11b2af0eL, 0x6409c2f02bcca3e3L, 0xe7ee067e6a8ff8e1L, 0x5e0a68132b9aad00L, 0x00b3bd1d48f56decL });
        CURVE_IBZ[7][11] = Ibz.fromMpLimbs(6, new long[]{ 0x2a700afe252ec29dL, 0x4c4607422d9a78beL, 0x4320ba54037453f7L, 0xefd0ef12f608fafeL, 0x724b076d23a8391cL, 0x0071d43cde54d389L });
        CURVE_IBZ[7][12] = Ibz.fromMpLimbs(6, new long[]{ 0x986de2a736f400e7L, 0x49f77818f464214bL, 0x85a09e1773e75ea0L, 0xbb287833c33dd1ccL, 0x879ed73c69d5ba60L, 0x00c8eefd09056732L });
        CURVE_IBZ[7][13] = Ibz.fromMpLimbs(6, new long[]{ 0x2effa6dcff6f925eL, 0x6829ab24e88cb2a6L, 0x850677ac011891ebL, 0xfd155cac5a869934L, 0xcdefebcfc2325869L, 0x0096cc7bf9e40254L });
        CURVE_IBZ[7][14] = Ibz.fromMpLimbs(6, new long[]{ 0x7829178ced4dae19L, 0xebc6dab348087b15L, 0x3d5ee9bd329825cbL, 0xb3ea92e60960e9a4L, 0xbdb92343f491033eL, 0x0041767f63a5a17dL });
        CURVE_IBZ[7][15] = Ibz.fromMpLimbs(6, new long[]{ 0x67921d58c90bff19L, 0xb60887e70b9bdeb4L, 0x7a5f61e88c18a15fL, 0x44d787cc3cc22e33L, 0x786128c3962a459fL, 0x00371102f6fa98cdL });
        CURVE_IBZ[7][16] = Ibz.fromMpLimbs(6, new long[]{ 0x8abeb338313453a7L, 0xb17d89f9dffa9b5fL, 0xd6d2dbd1c31da025L, 0xbebab5a664a29aafL, 0x5d1f26484480cf7eL, 0x00c9a4f5ab3ba478L });
        CURVE_IBZ[7][17] = Ibz.fromMpLimbs(6, new long[]{ 0xf05382a468fa86b9L, 0xeb95e31e7ede770aL, 0xd93c6289f3c38f22L, 0x45f4ae76e55a83e6L, 0xc396f4ec4b88fa52L, 0x009771a6f5680221L });
        CURVE_IBZ[7][18] = Ibz.fromMpLimbs(6, new long[]{ 0x915a5edcbbc4e766L, 0xe966470bbca73c17L, 0x0494ce440c9380fdL, 0xd6f0eb15ba371158L, 0x39b1e8a32f1563eeL, 0x00f76959aa30652fL });
        CURVE_IBZ[7][19] = Ibz.fromMpLimbs(6, new long[]{ 0x75414cc7cecbac5aL, 0x4e827606200564a0L, 0x292d242e3ce25fdaL, 0x41454a599b5d6550L, 0xa2e0d9b7bb7f3081L, 0x00365b0a54c45b87L });
        CURVE_IBZ[7][20] = Ibz.fromMpLimbs(6, new long[]{ 0x7483a55131e4d70dL, 0x085f6a80034d6f09L, 0x38d20188e29b6b11L, 0xddc8c423a241085bL, 0x7cf7f3a417223260L, 0x00c6eeb9795536e8L });
        CURVE_IBZ[7][21] = Ibz.fromMpLimbs(6, new long[]{ 0xf65bd42f8f5359a9L, 0x8428954344757134L, 0xe15d7bfb7d454555L, 0x88eaf17f24ece9c2L, 0x27712b42bf2d766cL, 0x00c9fa62d0405dfcL });
        CURVE_IBZ[7][22] = Ibz.fromMpLimbs(6, new long[]{ 0x91ca8c5289b04b49L, 0x082d0453d527ed1bL, 0x58163790b6bfb0ebL, 0x5530ffc6a0a749bbL, 0x6f5152c412bb23b9L, 0x00c6723d062d25fdL });
        CURVE_IBZ[7][23] = Ibz.fromMpLimbs(6, new long[]{ 0x8b7c5aaece1b28f3L, 0xf7a0957ffcb290f6L, 0xc72dfe771d6494eeL, 0x22373bdc5dbef7a4L, 0x83080c5be8ddcd9fL, 0x0039114686aac917L });

    }

    private EndomorphismActionLvl3()
    {
    }
}
