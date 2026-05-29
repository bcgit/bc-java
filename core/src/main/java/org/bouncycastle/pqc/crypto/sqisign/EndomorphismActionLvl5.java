package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Java mirror of {@code CURVES_WITH_ENDOMORPHISMS[7]} from
 * {@code src/precomp/ref/lvl5/endomorphism_action.c}.
 *
 * <p>This level holds 7 entries (primary curve E₀ at index 0 plus
 * 6 alternate starting curves). Each entry contains 20 GF(p²)
 * field elements (curve A/C, A24 point, and basis_even P/Q/PmQ) plus 24
 * integer matrix entries (the six 2×2 action matrices for i, j, k, and
 * the three order generators).</p>
 *
 * <p>Fp values are stored as canonical {@link BigInteger} in {@code [0, p)},
 * having been mechanically Montgomery-decoded from the C reference's
 * 9-limb-of-57-bit representation at extractor time.</p>
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
final class EndomorphismActionLvl5
{
    public static final int NUM_CURVES = 7;
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
        CURVE_FP[0][4] = new BigInteger("d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16);
        CURVE_FP[0][5] = BigInteger.ZERO;
        CURVE_FP[0][6] = BigInteger.ONE;
        CURVE_FP[0][7] = BigInteger.ZERO;
        CURVE_FP[0][8] = new BigInteger("9fafe5085fcb1f13d5e487f010c8026abe233871b01f4a3587f06737f9bc686ba009922e2d459ec8f149c4c4083604e7842a612b6fdf8180025cdeb187b4c0", 16);
        CURVE_FP[0][9] = new BigInteger("c42a516ef3cf80d3e2e7a2d88faba1e46785ddce14f150ff4d204a43d47ad8d01940b2eba9aaac28b7198e48ed9281128f5782cdd197f48cddfbffe867063d", 16);
        CURVE_FP[0][10] = BigInteger.ONE;
        CURVE_FP[0][11] = BigInteger.ZERO;
        CURVE_FP[0][12] = new BigInteger("bce91be61859cd3ddcd3f8408657d1d43c6f2764437e66e96371e74bc4b725f0cb99b58b09a91e872afcebb4608219f68aa3572c70ef5e6e654099bfc8aa09", 16);
        CURVE_FP[0][13] = new BigInteger("a48c9987de3810adbf0813505a561e134f31d64466875f90e21dd7c6b44eb81bed0e58d70ebd39fd9443a7523049993bd75145d72ec8f52be58b7086fffbe8", 16);
        CURVE_FP[0][14] = BigInteger.ONE;
        CURVE_FP[0][15] = BigInteger.ZERO;
        CURVE_FP[0][16] = new BigInteger("2a3165c5061348beca06a8b4316633e6fb8f64fc96a2354b8fa271a9f539a4d336ee88c0e0a5a22de6eb125da3ddc872cc0a91a5277c7aaf98ffc3d75e2d34", 16);
        CURVE_FP[0][17] = new BigInteger("b27e86c1eff34ce8995a3b707f152e907a662ffec7e5df6ff23b36ef3329fb1ebd12f2b2bf3459806f7905d73a8287e41c04b3936734761950daca2d3b3b4f", 16);
        CURVE_FP[0][18] = BigInteger.ONE;
        CURVE_FP[0][19] = BigInteger.ZERO;
        CURVE_IBZ[0][0] = Ibz.fromMpLimbs(8, new long[]{ 0x892f96a886b93337L, 0xdf75c4974c8e9f38L, 0xd5435decd5b34fd7L, 0xa71e8de3d5c3f3dcL, 0x5af370731324d939L, 0x81d709d04122bb6bL, 0x6d855ea0387774deL, 0x00019df28f2d7c31L });
        CURVE_IBZ[0][1] = Ibz.fromMpLimbs(8, new long[]{ 0x2061e1c20cfd028eL, 0x716c40df3b18e412L, 0xebb9c041d980d025L, 0xa8fe17de4982bb45L, 0x2aa634d9ffe5b079L, 0x6bc39bab67872b0bL, 0xb57bf5123c037365L, 0x00089c9cf0b50897L });
        CURVE_IBZ[0][2] = Ibz.fromMpLimbs(8, new long[]{ 0xd85637b2429e45b1L, 0x81ba39cb86cd2f81L, 0xfbe40058ee7e771eL, 0x5bb87a7d28fb0a4bL, 0x3a9d2d541657a413L, 0x3069068975a3bbadL, 0xad392e812fddb0adL, 0x0007b5cb2bffd3cdL });
        CURVE_IBZ[0][3] = Ibz.fromMpLimbs(8, new long[]{ 0x76d069577946ccc9L, 0x208a3b68b37160c7L, 0x2abca2132a4cb028L, 0x58e1721c2a3c0c23L, 0xa50c8f8cecdb26c6L, 0x7e28f62fbedd4494L, 0x927aa15fc7888b21L, 0x000e620d70d283ceL });
        CURVE_IBZ[0][4] = Ibz.fromMpLimbs(8, new long[]{ 0xeb4fc9a677e020f3L, 0xa6e3ecb4ff68b334L, 0xf4eb9e8743c15015L, 0x80a093925f3722e7L, 0x75591be3670f9ea0L, 0x1519fa83900d2cb5L, 0x6dc4af3a4d7c67b8L, 0x00058d841e5112e1L });
        CURVE_IBZ[0][5] = Ibz.fromMpLimbs(8, new long[]{ 0x2fa66d21e4308e98L, 0x30ece5ebf0cf524fL, 0x47bf7d2f77113658L, 0x1ef4e7a6720cbbc5L, 0x471c59e52c25335fL, 0xa2a762d65d385e06L, 0x7a7a5e15defc65f3L, 0x000d7bb8c542dac4L });
        CURVE_IBZ[0][6] = Ibz.fromMpLimbs(8, new long[]{ 0x49e0ec61e4fe3249L, 0x08116ef6c4955b5fL, 0x608ebd6959fc4fdfL, 0x98ac5706e9a9afe2L, 0xecac9c4e481ab327L, 0x14a4faad640119faL, 0x97687eb53fb50edaL, 0x000bdc284c106597L });
        CURVE_IBZ[0][7] = Ibz.fromMpLimbs(8, new long[]{ 0x14b03659881fdf0dL, 0x591c134b00974ccbL, 0x0b146178bc3eafeaL, 0x7f5f6c6da0c8dd18L, 0x8aa6e41c98f0615fL, 0xeae6057c6ff2d34aL, 0x923b50c5b2839847L, 0x000a727be1aeed1eL });
        CURVE_IBZ[0][8] = Ibz.fromMpLimbs(8, new long[]{ 0x75f1d05088dbf3b3L, 0xe7a297c48cbe10ddL, 0x8d12d51ff1e2e6aeL, 0xc097c98a639555a8L, 0x78ce54f366aa60c3L, 0x03e199a77fb35dceL, 0x30f333393c9a8753L, 0x0007c99fc05e406eL });
        CURVE_IBZ[0][9] = Ibz.fromMpLimbs(8, new long[]{ 0xcae77bc01bf3bddeL, 0xbcb84b1a58a88d2eL, 0x4881fcf23d98ccd9L, 0x730d2e8a347366f8L, 0x58eadce94789abbfL, 0x328058d061690f54L, 0x23d267a05bd0e1f9L, 0x0007d51f18e12611L });
        CURVE_IBZ[0][10] = Ibz.fromMpLimbs(8, new long[]{ 0xea02939de36fee54L, 0x8bb39f39a7aee6dbL, 0xae5ea9abf5947f02L, 0xbecd0d9a7fc09a76L, 0xff9a30f48b68692dL, 0xc552bdfcfd43d1aeL, 0x981b33e5a4bffe0dL, 0x000c857345e8202cL });
        CURVE_IBZ[0][11] = Ibz.fromMpLimbs(8, new long[]{ 0x8a0e2faf77240c4dL, 0x185d683b7341ef22L, 0x72ed2ae00e1d1951L, 0x3f6836759c6aaa57L, 0x8731ab0c99559f3cL, 0xfc1e6658804ca231L, 0xcf0cccc6c36578acL, 0x000836603fa1bf91L });
        CURVE_IBZ[0][12] = Ibz.fromMpLimbs(8, new long[]{ 0x892f96a886b93337L, 0xdf75c4974c8e9f38L, 0xd5435decd5b34fd7L, 0xa71e8de3d5c3f3dcL, 0x5af370731324d939L, 0x81d709d04122bb6bL, 0x6d855ea0387774deL, 0x00019df28f2d7c31L });
        CURVE_IBZ[0][13] = Ibz.fromMpLimbs(8, new long[]{ 0x2061e1c20cfd028eL, 0x716c40df3b18e412L, 0xebb9c041d980d025L, 0xa8fe17de4982bb45L, 0x2aa634d9ffe5b079L, 0x6bc39bab67872b0bL, 0xb57bf5123c037365L, 0x00089c9cf0b50897L });
        CURVE_IBZ[0][14] = Ibz.fromMpLimbs(8, new long[]{ 0xd85637b2429e45b1L, 0x81ba39cb86cd2f81L, 0xfbe40058ee7e771eL, 0x5bb87a7d28fb0a4bL, 0x3a9d2d541657a413L, 0x3069068975a3bbadL, 0xad392e812fddb0adL, 0x0007b5cb2bffd3cdL });
        CURVE_IBZ[0][15] = Ibz.fromMpLimbs(8, new long[]{ 0x76d069577946ccc9L, 0x208a3b68b37160c7L, 0x2abca2132a4cb028L, 0x58e1721c2a3c0c23L, 0xa50c8f8cecdb26c6L, 0x7e28f62fbedd4494L, 0x927aa15fc7888b21L, 0x000e620d70d283ceL });
        CURVE_IBZ[0][16] = Ibz.fromMpLimbs(8, new long[]{ 0xba3fb0277f4caa15L, 0xc32cd8a625fba936L, 0x65177e3a0cba4ff6L, 0x13df90bb1a7d8b62L, 0x6826462b3d1a3bedL, 0x4b788229e897f410L, 0x6da506ed42f9ee4bL, 0x000b95bb56bf4789L });
        CURVE_IBZ[0][17] = Ibz.fromMpLimbs(8, new long[]{ 0xa8042771f896c893L, 0xd12c936595f41b30L, 0x99bc9eb8a849033eL, 0x63f97fc25dc7bb85L, 0xb8e1475f960571ecL, 0x87357f40e25fc488L, 0x17fb29940d7fecacL, 0x00030c2adafbf1aeL });
        CURVE_IBZ[0][18] = Ibz.fromMpLimbs(8, new long[]{ 0x911b920a13ce3bfdL, 0xc4e5d46125b14570L, 0x2e395ee1243d637eL, 0x7a3268c209525d17L, 0x13a4e4d12f392b9dL, 0xa287009b6cd26ad4L, 0xa250d69b37c95fc3L, 0x0001c8f9bc081cb2L });
        CURVE_IBZ[0][19] = Ibz.fromMpLimbs(8, new long[]{ 0x45c04fd880b355ebL, 0x3cd32759da0456c9L, 0x9ae881c5f345b009L, 0xec206f44e582749dL, 0x97d9b9d4c2e5c412L, 0xb4877dd617680befL, 0x925af912bd0611b4L, 0x00046a44a940b876L });
        CURVE_IBZ[0][20] = Ibz.fromMpLimbs(8, new long[]{ 0xbaf8e828446df9daL, 0x73d14be2465f086eL, 0x46896a8ff8f17357L, 0xe04be4c531caaad4L, 0x3c672a79b3553061L, 0x81f0ccd3bfd9aee7L, 0x1879999c9e4d43a9L, 0x000be4cfe02f2037L });
        CURVE_IBZ[0][21] = Ibz.fromMpLimbs(8, new long[]{ 0x6573bde00df9deefL, 0xde5c258d2c544697L, 0x2440fe791ecc666cL, 0xb98697451a39b37cL, 0x2c756e74a3c4d5dfL, 0x99402c6830b487aaL, 0x91e933d02de870fcL, 0x000bea8f8c709308L });
        CURVE_IBZ[0][22] = Ibz.fromMpLimbs(8, new long[]{ 0xf50149cef1b7f72aL, 0x45d9cf9cd3d7736dL, 0x572f54d5faca3f81L, 0xdf6686cd3fe04d3bL, 0x7fcd187a45b43496L, 0xe2a95efe7ea1e8d7L, 0x4c0d99f2d25fff06L, 0x000e42b9a2f41016L });
        CURVE_IBZ[0][23] = Ibz.fromMpLimbs(8, new long[]{ 0x450717d7bb920627L, 0x8c2eb41db9a0f791L, 0xb9769570070e8ca8L, 0x1fb41b3ace35552bL, 0xc398d5864caacf9eL, 0x7e0f332c40265118L, 0xe786666361b2bc56L, 0x00041b301fd0dfc8L });

        // ---- Entry [1] ----
        CURVE_FP[1][0] = new BigInteger("636b52cc874054cecd0ff39a40fd70436fb46d6de9f666ce3bb2417d75a22b9811eba8c7c16b3ffa64689725237650ed05e350e3ce8faaddf3156fe2a8acc5", 16);
        CURVE_FP[1][1] = BigInteger.ZERO;
        CURVE_FP[1][2] = BigInteger.ONE;
        CURVE_FP[1][3] = BigInteger.ZERO;
        CURVE_FP[1][4] = new BigInteger("15cdad4b321d01533b343fce6903f5c10dbed1b5b7a7d99b38eec905f5d688ae6047aea31f05acffe991a25c948dd943b4178d438f3a3eab77cc55bf8aa2b31", 16);
        CURVE_FP[1][5] = BigInteger.ZERO;
        CURVE_FP[1][6] = BigInteger.ONE;
        CURVE_FP[1][7] = BigInteger.ZERO;
        CURVE_FP[1][8] = new BigInteger("5202e80b3de80d412bad4c4f2687962739f6042fa1cd01e69b8b491ee6b167f18a479a19ba2eabbefb19ef1da9b0febc5d6a66a2c1e6bdf3bc7a9a6c1eae5", 16);
        CURVE_FP[1][9] = new BigInteger("687237978ffdbc9b2c00541dd6e87eda3edb3d3b63d01b120ab1eed2002c8a4b18594b9b18f90f9b92748cb3b7a438e265d6dc144e7cdef11978a43815a699", 16);
        CURVE_FP[1][10] = BigInteger.ONE;
        CURVE_FP[1][11] = BigInteger.ZERO;
        CURVE_FP[1][12] = new BigInteger("c3e3dcb7e5fe252fd5982d901866e017af10ac85642a5daf147f59aa919a544414b07376fa0816265f555cf2f26993923f95f33243174589a99395ee726c74", 16);
        CURVE_FP[1][13] = new BigInteger("6901db5b5750b8eae15abbc65cdccfa37f9963914303fc67f9b84fa2a59d96da664cf00d64127670bdc5f1963c7f780cec70bf7531952bb646ac9cb2672735", 16);
        CURVE_FP[1][14] = BigInteger.ONE;
        CURVE_FP[1][15] = BigInteger.ZERO;
        CURVE_FP[1][16] = new BigInteger("7fe235f4eb9a04c161e268bc311117c264ad0abd27283179264d8c71def10fdc7911ae9d8d80447aea8b89318b5cb7b69bb20d49edf6c8269ac7511fa0344f", 16);
        CURVE_FP[1][17] = new BigInteger("c3e8989e4f1a7cf58f954f03290ec51821a186a40d254085bc2f1157d3d4725bb73caeaa8fea4666ece83e12ebb1671dc5aa833aae5b910c21fcda8a45c67a", 16);
        CURVE_FP[1][18] = BigInteger.ONE;
        CURVE_FP[1][19] = BigInteger.ZERO;
        CURVE_IBZ[1][0] = Ibz.fromMpLimbs(8, new long[]{ 0x6297ba6ae815625dL, 0xd28bc698d2b21a75L, 0x412682e497f300b1L, 0x9c4318163639f8e7L, 0x2b8aad5237dad2cfL, 0x1a986be7429791cbL, 0x835c22de0a8a19e4L, 0x0007a95745964d5fL });
        CURVE_IBZ[1][1] = Ibz.fromMpLimbs(8, new long[]{ 0xf04d0a1071f7f6c6L, 0xbcad60da241923ddL, 0xdb612f1db26de86cL, 0x9d94b159d9470ae7L, 0xcd5ce3fe840142dbL, 0xc4c5f28afd387586L, 0xd31f185c5c2240d7L, 0x0005b462e782843fL });
        CURVE_IBZ[1][2] = Ibz.fromMpLimbs(8, new long[]{ 0x4b34fc9673181c53L, 0xa9144d56ae17d504L, 0x028b244800696a8cL, 0xd29ca7ccce1b5716L, 0x40ddc81e102848cfL, 0xcb9f36f706d4bcdfL, 0x38d399c03a3408d7L, 0x000be1a8b4bc6e18L });
        CURVE_IBZ[1][3] = Ibz.fromMpLimbs(8, new long[]{ 0x9d68459517ea9da3L, 0x2d7439672d4de58aL, 0xbed97d1b680cff4eL, 0x63bce7e9c9c60718L, 0xd47552adc8252d30L, 0xe5679418bd686e34L, 0x7ca3dd21f575e61bL, 0x000856a8ba69b2a0L });
        CURVE_IBZ[1][4] = Ibz.fromMpLimbs(8, new long[]{ 0x75f1d05088dbf3b3L, 0xe7a297c48cbe10ddL, 0x8d12d51ff1e2e6aeL, 0xc097c98a639555a8L, 0x78ce54f366aa60c3L, 0x03e199a77fb35dceL, 0x30f333393c9a8753L, 0x0007c99fc05e406eL });
        CURVE_IBZ[1][5] = Ibz.fromMpLimbs(8, new long[]{ 0xcae77bc01bf3bddeL, 0xbcb84b1a58a88d2eL, 0x4881fcf23d98ccd9L, 0x730d2e8a347366f8L, 0x58eadce94789abbfL, 0x328058d061690f54L, 0x23d267a05bd0e1f9L, 0x0007d51f18e12611L });
        CURVE_IBZ[1][6] = Ibz.fromMpLimbs(8, new long[]{ 0xea02939de36fee54L, 0x8bb39f39a7aee6dbL, 0xae5ea9abf5947f02L, 0xbecd0d9a7fc09a76L, 0xff9a30f48b68692dL, 0xc552bdfcfd43d1aeL, 0x981b33e5a4bffe0dL, 0x000c857345e8202cL });
        CURVE_IBZ[1][7] = Ibz.fromMpLimbs(8, new long[]{ 0x8a0e2faf77240c4dL, 0x185d683b7341ef22L, 0x72ed2ae00e1d1951L, 0x3f6836759c6aaa57L, 0x8731ab0c99559f3cL, 0xfc1e6658804ca231L, 0xcf0cccc6c36578acL, 0x000836603fa1bf91L });
        CURVE_IBZ[1][8] = Ibz.fromMpLimbs(8, new long[]{ 0xd816f1c69f841affL, 0x01191990d450bdd0L, 0x820947801a97bcf7L, 0x7b5320ba1d73695bL, 0x351fac534ce55e3cL, 0x121fd54c5a3eaaa3L, 0x83700c9cdb55bf17L, 0x000c1f35415c2061L });
        CURVE_IBZ[1][9] = Ibz.fromMpLimbs(8, new long[]{ 0xd4f3bab1de6f7734L, 0x7cc069b06c68c928L, 0x2eb2b1dc296c994fL, 0x95d3a8ff8494e4ceL, 0x6cd609180e7f5f30L, 0xed961f93747cae27L, 0xc33e713dc91a5590L, 0x00039ce540fdc075L });
        CURVE_IBZ[1][10] = Ibz.fromMpLimbs(8, new long[]{ 0x9ec71aaf89f5da85L, 0x20bc3ae9ec63cfffL, 0xfa257d849942c2f3L, 0x9342c357eb7b5e69L, 0x7a7f857bd26c5c58L, 0x0033bb97fb5c0757L, 0xcc0ad644fceb6c28L, 0x000412d6e1c022adL });
        CURVE_IBZ[1][11] = Ibz.fromMpLimbs(8, new long[]{ 0x27e90e39607be501L, 0xfee6e66f2baf422fL, 0x7df6b87fe5684308L, 0x84acdf45e28c96a4L, 0xcae053acb31aa1c3L, 0xede02ab3a5c1555cL, 0x7c8ff36324aa40e8L, 0x0003e0cabea3df9eL });
        CURVE_IBZ[1][12] = Ibz.fromMpLimbs(8, new long[]{ 0x6297ba6ae815625dL, 0xd28bc698d2b21a75L, 0x412682e497f300b1L, 0x9c4318163639f8e7L, 0x2b8aad5237dad2cfL, 0x1a986be7429791cbL, 0x835c22de0a8a19e4L, 0x0007a95745964d5fL });
        CURVE_IBZ[1][13] = Ibz.fromMpLimbs(8, new long[]{ 0xf04d0a1071f7f6c6L, 0xbcad60da241923ddL, 0xdb612f1db26de86cL, 0x9d94b159d9470ae7L, 0xcd5ce3fe840142dbL, 0xc4c5f28afd387586L, 0xd31f185c5c2240d7L, 0x0005b462e782843fL });
        CURVE_IBZ[1][14] = Ibz.fromMpLimbs(8, new long[]{ 0x4b34fc9673181c53L, 0xa9144d56ae17d504L, 0x028b244800696a8cL, 0xd29ca7ccce1b5716L, 0x40ddc81e102848cfL, 0xcb9f36f706d4bcdfL, 0x38d399c03a3408d7L, 0x000be1a8b4bc6e18L });
        CURVE_IBZ[1][15] = Ibz.fromMpLimbs(8, new long[]{ 0x9d68459517ea9da3L, 0x2d7439672d4de58aL, 0xbed97d1b680cff4eL, 0x63bce7e9c9c60718L, 0xd47552adc8252d30L, 0xe5679418bd686e34L, 0x7ca3dd21f575e61bL, 0x000856a8ba69b2a0L });
        CURVE_IBZ[1][16] = Ibz.fromMpLimbs(8, new long[]{ 0xbaf8e828446df9daL, 0x73d14be2465f086eL, 0x46896a8ff8f17357L, 0xe04be4c531caaad4L, 0x3c672a79b3553061L, 0x81f0ccd3bfd9aee7L, 0x1879999c9e4d43a9L, 0x000be4cfe02f2037L });
        CURVE_IBZ[1][17] = Ibz.fromMpLimbs(8, new long[]{ 0x6573bde00df9deefL, 0xde5c258d2c544697L, 0x2440fe791ecc666cL, 0xb98697451a39b37cL, 0x2c756e74a3c4d5dfL, 0x99402c6830b487aaL, 0x91e933d02de870fcL, 0x000bea8f8c709308L });
        CURVE_IBZ[1][18] = Ibz.fromMpLimbs(8, new long[]{ 0xf50149cef1b7f72aL, 0x45d9cf9cd3d7736dL, 0x572f54d5faca3f81L, 0xdf6686cd3fe04d3bL, 0x7fcd187a45b43496L, 0xe2a95efe7ea1e8d7L, 0x4c0d99f2d25fff06L, 0x000e42b9a2f41016L });
        CURVE_IBZ[1][19] = Ibz.fromMpLimbs(8, new long[]{ 0x450717d7bb920627L, 0x8c2eb41db9a0f791L, 0xb9769570070e8ca8L, 0x1fb41b3ace35552bL, 0xc398d5864caacf9eL, 0x7e0f332c40265118L, 0xe786666361b2bc56L, 0x00041b301fd0dfc8L });
        CURVE_IBZ[1][20] = Ibz.fromMpLimbs(8, new long[]{ 0xee5e6c8c35ac679cL, 0x0bda9f6c29fa2827L, 0x39bdd3515e202083L, 0x08f237274085d9bcL, 0x6e266f9055dde905L, 0xec90f170f15a6779L, 0xe7106f9953a0db0eL, 0x000de2e1a7f0ad92L });
        CURVE_IBZ[1][21] = Ibz.fromMpLimbs(8, new long[]{ 0x4c65238cbf25a483L, 0xac20c5afccc9dd0bL, 0xbd24e2bfb162e998L, 0xd37dd781672005fdL, 0x7f8676b0595a0a89L, 0xd6792c0159eadea4L, 0x2bcfe2625454714bL, 0x000c8cd38bc0fad4L });
        CURVE_IBZ[1][22] = Ibz.fromMpLimbs(8, new long[]{ 0xed1595e861883f72L, 0x15d9aae902fd2b1aL, 0xce25fe5523ff5945L, 0x16db8534a648aa48L, 0x3a68fb7ca3013fcfL, 0xf04430ee1c1d04baL, 0x497198b2c4f8116fL, 0x00032836b93eea5cL });
        CURVE_IBZ[1][23] = Ibz.fromMpLimbs(8, new long[]{ 0x11a19373ca539864L, 0xf4256093d605d7d8L, 0xc6422caea1dfdf7cL, 0xf70dc8d8bf7a2643L, 0x91d9906faa2216faL, 0x136f0e8f0ea59886L, 0x18ef9066ac5f24f1L, 0x00021d1e580f526dL });

        // ---- Entry [2] ----
        CURVE_FP[2][0] = new BigInteger("15a038b85f1569b0ac433f252858652b493f6186c516f221064d7ec8186e2ec4b082733b14beb537e019dbb33cc856a896e00ee84cafaaad92b857c803e624", 16);
        CURVE_FP[2][1] = BigInteger.ZERO;
        CURVE_FP[2][2] = BigInteger.ONE;
        CURVE_FP[2][3] = BigInteger.ZERO;
        CURVE_FP[2][4] = new BigInteger("dd680e2e17c55a6c2b10cfc94a16194ad24fd861b145bc8841935fb2061b8bb12c209ccec52fad4df80676eccf3215aa25b803ba132beaab64ae15f200f989", 16);
        CURVE_FP[2][5] = BigInteger.ZERO;
        CURVE_FP[2][6] = BigInteger.ONE;
        CURVE_FP[2][7] = BigInteger.ZERO;
        CURVE_FP[2][8] = new BigInteger("543554ec1828f09e97d13289372a206a5fb2cb070c49585881682f2f4dba93ca6a7c051dfcd7d2da48d4539fff0ce1abbd9f9a5404c7c32afd4cca5b2a046f", 16);
        CURVE_FP[2][9] = new BigInteger("61d4c27aeed5909fe43d830179cc0e5f0633593d704b87e9aa4a620e67ae03fa435ee9d0ba242fdb655c1f003b54e21fd32c1507bfa8ce7ad963ba2ad9b21b", 16);
        CURVE_FP[2][10] = BigInteger.ONE;
        CURVE_FP[2][11] = BigInteger.ZERO;
        CURVE_FP[2][12] = new BigInteger("1208ca81c90729a6478f1dad53278a9740f89ad92df2f23188d8fd21f2facf013ae3bc78bf42b50d6a45a45c67fc2390bf4fce999c95ebde215ed507a5c9b8", 16);
        CURVE_FP[2][13] = new BigInteger("11b1f676e22542c256a132e71dd36156dd43e7d8775045dc1d0bad0d7ef36cc5cf27041acad5ed1e6610d133211b5314b67f87e5aaf4dcc131a1d1da50c8b5e", 16);
        CURVE_FP[2][14] = BigInteger.ONE;
        CURVE_FP[2][15] = BigInteger.ZERO;
        CURVE_FP[2][16] = new BigInteger("e974b2846ddbd4d6409af9cefa70e91e8b3abf50cb54581879a1120de4d30eb5a4edab6ce30088dbc15a1a9261b6c66221d1b359d0c97b09949dc38372ff6e", 16);
        CURVE_FP[2][17] = new BigInteger("13769b23e567836181d00207e47754281065ddad68e74601d62dc8246d6fccef7872f2414e7fe4c7b9e81628d29d285fa4168ff0de7a1294fb818884fc498a1", 16);
        CURVE_FP[2][18] = BigInteger.ONE;
        CURVE_FP[2][19] = BigInteger.ZERO;
        CURVE_IBZ[2][0] = Ibz.fromMpLimbs(8, new long[]{ 0x9d1132540fec5b0bL, 0x86b865ca32bb8130L, 0x667c3cc3fce78184L, 0x9834271e4e65a54bL, 0x45fd5e0d1d810a9cL, 0x7e575f8f4b0b26ebL, 0xe98456b4cb4cd36fL, 0x000b59a1cfdfad75L });
        CURVE_IBZ[2][1] = Ibz.fromMpLimbs(8, new long[]{ 0x55ed1c2b15e82bbaL, 0xb4093a5cb3ccb72cL, 0x90a1d365071b2f3dL, 0xa6330be01e26b2f5L, 0x49b3e0e3e2bdc5a6L, 0x36749ba39f1cd4c8L, 0xcdd3c60354112e5aL, 0x0004088a2e7efb23L });
        CURVE_IBZ[2][2] = Ibz.fromMpLimbs(8, new long[]{ 0x236512fcb5b7a8e5L, 0x5ece526022676f00L, 0xe5b3fcde93eebf38L, 0xdd481770712a09f9L, 0x0bdfb7f55350dd27L, 0xca36e6a97cb446a4L, 0x3713e43b03c98565L, 0x0004806aeeb14fe2L });
        CURVE_IBZ[2][3] = Ibz.fromMpLimbs(8, new long[]{ 0x62eecdabf013a4f5L, 0x79479a35cd447ecfL, 0x9983c33c03187e7bL, 0x67cbd8e1b19a5ab4L, 0xba02a1f2e27ef563L, 0x81a8a070b4f4d914L, 0x167ba94b34b32c90L, 0x0004a65e3020528aL });
        CURVE_IBZ[2][4] = Ibz.fromMpLimbs(8, new long[]{ 0x75f1d05088dbf3b3L, 0xe7a297c48cbe10ddL, 0x8d12d51ff1e2e6aeL, 0xc097c98a639555a8L, 0x78ce54f366aa60c3L, 0x03e199a77fb35dceL, 0x30f333393c9a8753L, 0x0007c99fc05e406eL });
        CURVE_IBZ[2][5] = Ibz.fromMpLimbs(8, new long[]{ 0xcae77bc01bf3bddeL, 0xbcb84b1a58a88d2eL, 0x4881fcf23d98ccd9L, 0x730d2e8a347366f8L, 0x58eadce94789abbfL, 0x328058d061690f54L, 0x23d267a05bd0e1f9L, 0x0007d51f18e12611L });
        CURVE_IBZ[2][6] = Ibz.fromMpLimbs(8, new long[]{ 0xea02939de36fee54L, 0x8bb39f39a7aee6dbL, 0xae5ea9abf5947f02L, 0xbecd0d9a7fc09a76L, 0xff9a30f48b68692dL, 0xc552bdfcfd43d1aeL, 0x981b33e5a4bffe0dL, 0x000c857345e8202cL });
        CURVE_IBZ[2][7] = Ibz.fromMpLimbs(8, new long[]{ 0x8a0e2faf77240c4dL, 0x185d683b7341ef22L, 0x72ed2ae00e1d1951L, 0x3f6836759c6aaa57L, 0x8731ab0c99559f3cL, 0xfc1e6658804ca231L, 0xcf0cccc6c36578acL, 0x000836603fa1bf91L });
        CURVE_IBZ[2][8] = Ibz.fromMpLimbs(8, new long[]{ 0xc566d8e823935eb9L, 0x45771bf1a77f0d78L, 0x0281132cecd33141L, 0x0f25b4bb1d3413b5L, 0xde505e9fbf860dc3L, 0x687dd5b0e95ef536L, 0xc8ccdb8d992c03abL, 0x00056e1ad954faf0L });
        CURVE_IBZ[2][9] = Ibz.fromMpLimbs(8, new long[]{ 0x1544d9f7f7a8f17cL, 0x3fba3812f5aab2c8L, 0xad77678cb545f63eL, 0x74c9a5dc12f8ed9fL, 0x14a0806fc1e0ec1dL, 0x57d5606c34f3fb25L, 0xa78783e39c8c9733L, 0x00012499503b7caeL });
        CURVE_IBZ[2][10] = Ibz.fromMpLimbs(8, new long[]{ 0xb74db73f57ac5d83L, 0x0915004335881869L, 0xb830448782eb7f31L, 0x5646991170a76627L, 0x925d168ce1134779L, 0xd5a6a95ed347c1e8L, 0xf75500720beb7debL, 0x00027ef99ee20306L });
        CURVE_IBZ[2][11] = Ibz.fromMpLimbs(8, new long[]{ 0x3a992717dc6ca147L, 0xba88e40e5880f287L, 0xfd7eecd3132ccebeL, 0xf0da4b44e2cbec4aL, 0x21afa1604079f23cL, 0x97822a4f16a10ac9L, 0x3733247266d3fc54L, 0x000a91e526ab050fL });
        CURVE_IBZ[2][12] = Ibz.fromMpLimbs(8, new long[]{ 0x9d1132540fec5b0bL, 0x86b865ca32bb8130L, 0x667c3cc3fce78184L, 0x9834271e4e65a54bL, 0x45fd5e0d1d810a9cL, 0x7e575f8f4b0b26ebL, 0xe98456b4cb4cd36fL, 0x000b59a1cfdfad75L });
        CURVE_IBZ[2][13] = Ibz.fromMpLimbs(8, new long[]{ 0x55ed1c2b15e82bbaL, 0xb4093a5cb3ccb72cL, 0x90a1d365071b2f3dL, 0xa6330be01e26b2f5L, 0x49b3e0e3e2bdc5a6L, 0x36749ba39f1cd4c8L, 0xcdd3c60354112e5aL, 0x0004088a2e7efb23L });
        CURVE_IBZ[2][14] = Ibz.fromMpLimbs(8, new long[]{ 0x236512fcb5b7a8e5L, 0x5ece526022676f00L, 0xe5b3fcde93eebf38L, 0xdd481770712a09f9L, 0x0bdfb7f55350dd27L, 0xca36e6a97cb446a4L, 0x3713e43b03c98565L, 0x0004806aeeb14fe2L });
        CURVE_IBZ[2][15] = Ibz.fromMpLimbs(8, new long[]{ 0x62eecdabf013a4f5L, 0x79479a35cd447ecfL, 0x9983c33c03187e7bL, 0x67cbd8e1b19a5ab4L, 0xba02a1f2e27ef563L, 0x81a8a070b4f4d914L, 0x167ba94b34b32c90L, 0x0004a65e3020528aL });
        CURVE_IBZ[2][16] = Ibz.fromMpLimbs(8, new long[]{ 0xbaf8e828446df9daL, 0x73d14be2465f086eL, 0x46896a8ff8f17357L, 0xe04be4c531caaad4L, 0x3c672a79b3553061L, 0x81f0ccd3bfd9aee7L, 0x1879999c9e4d43a9L, 0x000be4cfe02f2037L });
        CURVE_IBZ[2][17] = Ibz.fromMpLimbs(8, new long[]{ 0x6573bde00df9deefL, 0xde5c258d2c544697L, 0x2440fe791ecc666cL, 0xb98697451a39b37cL, 0x2c756e74a3c4d5dfL, 0x99402c6830b487aaL, 0x91e933d02de870fcL, 0x000bea8f8c709308L });
        CURVE_IBZ[2][18] = Ibz.fromMpLimbs(8, new long[]{ 0xf50149cef1b7f72aL, 0x45d9cf9cd3d7736dL, 0x572f54d5faca3f81L, 0xdf6686cd3fe04d3bL, 0x7fcd187a45b43496L, 0xe2a95efe7ea1e8d7L, 0x4c0d99f2d25fff06L, 0x000e42b9a2f41016L });
        CURVE_IBZ[2][19] = Ibz.fromMpLimbs(8, new long[]{ 0x450717d7bb920627L, 0x8c2eb41db9a0f791L, 0xb9769570070e8ca8L, 0x1fb41b3ace35552bL, 0xc398d5864caacf9eL, 0x7e0f332c40265118L, 0xe786666361b2bc56L, 0x00041b301fd0dfc8L });
        CURVE_IBZ[2][20] = Ibz.fromMpLimbs(8, new long[]{ 0x00645aeb34786f0bL, 0x2fabccf0ecff9a1aL, 0xc31a97e7718af3a8L, 0x5ee1514eb872a0cdL, 0x97c6d0c34af94b79L, 0xa5e6a98723709591L, 0x198031508730e201L, 0x000b25c93b838452L });
        CURVE_IBZ[2][21] = Ibz.fromMpLimbs(8, new long[]{ 0xfc6bdefe7f691de7L, 0x13185188c1006fd5L, 0x426033ac10dd416eL, 0xd02e5b131d0e8985L, 0x4f729b7d6e286fb5L, 0xda5ff00dd5f39665L, 0x958d4b2ad77898f2L, 0x00034a93d837fcefL });
        CURVE_IBZ[2][22] = Ibz.fromMpLimbs(8, new long[]{ 0x5e0dcb8f81f38527L, 0xedcf061374487c93L, 0x8ace19dc77c77d31L, 0x28df9ccca582bfb8L, 0x546b33e64f69b6e0L, 0xdc8d53ed1627cfb2L, 0xb942c438b843d80bL, 0x0002c1dcb3c08fb5L });
        CURVE_IBZ[2][23] = Ibz.fromMpLimbs(8, new long[]{ 0xff9ba514cb8790f5L, 0xd054330f130065e5L, 0x3ce568188e750c57L, 0xa11eaeb1478d5f32L, 0x68392f3cb506b486L, 0x5a195678dc8f6a6eL, 0xe67fceaf78cf1dfeL, 0x0004da36c47c7badL });

        // ---- Entry [3] ----
        CURVE_FP[3][0] = new BigInteger("34f5bb862f59f4656a2a280ac28beef202867b9ac6076c876cdcb2b5d6c5fde42d13a015eab2ef4e6f471ec57b1b99cd3243f1969df779140596d9e45d60a5", 16);
        CURVE_FP[3][1] = BigInteger.ZERO;
        CURVE_FP[3][2] = BigInteger.ONE;
        CURVE_FP[3][3] = BigInteger.ZERO;
        CURVE_FP[3][4] = new BigInteger("1513d6ee18bd67d195a8a8a02b0a2fbbc80a19ee6b181db21db372cad75b17f790b44e8057aacbbd39bd1c7b15ec6e6734c90fc65a77dde450165b679175829", 16);
        CURVE_FP[3][5] = BigInteger.ZERO;
        CURVE_FP[3][6] = BigInteger.ONE;
        CURVE_FP[3][7] = BigInteger.ZERO;
        CURVE_FP[3][8] = new BigInteger("18daecd7d1551c7cd8792fc280b0d42616fcf20535c4b7b581c9f15e8675c5f30f5cf48daaeb2594572058a01d3222bbd70897a3f754cf83deba80d6317c5e3", 16);
        CURVE_FP[3][9] = new BigInteger("721512175fdc073920d9ff6fcc3c5b0c1453dc9f3ea937c19b76d1f5dc49148e4aab0d70f956789da96cc0cc8f24e61f4195b53d3374833c6cccef7e0333d4", 16);
        CURVE_FP[3][10] = BigInteger.ONE;
        CURVE_FP[3][11] = BigInteger.ZERO;
        CURVE_FP[3][12] = new BigInteger("e6c983020dcff9cc2e3ae8ebc4ad18449d84807b6c92770cf8fc5ce557cfda1af0bedda70feabcef15b6b8f3346fe76c04f1ce25c04be343022381b6c1effc", 16);
        CURVE_FP[3][13] = new BigInteger("8ca010e8d5821f53a0f336894621b5a8651423aa2cf969653ae0a26013f48675b7ac0b142f1f4c17ba9cc39c237d0169d9e64840afc4d59f7987d21736542c", 16);
        CURVE_FP[3][14] = BigInteger.ONE;
        CURVE_FP[3][15] = BigInteger.ZERO;
        CURVE_FP[3][16] = new BigInteger("bf6cc167116ecff1c223a8902fd23da35e03258f3b5159eb9d48c0397e80f774e57b54ef37ddd169595ad8824457573d70567d5328fbc87786b76ae2bf4ef9", 16);
        CURVE_FP[3][17] = new BigInteger("199cec573a270b9bec19f8fdc3a42f1f0711a740adcdc51537a607b6d5708534ef1b401a41d663bb7181570603d9f5a42d9de8c4300d0e52553c1d0a01016b1", 16);
        CURVE_FP[3][18] = BigInteger.ONE;
        CURVE_FP[3][19] = BigInteger.ZERO;
        CURVE_IBZ[3][0] = Ibz.fromMpLimbs(8, new long[]{ 0xe8a6cbb79bc53919L, 0xc64e8690022a3f55L, 0x422f80e86c4d8e93L, 0xb342f54507e10ffdL, 0xfb8da62b80a587beL, 0x0d4d4697466e4048L, 0xa00852c1c9ba9d79L, 0x000ab87cf30921f1L });
        CURVE_IBZ[3][1] = Ibz.fromMpLimbs(8, new long[]{ 0x5bc4cdfe86b5c03eL, 0x946490d9bc7bc7a1L, 0xc710853d9345c604L, 0x8ef440504b981ad2L, 0xb6100bd26664d73cL, 0xcf72abe95e87483eL, 0x348352b1bfbf679eL, 0x000ebd534a360f7cL });
        CURVE_IBZ[3][2] = Ibz.fromMpLimbs(8, new long[]{ 0x676cba319b8c5937L, 0x42e2f6199c3d8d31L, 0x390a76e5d0724d1aL, 0xfd712d1676435086L, 0xed6356ecff7b0341L, 0x94886a5d73241436L, 0x4043d6b5014509f0L, 0x000f7784eb6e10d8L });
        CURVE_IBZ[3][3] = Ibz.fromMpLimbs(8, new long[]{ 0x17593448643ac6e7L, 0x39b1796ffdd5c0aaL, 0xbdd07f1793b2716cL, 0x4cbd0abaf81ef002L, 0x047259d47f5a7841L, 0xf2b2b968b991bfb7L, 0x5ff7ad3e36456286L, 0x000547830cf6de0eL });
        CURVE_IBZ[3][4] = Ibz.fromMpLimbs(8, new long[]{ 0x75f1d05088dbf3b3L, 0xe7a297c48cbe10ddL, 0x8d12d51ff1e2e6aeL, 0xc097c98a639555a8L, 0x78ce54f366aa60c3L, 0x03e199a77fb35dceL, 0x30f333393c9a8753L, 0x0007c99fc05e406eL });
        CURVE_IBZ[3][5] = Ibz.fromMpLimbs(8, new long[]{ 0xcae77bc01bf3bddeL, 0xbcb84b1a58a88d2eL, 0x4881fcf23d98ccd9L, 0x730d2e8a347366f8L, 0x58eadce94789abbfL, 0x328058d061690f54L, 0x23d267a05bd0e1f9L, 0x0007d51f18e12611L });
        CURVE_IBZ[3][6] = Ibz.fromMpLimbs(8, new long[]{ 0xea02939de36fee54L, 0x8bb39f39a7aee6dbL, 0xae5ea9abf5947f02L, 0xbecd0d9a7fc09a76L, 0xff9a30f48b68692dL, 0xc552bdfcfd43d1aeL, 0x981b33e5a4bffe0dL, 0x000c857345e8202cL });
        CURVE_IBZ[3][7] = Ibz.fromMpLimbs(8, new long[]{ 0x8a0e2faf77240c4dL, 0x185d683b7341ef22L, 0x72ed2ae00e1d1951L, 0x3f6836759c6aaa57L, 0x8731ab0c99559f3cL, 0xfc1e6658804ca231L, 0xcf0cccc6c36578acL, 0x000836603fa1bf91L });
        CURVE_IBZ[3][8] = Ibz.fromMpLimbs(8, new long[]{ 0x289e3527c1bb5fd3L, 0xfbf2a8e1f5ce97fdL, 0xcb44df66b5e78f04L, 0x6e5c031c831405b5L, 0x5ea93d193134a6b9L, 0xafb9800337fe860dL, 0xde5aa36df377bfddL, 0x000bc87208daa9dfL });
        CURVE_IBZ[3][9] = Ibz.fromMpLimbs(8, new long[]{ 0xf7dbd4616a4fb354L, 0xb2740ff667864aecL, 0x277e97e9066dfcf4L, 0x6062b1fa68a35e43L, 0xd92667ed8c2ba56aL, 0x80845bc54883444aL, 0x4eb63b85209e1f0aL, 0x000ab05cb97314feL });
        CURVE_IBZ[3][10] = Ibz.fromMpLimbs(8, new long[]{ 0x4d2a2271213b9c41L, 0x8462f3fd987cca4cL, 0x5ca1f930550484baL, 0x1bc10b1684d2b075L, 0x4bb0e84efeb5e1acL, 0x97f43d9857b6f6b6L, 0x0b841aae9866da24L, 0x000f4a2dfcb736ecL });
        CURVE_IBZ[3][11] = Ibz.fromMpLimbs(8, new long[]{ 0xd761cad83e44a02dL, 0x040d571e0a316802L, 0x34bb20994a1870fbL, 0x91a3fce37cebfa4aL, 0xa156c2e6cecb5946L, 0x50467ffcc80179f2L, 0x21a55c920c884022L, 0x0004378df7255620L });
        CURVE_IBZ[3][12] = Ibz.fromMpLimbs(8, new long[]{ 0xe8a6cbb79bc53919L, 0xc64e8690022a3f55L, 0x422f80e86c4d8e93L, 0xb342f54507e10ffdL, 0xfb8da62b80a587beL, 0x0d4d4697466e4048L, 0xa00852c1c9ba9d79L, 0x000ab87cf30921f1L });
        CURVE_IBZ[3][13] = Ibz.fromMpLimbs(8, new long[]{ 0x5bc4cdfe86b5c03eL, 0x946490d9bc7bc7a1L, 0xc710853d9345c604L, 0x8ef440504b981ad2L, 0xb6100bd26664d73cL, 0xcf72abe95e87483eL, 0x348352b1bfbf679eL, 0x000ebd534a360f7cL });
        CURVE_IBZ[3][14] = Ibz.fromMpLimbs(8, new long[]{ 0x676cba319b8c5937L, 0x42e2f6199c3d8d31L, 0x390a76e5d0724d1aL, 0xfd712d1676435086L, 0xed6356ecff7b0341L, 0x94886a5d73241436L, 0x4043d6b5014509f0L, 0x000f7784eb6e10d8L });
        CURVE_IBZ[3][15] = Ibz.fromMpLimbs(8, new long[]{ 0x17593448643ac6e7L, 0x39b1796ffdd5c0aaL, 0xbdd07f1793b2716cL, 0x4cbd0abaf81ef002L, 0x047259d47f5a7841L, 0xf2b2b968b991bfb7L, 0x5ff7ad3e36456286L, 0x000547830cf6de0eL });
        CURVE_IBZ[3][16] = Ibz.fromMpLimbs(8, new long[]{ 0xbaf8e828446df9daL, 0x73d14be2465f086eL, 0x46896a8ff8f17357L, 0xe04be4c531caaad4L, 0x3c672a79b3553061L, 0x81f0ccd3bfd9aee7L, 0x1879999c9e4d43a9L, 0x000be4cfe02f2037L });
        CURVE_IBZ[3][17] = Ibz.fromMpLimbs(8, new long[]{ 0x6573bde00df9deefL, 0xde5c258d2c544697L, 0x2440fe791ecc666cL, 0xb98697451a39b37cL, 0x2c756e74a3c4d5dfL, 0x99402c6830b487aaL, 0x91e933d02de870fcL, 0x000bea8f8c709308L });
        CURVE_IBZ[3][18] = Ibz.fromMpLimbs(8, new long[]{ 0xf50149cef1b7f72aL, 0x45d9cf9cd3d7736dL, 0x572f54d5faca3f81L, 0xdf6686cd3fe04d3bL, 0x7fcd187a45b43496L, 0xe2a95efe7ea1e8d7L, 0x4c0d99f2d25fff06L, 0x000e42b9a2f41016L });
        CURVE_IBZ[3][19] = Ibz.fromMpLimbs(8, new long[]{ 0x450717d7bb920627L, 0x8c2eb41db9a0f791L, 0xb9769570070e8ca8L, 0x1fb41b3ace35552bL, 0xc398d5864caacf9eL, 0x7e0f332c40265118L, 0xe786666361b2bc56L, 0x00041b301fd0dfc8L });
        CURVE_IBZ[3][20] = Ibz.fromMpLimbs(8, new long[]{ 0xa4d60ae5e24a718aL, 0x69ce9f91f453d401L, 0x4e639273fa117d19L, 0x746ae08fde49f33aL, 0x0e4c43b652bb243dL, 0x74fedf64380d1bddL, 0xd71ba4d6584f4dfaL, 0x000f717ef070f067L });
        CURVE_IBZ[3][21] = Ibz.fromMpLimbs(8, new long[]{ 0xe045d1d078455d93L, 0xad36940006b6fa74L, 0x7ca09b00d3f64e68L, 0xb42f1fb60facab22L, 0x2b2dbc5bb2e357dbL, 0x291834e2c77e94faL, 0xd4a268cff9dd6ce9L, 0x0005da606050bc59L });
        CURVE_IBZ[3][22] = Ibz.fromMpLimbs(8, new long[]{ 0x2d81ac2b5d39c6dcL, 0x8e30dab5f398c9b8L, 0x8cd271021b25b3b2L, 0x52b8b4f37c35952eL, 0x8d316906b8775789L, 0x166702b38a1098a6L, 0xc8ecfc76a9350856L, 0x000d4f0291486044L });
        CURVE_IBZ[3][23] = Ibz.fromMpLimbs(8, new long[]{ 0x5b29f51a1db58e76L, 0x9631606e0bac2bfeL, 0xb19c6d8c05ee82e6L, 0x8b951f7021b60cc5L, 0xf1b3bc49ad44dbc2L, 0x8b01209bc7f2e422L, 0x28e45b29a7b0b205L, 0x00008e810f8f0f98L });

        // ---- Entry [4] ----
        CURVE_FP[4][0] = new BigInteger("1f1410257ffe85ba46c758a066a46a6f63c94f88b59d3b8c97f811ba1835948701fe3f833a9ade2a0f57e7d22c3626eadcdc42c587b9922ede65966eac9f6b", 16);
        CURVE_FP[4][1] = BigInteger.ZERO;
        CURVE_FP[4][2] = BigInteger.ONE;
        CURVE_FP[4][3] = BigInteger.ZERO;
        CURVE_FP[4][4] = new BigInteger("73c504095fffa16e91b1d62819a91a9bd8f253e22d674ee325fe046e860d6521c07f8fe0cea6b78a83d5f9f48b0d89bab73710b161ee648bb799659bab27db", 16);
        CURVE_FP[4][5] = BigInteger.ZERO;
        CURVE_FP[4][6] = BigInteger.ONE;
        CURVE_FP[4][7] = BigInteger.ZERO;
        CURVE_FP[4][8] = new BigInteger("194f25e998fcd09acd1e052c46b6ae84770afa73015ef5e00b582de5ad50359ef1fc4cfc3b407b6599bdba154b59008583e8ceb8b838ee6ed72fb6b6bd66f12", 16);
        CURVE_FP[4][9] = new BigInteger("1485b3568b39b0c4a73e5c4119f847283eae913a9438a000d39aee2d824b707305cd153ea86199f9ad4728ebe7164ac819a56d4c2de6003de2cd7b63055f12", 16);
        CURVE_FP[4][10] = BigInteger.ONE;
        CURVE_FP[4][11] = BigInteger.ZERO;
        CURVE_FP[4][12] = new BigInteger("1994ca97b07d9ca4898fd9ef21945d758db0a4a76e7a73cc6594fcae675b10e1ffdc8b160b97889230962fedc51d131f245a7d65472a6c6612221bbbdc42917", 16);
        CURVE_FP[4][13] = new BigInteger("14365c1f5b333be389b7d6e436d7315c94147d11edfe4d55cea705ee0645f81d9a32c71d0cd3c1bffefe344f7b5a4f4993160e62975483df955d1358780213", 16);
        CURVE_FP[4][14] = BigInteger.ONE;
        CURVE_FP[4][15] = BigInteger.ZERO;
        CURVE_FP[4][16] = new BigInteger("19af04644366d055f75ea0ace4093b1734a999e82bea4699bf3557fe6582fb5ac046ea08ed11e5185aeb73ef7dbf005b190d242cac547ffebc760d305a5e4e5", 16);
        CURVE_FP[4][17] = new BigInteger("8b5bea4879479d80775b9bb9ffc0d6da93f29dca979fee70c5d0785ba7cbaf78976ab932e1fbcd965eb5330f4375776e404a7084b3101c88558c8f708bfe9e", 16);
        CURVE_FP[4][18] = BigInteger.ONE;
        CURVE_FP[4][19] = BigInteger.ZERO;
        CURVE_IBZ[4][0] = Ibz.fromMpLimbs(8, new long[]{ 0x55cc620ad8504f71L, 0x125cab424b7431b0L, 0xca6473b3a634b589L, 0x9b4a60226c416ed0L, 0x29251e190e0db03eL, 0xfc6a10dd042a275eL, 0xe556977eb5927f51L, 0x0003a68f873d10bcL });
        CURVE_IBZ[4][1] = Ibz.fromMpLimbs(8, new long[]{ 0x90c5b7847e790ed2L, 0x59f4606efc99e054L, 0xe3fc29bfb6aeb88fL, 0x4bf9ba948c88a3cfL, 0x723631c0f771cb60L, 0xfdbfb9b8a9e72401L, 0xc8109bd6b4d5326eL, 0x000f1f620661b7f0L });
        CURVE_IBZ[4][2] = Ibz.fromMpLimbs(8, new long[]{ 0xe1ad6715c1a7b407L, 0xbd8e159415e831ebL, 0x16368f7a2bae3976L, 0x162712ae88d28d19L, 0xfa51dd784868f2b0L, 0x35d97eb3a1f3fd6bL, 0x54dd12a82c09d826L, 0x00015bcdc29c87d6L });
        CURVE_IBZ[4][3] = Ibz.fromMpLimbs(8, new long[]{ 0xaa339df527afb08fL, 0xeda354bdb48bce4fL, 0x359b8c4c59cb4a76L, 0x64b59fdd93be912fL, 0xd6dae1e6f1f24fc1L, 0x0395ef22fbd5d8a1L, 0x1aa968814a6d80aeL, 0x000c597078c2ef43L });
        CURVE_IBZ[4][4] = Ibz.fromMpLimbs(8, new long[]{ 0x75f1d05088dbf3b3L, 0xe7a297c48cbe10ddL, 0x8d12d51ff1e2e6aeL, 0xc097c98a639555a8L, 0x78ce54f366aa60c3L, 0x03e199a77fb35dceL, 0x30f333393c9a8753L, 0x0007c99fc05e406eL });
        CURVE_IBZ[4][5] = Ibz.fromMpLimbs(8, new long[]{ 0xcae77bc01bf3bddeL, 0xbcb84b1a58a88d2eL, 0x4881fcf23d98ccd9L, 0x730d2e8a347366f8L, 0x58eadce94789abbfL, 0x328058d061690f54L, 0x23d267a05bd0e1f9L, 0x0007d51f18e12611L });
        CURVE_IBZ[4][6] = Ibz.fromMpLimbs(8, new long[]{ 0xea02939de36fee54L, 0x8bb39f39a7aee6dbL, 0xae5ea9abf5947f02L, 0xbecd0d9a7fc09a76L, 0xff9a30f48b68692dL, 0xc552bdfcfd43d1aeL, 0x981b33e5a4bffe0dL, 0x000c857345e8202cL });
        CURVE_IBZ[4][7] = Ibz.fromMpLimbs(8, new long[]{ 0x8a0e2faf77240c4dL, 0x185d683b7341ef22L, 0x72ed2ae00e1d1951L, 0x3f6836759c6aaa57L, 0x8731ab0c99559f3cL, 0xfc1e6658804ca231L, 0xcf0cccc6c36578acL, 0x000836603fa1bf91L });
        CURVE_IBZ[4][8] = Ibz.fromMpLimbs(8, new long[]{ 0x6eaa739b27c8e7ebL, 0x4a84ac1cf5937a17L, 0xea3de67e77711a27L, 0xc51c8edda34b4596L, 0x481b2551d1a17c15L, 0x1eab8b82fed0402eL, 0x6abf714320fac98bL, 0x0009510f475f463aL });
        CURVE_IBZ[4][9] = Ibz.fromMpLimbs(8, new long[]{ 0x138cdab69e319e28L, 0xb2b7444d5193c3c0L, 0xc700b08b5630f371L, 0xbd7c0c3f3f082404L, 0x429d7bb2d892963bL, 0x9aac853df27719d8L, 0x9e40f5e842cd9bfaL, 0x00069c2315a88a41L });
        CURVE_IBZ[4][10] = Ibz.fromMpLimbs(8, new long[]{ 0x9d61921908ee66d1L, 0xdf2ac3eefc6313a4L, 0x8ad8c39102ef1353L, 0xa4b21029b014953bL, 0x199cf3a8fc0761a3L, 0xb4596eb76a41e6c8L, 0x8b4e9ec32f4ea187L, 0x00035b21038b5321L });
        CURVE_IBZ[4][11] = Ibz.fromMpLimbs(8, new long[]{ 0x91558c64d8371815L, 0xb57b53e30a6c85e8L, 0x15c21981888ee5d8L, 0x3ae371225cb4ba69L, 0xb7e4daae2e5e83eaL, 0xe154747d012fbfd1L, 0x95408ebcdf053674L, 0x0006aef0b8a0b9c5L });
        CURVE_IBZ[4][12] = Ibz.fromMpLimbs(8, new long[]{ 0x55cc620ad8504f71L, 0x125cab424b7431b0L, 0xca6473b3a634b589L, 0x9b4a60226c416ed0L, 0x29251e190e0db03eL, 0xfc6a10dd042a275eL, 0xe556977eb5927f51L, 0x0003a68f873d10bcL });
        CURVE_IBZ[4][13] = Ibz.fromMpLimbs(8, new long[]{ 0x90c5b7847e790ed2L, 0x59f4606efc99e054L, 0xe3fc29bfb6aeb88fL, 0x4bf9ba948c88a3cfL, 0x723631c0f771cb60L, 0xfdbfb9b8a9e72401L, 0xc8109bd6b4d5326eL, 0x000f1f620661b7f0L });
        CURVE_IBZ[4][14] = Ibz.fromMpLimbs(8, new long[]{ 0xe1ad6715c1a7b407L, 0xbd8e159415e831ebL, 0x16368f7a2bae3976L, 0x162712ae88d28d19L, 0xfa51dd784868f2b0L, 0x35d97eb3a1f3fd6bL, 0x54dd12a82c09d826L, 0x00015bcdc29c87d6L });
        CURVE_IBZ[4][15] = Ibz.fromMpLimbs(8, new long[]{ 0xaa339df527afb08fL, 0xeda354bdb48bce4fL, 0x359b8c4c59cb4a76L, 0x64b59fdd93be912fL, 0xd6dae1e6f1f24fc1L, 0x0395ef22fbd5d8a1L, 0x1aa968814a6d80aeL, 0x000c597078c2ef43L });
        CURVE_IBZ[4][16] = Ibz.fromMpLimbs(8, new long[]{ 0xbaf8e828446df9daL, 0x73d14be2465f086eL, 0x46896a8ff8f17357L, 0xe04be4c531caaad4L, 0x3c672a79b3553061L, 0x81f0ccd3bfd9aee7L, 0x1879999c9e4d43a9L, 0x000be4cfe02f2037L });
        CURVE_IBZ[4][17] = Ibz.fromMpLimbs(8, new long[]{ 0x6573bde00df9deefL, 0xde5c258d2c544697L, 0x2440fe791ecc666cL, 0xb98697451a39b37cL, 0x2c756e74a3c4d5dfL, 0x99402c6830b487aaL, 0x91e933d02de870fcL, 0x000bea8f8c709308L });
        CURVE_IBZ[4][18] = Ibz.fromMpLimbs(8, new long[]{ 0xf50149cef1b7f72aL, 0x45d9cf9cd3d7736dL, 0x572f54d5faca3f81L, 0xdf6686cd3fe04d3bL, 0x7fcd187a45b43496L, 0xe2a95efe7ea1e8d7L, 0x4c0d99f2d25fff06L, 0x000e42b9a2f41016L });
        CURVE_IBZ[4][19] = Ibz.fromMpLimbs(8, new long[]{ 0x450717d7bb920627L, 0x8c2eb41db9a0f791L, 0xb9769570070e8ca8L, 0x1fb41b3ace35552bL, 0xc398d5864caacf9eL, 0x7e0f332c40265118L, 0xe786666361b2bc56L, 0x00041b301fd0dfc8L });
        CURVE_IBZ[4][20] = Ibz.fromMpLimbs(8, new long[]{ 0xd4832c9b5e7ab83aL, 0x2eae4a2171e9eff9L, 0xb0386bf2bb260921L, 0x34fbd498c05aeac9L, 0x81de2674aae907caL, 0xa35488c97dbe471fL, 0x7c829acc53019f03L, 0x0008dc7b0732c479L });
        CURVE_IBZ[4][21] = Ibz.fromMpLimbs(8, new long[]{ 0x84bff3d4aeba4733L, 0x4604e0faa71a453aL, 0x5fc5b1149bc2f02bL, 0x175d23021a8d5f8dL, 0x698c051b83513655L, 0xdd4bdd6a8c83c745L, 0xe320d1fc80b7682fL, 0x0000c365c1d3ca30L });
        CURVE_IBZ[4][22] = Ibz.fromMpLimbs(8, new long[]{ 0xe05ddcb05173e32cL, 0xbed7fd386e8c3a7eL, 0xedf026f1a9865fe0L, 0x2e70a48e1dbc8fc7L, 0xf05be8c3e7676648L, 0x5304f8f663b626aaL, 0xe67554a27c937042L, 0x0008b36e02b1d3eaL });
        CURVE_IBZ[4][23] = Ibz.fromMpLimbs(8, new long[]{ 0x2b7cd364a18547c6L, 0xd151b5de8e161006L, 0x4fc7940d44d9f6deL, 0xcb042b673fa51536L, 0x7e21d98b5516f835L, 0x5cab77368241b8e0L, 0x837d6533acfe60fcL, 0x00072384f8cd3b86L });

        // ---- Entry [5] ----
        CURVE_FP[5][0] = new BigInteger("c9b85e426dbe7a58f0f26a6dfcf73674ff11efad540f672d1521eb8e17c948c0a71ad469b7f09b7050700d056741422cd659bafe6d4abc75b7a5e9a9f04ed", 16);
        CURVE_FP[5][1] = BigInteger.ZERO;
        CURVE_FP[5][2] = BigInteger.ONE;
        CURVE_FP[5][3] = BigInteger.ZERO;
        CURVE_FP[5][4] = new BigInteger("14726e17909b6f9e963c3c9a9b7f3dcd9d3fc47beb5503d9cb45487ae385f2523029c6b51a6dfc26dc141c034159d0508b35966ebf9b52af1d6de97a6a7c13b", 16);
        CURVE_FP[5][5] = BigInteger.ZERO;
        CURVE_FP[5][6] = BigInteger.ONE;
        CURVE_FP[5][7] = BigInteger.ZERO;
        CURVE_FP[5][8] = new BigInteger("400d366c5fcaba12f9e292556b5fa322878ea36491240c437663bde1acc724a26189396d5989bf898f0023e80bdb0c39b8f20c4bbcfe8697884202caf42814", 16);
        CURVE_FP[5][9] = new BigInteger("53a3d404849347710b93af67bba357868c3a1898eb34765ab6afe4aeb04ffe5e918e7a55fc2593ead8e50ac10388a94c38c38908d4ad68a7b3b1389f1b347e", 16);
        CURVE_FP[5][10] = BigInteger.ONE;
        CURVE_FP[5][11] = BigInteger.ZERO;
        CURVE_FP[5][12] = new BigInteger("10acfc0b5d306ad95e3ab54ff981c246e11a023d60e6c5df078f47612750e2d3610dde5778a21287326f82c664b07773978f271f3dcff16f03d01e687dfd7fb", 16);
        CURVE_FP[5][13] = new BigInteger("5cb772845abb0c4d2cdda8514db0932b865b81b23410481e93e178b38c370fba70cefa2805c9055c18516fa36cadf2b632ec733cd8b563ebc55527ee893438", 16);
        CURVE_FP[5][14] = BigInteger.ONE;
        CURVE_FP[5][15] = BigInteger.ZERO;
        CURVE_FP[5][16] = new BigInteger("7956602c26482a6f4ec2d872fd1cd9d997d1371b8cad98e51ca19a406a18c91d3232be9d9b48b0b7b0670f8c12095f056fe36833de9de5155f4ad695668c60", 16);
        CURVE_FP[5][17] = new BigInteger("19a9765072429253ed84f366e82a9e7d5f94c9ff63c1225a20d9a83b0edcb026e0aebf48ac31ff585d5ca1828137797f18ed1f1faa7ecbdcf578c9315333cec", 16);
        CURVE_FP[5][18] = BigInteger.ONE;
        CURVE_FP[5][19] = BigInteger.ZERO;
        CURVE_IBZ[5][0] = Ibz.fromMpLimbs(8, new long[]{ 0x18c2d32ef14f2ce5L, 0x4090a7fc28335217L, 0x3801e7704d89d9d5L, 0x2ee554326ac9bca0L, 0x8911df1a827a4356L, 0x18b903e5f05a4102L, 0xea2fd99b77adf66fL, 0x000de07136bba030L });
        CURVE_IBZ[5][1] = Ibz.fromMpLimbs(8, new long[]{ 0x014f02608c670752L, 0x4db95e4d0865138aL, 0x94224a7e7a2cca26L, 0x7e33841dbdc8b2f6L, 0x15fc963338a65677L, 0xb16cdcefbe04acceL, 0x1f8f83957a5ed57bL, 0x00064be3e383e4b9L });
        CURVE_IBZ[5][2] = Ibz.fromMpLimbs(8, new long[]{ 0x535f517740f29b63L, 0x5e1c18a22f265098L, 0x23971db933e95d70L, 0x87bfcae6b98bacccL, 0x2f67f2d0b329d43fL, 0xc67d4369d2ab779cL, 0x1a2bf06b9550d065L, 0x0003bb649b2b0c6eL });
        CURVE_IBZ[5][3] = Ibz.fromMpLimbs(8, new long[]{ 0xe73d2cd10eb0d31bL, 0xbf6f5803d7ccade8L, 0xc7fe188fb276262aL, 0xd11aabcd9536435fL, 0x76ee20e57d85bca9L, 0xe746fc1a0fa5befdL, 0x15d0266488520990L, 0x00021f8ec9445fcfL });
        CURVE_IBZ[5][4] = Ibz.fromMpLimbs(8, new long[]{ 0x8a0e2faf77240c4dL, 0x185d683b7341ef22L, 0x72ed2ae00e1d1951L, 0x3f6836759c6aaa57L, 0x8731ab0c99559f3cL, 0xfc1e6658804ca231L, 0xcf0cccc6c36578acL, 0x000836603fa1bf91L });
        CURVE_IBZ[5][5] = Ibz.fromMpLimbs(8, new long[]{ 0x3518843fe40c4222L, 0x4347b4e5a75772d1L, 0xb77e030dc2673326L, 0x8cf2d175cb8c9907L, 0xa7152316b8765440L, 0xcd7fa72f9e96f0abL, 0xdc2d985fa42f1e06L, 0x00082ae0e71ed9eeL });
        CURVE_IBZ[5][6] = Ibz.fromMpLimbs(8, new long[]{ 0x15fd6c621c9011acL, 0x744c60c658511924L, 0x51a156540a6b80fdL, 0x4132f265803f6589L, 0x0065cf0b749796d2L, 0x3aad420302bc2e51L, 0x67e4cc1a5b4001f2L, 0x00037a8cba17dfd3L });
        CURVE_IBZ[5][7] = Ibz.fromMpLimbs(8, new long[]{ 0x75f1d05088dbf3b3L, 0xe7a297c48cbe10ddL, 0x8d12d51ff1e2e6aeL, 0xc097c98a639555a8L, 0x78ce54f366aa60c3L, 0x03e199a77fb35dceL, 0x30f333393c9a8753L, 0x0007c99fc05e406eL });
        CURVE_IBZ[5][8] = Ibz.fromMpLimbs(8, new long[]{ 0xb0a2d75050f499f9L, 0x34be6b4b6986fdaaL, 0x8c180e0539747bd5L, 0x63b5cc33bb5a6bb8L, 0xbdc4b4efec49943bL, 0x129185ad2fc85a2aL, 0x93f6721b9618a29fL, 0x000bdfbb2e85b40fL });
        CURVE_IBZ[5][9] = Ibz.fromMpLimbs(8, new long[]{ 0x3e902aee4ff5f4c0L, 0x111cf257b2af0049L, 0x8a7cc7d9c1d5ead0L, 0xb43ce1f60f629579L, 0xc2091b7b14ca8f3fL, 0x5d39dfc0f5cd0ac8L, 0xba542e6e9c9a9d8dL, 0x00021cfc4f0279d5L });
        CURVE_IBZ[5][10] = Ibz.fromMpLimbs(8, new long[]{ 0xcef33343173001ebL, 0xd52b353e76152addL, 0x69d0229200c19951L, 0xd332fec7c1bd4a9fL, 0x61a4aa2767f872b7L, 0x9a69fe1d8ec033ddL, 0xbb33209b060f38acL, 0x000c5c8013f555b1L });
        CURVE_IBZ[5][11] = Ibz.fromMpLimbs(8, new long[]{ 0x4f5d28afaf0b6607L, 0xcb4194b496790255L, 0x73e7f1fac68b842aL, 0x9c4a33cc44a59447L, 0x423b4b1013b66bc4L, 0xed6e7a52d037a5d5L, 0x6c098de469e75d60L, 0x00042044d17a4bf0L });
        CURVE_IBZ[5][12] = Ibz.fromMpLimbs(8, new long[]{ 0x18c2d32ef14f2ce5L, 0x4090a7fc28335217L, 0x3801e7704d89d9d5L, 0x2ee554326ac9bca0L, 0x8911df1a827a4356L, 0x18b903e5f05a4102L, 0xea2fd99b77adf66fL, 0x000de07136bba030L });
        CURVE_IBZ[5][13] = Ibz.fromMpLimbs(8, new long[]{ 0x014f02608c670752L, 0x4db95e4d0865138aL, 0x94224a7e7a2cca26L, 0x7e33841dbdc8b2f6L, 0x15fc963338a65677L, 0xb16cdcefbe04acceL, 0x1f8f83957a5ed57bL, 0x00064be3e383e4b9L });
        CURVE_IBZ[5][14] = Ibz.fromMpLimbs(8, new long[]{ 0x535f517740f29b63L, 0x5e1c18a22f265098L, 0x23971db933e95d70L, 0x87bfcae6b98bacccL, 0x2f67f2d0b329d43fL, 0xc67d4369d2ab779cL, 0x1a2bf06b9550d065L, 0x0003bb649b2b0c6eL });
        CURVE_IBZ[5][15] = Ibz.fromMpLimbs(8, new long[]{ 0xe73d2cd10eb0d31bL, 0xbf6f5803d7ccade8L, 0xc7fe188fb276262aL, 0xd11aabcd9536435fL, 0x76ee20e57d85bca9L, 0xe746fc1a0fa5befdL, 0x15d0266488520990L, 0x00021f8ec9445fcfL });
        CURVE_IBZ[5][16] = Ibz.fromMpLimbs(8, new long[]{ 0x450717d7bb920627L, 0x8c2eb41db9a0f791L, 0xb9769570070e8ca8L, 0x1fb41b3ace35552bL, 0xc398d5864caacf9eL, 0x7e0f332c40265118L, 0xe786666361b2bc56L, 0x00041b301fd0dfc8L });
        CURVE_IBZ[5][17] = Ibz.fromMpLimbs(8, new long[]{ 0x9a8c421ff2062111L, 0x21a3da72d3abb968L, 0xdbbf0186e1339993L, 0x467968bae5c64c83L, 0xd38a918b5c3b2a20L, 0x66bfd397cf4b7855L, 0x6e16cc2fd2178f03L, 0x00041570738f6cf7L });
        CURVE_IBZ[5][18] = Ibz.fromMpLimbs(8, new long[]{ 0x0afeb6310e4808d6L, 0xba2630632c288c92L, 0xa8d0ab2a0535c07eL, 0x20997932c01fb2c4L, 0x8032e785ba4bcb69L, 0x1d56a101815e1728L, 0xb3f2660d2da000f9L, 0x0001bd465d0befe9L });
        CURVE_IBZ[5][19] = Ibz.fromMpLimbs(8, new long[]{ 0xbaf8e828446df9daL, 0x73d14be2465f086eL, 0x46896a8ff8f17357L, 0xe04be4c531caaad4L, 0x3c672a79b3553061L, 0x81f0ccd3bfd9aee7L, 0x1879999c9e4d43a9L, 0x000be4cfe02f2037L });
        CURVE_IBZ[5][20] = Ibz.fromMpLimbs(8, new long[]{ 0xca3be2b2dd4c129dL, 0x041268f99c8b6c0bL, 0xb80dae25758351a8L, 0x66e14ba1387b35d5L, 0x06503d8cf6b60754L, 0x16d2c05f214fa955L, 0x3ed3123e246f9ce4L, 0x000589642e24a07fL });
        CURVE_IBZ[5][21] = Ibz.fromMpLimbs(8, new long[]{ 0x253ca44cbc609e3fL, 0x9f9f326fa9f9a75eL, 0x5ee33889a47f14aaL, 0x62226cba933f087dL, 0x992aa815a8c9cd43L, 0xf6754cffc1d3643aL, 0xb9e452487e2af30bL, 0x0003525b2c53a454L });
        CURVE_IBZ[5][22] = Ibz.fromMpLimbs(8, new long[]{ 0x45deb681a517584dL, 0xe0fd01237c58c2eaL, 0xddc5f6696c5bfd80L, 0x37ecc7a0caa9b21aL, 0xe812e98412e7f8c6L, 0x41f59fca128aef9fL, 0x78c5f1cf5c32118fL, 0x000260d22ae39424L });
        CURVE_IBZ[5][23] = Ibz.fromMpLimbs(8, new long[]{ 0x35c41d4d22b3ed63L, 0xfbed9706637493f4L, 0x47f251da8a7cae57L, 0x991eb45ec784ca2aL, 0xf9afc2730949f8abL, 0xe92d3fa0deb056aaL, 0xc12cedc1db90631bL, 0x000a769bd1db5f80L });

        // ---- Entry [6] ----
        CURVE_FP[6][0] = new BigInteger("6c641e2f2e09bd2f7e94a752a94544bea427853c3fe884b37a84cea8986716d10cb5c2d8734e99ff6af4fb9bec99f48da362bc65cb6e33791b338eb1713dbc", 16);
        CURVE_FP[6][1] = BigInteger.ZERO;
        CURVE_FP[6][2] = BigInteger.ONE;
        CURVE_FP[6][3] = BigInteger.ZERO;
        CURVE_FP[6][4] = new BigInteger("f319078bcb826f4bdfa529d4aa51512fa909e14f0ffa212cdea133aa2619c5b4432d70b61cd3a67fdabd3ee6fb267d2368d8af1972db8cde46cce3ac5c4f6f", 16);
        CURVE_FP[6][5] = BigInteger.ZERO;
        CURVE_FP[6][6] = BigInteger.ONE;
        CURVE_FP[6][7] = BigInteger.ZERO;
        CURVE_FP[6][8] = new BigInteger("117dc75b6a65c0eb9f6e662ab8d0fc20bc98f4faeaf837db6690d36e6be2584d6f43c434ce873461370cee1b04b287fd6d27930ab55575485fdb423ae353d5d", 16);
        CURVE_FP[6][9] = new BigInteger("da0e1aa49eae3832788f957c0ddb2135ef4c51eb3f13b6bb93927014678f329ccd356683b5cb4eb3bb8bd36a4033db4820ced260c532fd29851a4a8c633200", 16);
        CURVE_FP[6][10] = BigInteger.ONE;
        CURVE_FP[6][11] = BigInteger.ZERO;
        CURVE_FP[6][12] = new BigInteger("69de7412496b7bcd8270870e41a4a3ca7cd3ab8e7cc533a9b0b59364a6e9f3db39bd0b658d2b48ee307cebc9764add141c5edf880a865d9547f115944340cb", 16);
        CURVE_FP[6][13] = new BigInteger("16fa967f9dc6d313964e01061e8bd8663f92bc8c862b9495c70db63a186e74e59e797fc576b869d7ad18358a365f6ae748d92bb034401f3dab5bdf13747c79f", 16);
        CURVE_FP[6][14] = BigInteger.ONE;
        CURVE_FP[6][15] = BigInteger.ZERO;
        CURVE_FP[6][16] = new BigInteger("3dc05c0e3809be3dcff3735045ef100c46c1c72cf4427c25875f5dc678d026cee0cf85d1644114fb0402b4e58d238d3c20bd07244c355cd23f0d5e69554c9c", 16);
        CURVE_FP[6][17] = new BigInteger("1371776e7714340465423fe753d55b83b47f18bf35b4bd641de70bb105dd1cbb0851501eaf0d2a751f4cc3e88e88ade75ae1b4663460de1ed09a5fa43c8be10", 16);
        CURVE_FP[6][18] = BigInteger.ONE;
        CURVE_FP[6][19] = BigInteger.ZERO;
        CURVE_IBZ[6][0] = Ibz.fromMpLimbs(8, new long[]{ 0xc163a798561efe45L, 0xda12b3c01fffedaaL, 0xface239051232588L, 0xb190a21d651b6e59L, 0x0d81603021b0e1b0L, 0xa91c8cef64b06542L, 0x961ae27bd947e0bdL, 0x00050ed0f20a2a3eL });
        CURVE_IBZ[6][1] = Ibz.fromMpLimbs(8, new long[]{ 0x3538ed4e4b770ff6L, 0xc49fd5473304c757L, 0x0cad4796b2ff801bL, 0x83e13e77969c58beL, 0x372066647d43a371L, 0xebbc74dce4e56c98L, 0x5bc93147c7e0aab5L, 0x000cb4007ff5537eL });
        CURVE_IBZ[6][2] = Ibz.fromMpLimbs(8, new long[]{ 0x429cfaa0ce5877ebL, 0xc196068abe89c7ddL, 0xbc4ea04a63aed249L, 0x4738fc2b64adbbb5L, 0x459d6b55918a4d4dL, 0xfe42208a748cf5abL, 0x28cc23d7378521d2L, 0x000d3406106afd9fL });
        CURVE_IBZ[6][3] = Ibz.fromMpLimbs(8, new long[]{ 0x3e9c5867a9e101bbL, 0x25ed4c3fe0001255L, 0x0531dc6faedcda77L, 0x4e6f5de29ae491a6L, 0xf27e9fcfde4f1e4fL, 0x56e373109b4f9abdL, 0x69e51d8426b81f42L, 0x000af12f0df5d5c1L });
        CURVE_IBZ[6][4] = Ibz.fromMpLimbs(8, new long[]{ 0x75f1d05088dbf3b3L, 0xe7a297c48cbe10ddL, 0x8d12d51ff1e2e6aeL, 0xc097c98a639555a8L, 0x78ce54f366aa60c3L, 0x03e199a77fb35dceL, 0x30f333393c9a8753L, 0x0007c99fc05e406eL });
        CURVE_IBZ[6][5] = Ibz.fromMpLimbs(8, new long[]{ 0xcae77bc01bf3bddeL, 0xbcb84b1a58a88d2eL, 0x4881fcf23d98ccd9L, 0x730d2e8a347366f8L, 0x58eadce94789abbfL, 0x328058d061690f54L, 0x23d267a05bd0e1f9L, 0x0007d51f18e12611L });
        CURVE_IBZ[6][6] = Ibz.fromMpLimbs(8, new long[]{ 0xea02939de36fee54L, 0x8bb39f39a7aee6dbL, 0xae5ea9abf5947f02L, 0xbecd0d9a7fc09a76L, 0xff9a30f48b68692dL, 0xc552bdfcfd43d1aeL, 0x981b33e5a4bffe0dL, 0x000c857345e8202cL });
        CURVE_IBZ[6][7] = Ibz.fromMpLimbs(8, new long[]{ 0x8a0e2faf77240c4dL, 0x185d683b7341ef22L, 0x72ed2ae00e1d1951L, 0x3f6836759c6aaa57L, 0x8731ab0c99559f3cL, 0xfc1e6658804ca231L, 0xcf0cccc6c36578acL, 0x000836603fa1bf91L });
        CURVE_IBZ[6][8] = Ibz.fromMpLimbs(8, new long[]{ 0x755771ea51a039f7L, 0x9aa76a816b5e794cL, 0x2121e387ab85d8ddL, 0xf813e27379891086L, 0xc6d59ef5b13febd5L, 0x24c4ecf314f82da2L, 0xb213b9efc8def485L, 0x000dd591e587bc4dL });
        CURVE_IBZ[6][9] = Ibz.fromMpLimbs(8, new long[]{ 0x2a9ec116133fc5d4L, 0xdacf6173aeddacf5L, 0x50136d36a33e6448L, 0x906de57159f62093L, 0xbe30b92ae4ab37c9L, 0x47ffffc8de581d49L, 0x867961286230e0cbL, 0x000d66c70c5e731cL });
        CURVE_IBZ[6][10] = Ibz.fromMpLimbs(8, new long[]{ 0x8dadd0dc2e3e55adL, 0x81af3e27e1d04e0aL, 0x5bd452f2a5fa1bb4L, 0xbdd40036ddfe2b9bL, 0x7b2921d23027f99aL, 0xec5c6864214610eeL, 0xe4a1bc15540f6bbdL, 0x0004df513d9c00eeL });
        CURVE_IBZ[6][11] = Ibz.fromMpLimbs(8, new long[]{ 0x8aa88e15ae5fc609L, 0x6558957e94a186b3L, 0xdede1c78547a2722L, 0x07ec1d8c8676ef79L, 0x392a610a4ec0142aL, 0xdb3b130ceb07d25dL, 0x4dec461037210b7aL, 0x00022a6e1a7843b2L });
        CURVE_IBZ[6][12] = Ibz.fromMpLimbs(8, new long[]{ 0xc163a798561efe45L, 0xda12b3c01fffedaaL, 0xface239051232588L, 0xb190a21d651b6e59L, 0x0d81603021b0e1b0L, 0xa91c8cef64b06542L, 0x961ae27bd947e0bdL, 0x00050ed0f20a2a3eL });
        CURVE_IBZ[6][13] = Ibz.fromMpLimbs(8, new long[]{ 0x3538ed4e4b770ff6L, 0xc49fd5473304c757L, 0x0cad4796b2ff801bL, 0x83e13e77969c58beL, 0x372066647d43a371L, 0xebbc74dce4e56c98L, 0x5bc93147c7e0aab5L, 0x000cb4007ff5537eL });
        CURVE_IBZ[6][14] = Ibz.fromMpLimbs(8, new long[]{ 0x429cfaa0ce5877ebL, 0xc196068abe89c7ddL, 0xbc4ea04a63aed249L, 0x4738fc2b64adbbb5L, 0x459d6b55918a4d4dL, 0xfe42208a748cf5abL, 0x28cc23d7378521d2L, 0x000d3406106afd9fL });
        CURVE_IBZ[6][15] = Ibz.fromMpLimbs(8, new long[]{ 0x3e9c5867a9e101bbL, 0x25ed4c3fe0001255L, 0x0531dc6faedcda77L, 0x4e6f5de29ae491a6L, 0xf27e9fcfde4f1e4fL, 0x56e373109b4f9abdL, 0x69e51d8426b81f42L, 0x000af12f0df5d5c1L });
        CURVE_IBZ[6][16] = Ibz.fromMpLimbs(8, new long[]{ 0xbaf8e828446df9daL, 0x73d14be2465f086eL, 0x46896a8ff8f17357L, 0xe04be4c531caaad4L, 0x3c672a79b3553061L, 0x81f0ccd3bfd9aee7L, 0x1879999c9e4d43a9L, 0x000be4cfe02f2037L });
        CURVE_IBZ[6][17] = Ibz.fromMpLimbs(8, new long[]{ 0x6573bde00df9deefL, 0xde5c258d2c544697L, 0x2440fe791ecc666cL, 0xb98697451a39b37cL, 0x2c756e74a3c4d5dfL, 0x99402c6830b487aaL, 0x91e933d02de870fcL, 0x000bea8f8c709308L });
        CURVE_IBZ[6][18] = Ibz.fromMpLimbs(8, new long[]{ 0xf50149cef1b7f72aL, 0x45d9cf9cd3d7736dL, 0x572f54d5faca3f81L, 0xdf6686cd3fe04d3bL, 0x7fcd187a45b43496L, 0xe2a95efe7ea1e8d7L, 0x4c0d99f2d25fff06L, 0x000e42b9a2f41016L });
        CURVE_IBZ[6][19] = Ibz.fromMpLimbs(8, new long[]{ 0x450717d7bb920627L, 0x8c2eb41db9a0f791L, 0xb9769570070e8ca8L, 0x1fb41b3ace35552bL, 0xc398d5864caacf9eL, 0x7e0f332c40265118L, 0xe786666361b2bc56L, 0x00041b301fd0dfc8L });
        CURVE_IBZ[6][20] = Ibz.fromMpLimbs(8, new long[]{ 0x8865a159619b9e37L, 0x57ce0b3b85c2ab15L, 0x8cf0feb0a8d68108L, 0xc3a96936c7e1ef13L, 0x7ba27c689c5dd8f2L, 0x22eb845b4c63f4daL, 0x701924f337a0beddL, 0x0003b81c69052855L });
        CURVE_IBZ[6][21] = Ibz.fromMpLimbs(8, new long[]{ 0xadd1c1ee130992b5L, 0x4a4faf0c49110165L, 0xacc0926fd4b25374L, 0xc1887c68eb63fd2fL, 0x9a226cfe152e41ceL, 0x5fef438c09330adbL, 0x8c5b773282aae17aL, 0x0006dcee4cd4fa7bL });
        CURVE_IBZ[6][22] = Ibz.fromMpLimbs(8, new long[]{ 0x91b3743ec00c77b7L, 0x4b6bc9e803bec92cL, 0x2be7857fed1b519cL, 0xd5ec3a2164a02270L, 0xa58f175a2392d5d1L, 0x18755f4639085c36L, 0x8eda7e0bcd4aee40L, 0x000d6e24c28c87e0L });
        CURVE_IBZ[6][23] = Ibz.fromMpLimbs(8, new long[]{ 0x779a5ea69e6461c9L, 0xa831f4c47a3d54eaL, 0x730f014f57297ef7L, 0x3c5696c9381e10ecL, 0x845d839763a2270dL, 0xdd147ba4b39c0b25L, 0x8fe6db0cc85f4122L, 0x000c47e396fad7aaL });

    }

    private EndomorphismActionLvl5()
    {
    }
}
