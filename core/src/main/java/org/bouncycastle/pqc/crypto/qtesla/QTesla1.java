package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

class QTesla1
{

    private static final int GENERATOR_A = 19;
    private static final int INVERSE_NUMBER_THEORETIC_TRANSFORM = 113307;
    private static final int PARAM_N = 512;
    private static final int PARAM_H = 30;
    private static final int PARAM_Q = 4205569;
    private static final long PARAM_QINV = 3098553343L;
    private static final int PARAM_Q_LOG = 23;
    private static final int PARAM_B = 1048575;
    private static final int PARAM_B_BITS = 20;
    private static final int PARAM_D = 21;
    private static final int PARAM_R = 1081347;
    private static final int KEY_GENERATOR_BOUND_S = 1586;
    private static final int U = KEY_GENERATOR_BOUND_S;
    private static final int KEY_GENERATOR_BOUND_E = 1586;
    private static final int REJECTION = KEY_GENERATOR_BOUND_E;
    private static final int PARAM_S_BITS = 9;


    private static final int CRYPTO_RANDOMBYTES = 32;
    private static final int CRYPTO_SEEDBYTES = 32;
    private static final int CRYPTO_C_BYTES = 32;
    private static final int HM_BYTES = 64;
    static final int SIGNATURE_SIZE = (PARAM_N * PARAM_D + 7) / 8 + CRYPTO_C_BYTES;


    //  static final int CRYPTO_BYTES = ((PARAM_N * (PARAM_B_BITS + 1) + 7) / 8 + CRYPTO_C_BYTES);
    // Contains polynomial s and e, and seeds seed_a and seed_y
    static final int CRYPTO_SECRETKEYBYTES = (2 * PARAM_S_BITS * PARAM_N / 8 + 2 * CRYPTO_SEEDBYTES);
    // Contains seed_a and polynomial t
    static final int CRYPTO_PUBLICKEYBYTES = ((PARAM_N * PARAM_Q_LOG + 7) / 8 + CRYPTO_SEEDBYTES);




    /* Heuristic qTESLA Security Category-1 */

    private static final int[] ZETA_I = {                    /* 512-Entry */

        3359531, 2189080, 370173, 677362, 3132616, 2989204, 2362181, 1720831,
        1203721, 3239574, 641414, 3932234, 3634017, 2251707, 355329, 4152265,
        1356023, 4021436, 1465601, 4145892, 3348341, 675693, 1598775, 2799365,
        3336234, 3856839, 603157, 1381183, 1069471, 2142038, 2877387, 2653969,
        2055310, 3837123, 3141231, 1951522, 2375048, 445122, 1689285, 3664328,
        676319, 3844199, 3669724, 1009639, 3666694, 1585701, 2102892, 966523,
        4069555, 3246046, 846643, 2088895, 4068915, 3715722, 4119007, 230501,
        1626667, 2119752, 1171284, 3153846, 17941, 1316589, 1814059, 3185686,
        1183551, 2533671, 4152595, 2616162, 3015757, 194860, 1601807, 1271569,
        139534, 2581874, 2183200, 2060697, 1036874, 646550, 2823563, 3312274,
        391700, 99391, 638903, 2397164, 3924868, 3315551, 1170767, 422539,
        1801679, 166402, 742283, 222557, 522210, 3415900, 177835, 3243355,
        4196855, 1821376, 1290490, 3624896, 1546898, 1282351, 3960516, 835944,
        2251927, 90910, 3034838, 4082965, 2311377, 3512216, 2652413, 2191140,
        302935, 3866228, 2007511, 744185, 2801160, 3993630, 592962, 795067,
        2822609, 3471782, 3710854, 1824985, 1495256, 3906591, 3111335, 3902620,
        11234, 1586236, 3698245, 492808, 2729660, 3369937, 1869963, 7244,
        1453951, 1757304, 1005437, 3668653, 1821321, 4203686, 1192473, 113408,
        2904803, 1346735, 4161890, 711442, 4020959, 1164150, 2139014, 4134238,
        731747, 3856202, 2351090, 3382729, 2644693, 617098, 2796766, 1911274,
        552932, 2476095, 1801797, 1381577, 2338697, 1336590, 2798544, 459121,
        3555631, 741068, 2302686, 1883916, 2148181, 2471691, 2174195, 1684042,
        3266036, 227434, 4107207, 2910899, 3427718, 2011049, 2706372, 4182237,
        1243355, 2908998, 15068, 1966206, 2157082, 4114100, 1846352, 230880,
        1161075, 1259576, 1212857, 1697580, 39500, 3079648, 2529577, 2082167,
        50282, 476606, 1494601, 1334236, 3349015, 1600445, 413060, 3104844,
        139283, 1688398, 3230017, 1009712, 614253, 2973529, 2077610, 2218429,
        4185344, 254428, 506799, 196179, 3310395, 4183346, 3897905, 2234639,
        1859699, 3322900, 2151737, 1904476, 2457045, 383438, 2543045, 2985636,
        731083, 1609871, 2171434, 535413, 2666041, 405934, 3303186, 802974,
        3573046, 1760267, 2758359, 2102800, 1512274, 3981750, 1838169, 2101846,
        1363757, 1342163, 3608830, 321523, 1072908, 855117, 1679204, 3624675,
        3183259, 2438624, 407591, 1549799, 490068, 2769318, 3185950, 990968,
        3700398, 2715638, 3672301, 3203080, 1775408, 2071611, 778637, 2335351,
        3317014, 3768001, 571163, 2618746, 1028702, 3174131, 764504, 1386439,
        4188876, 1131998, 1057083, 39651, 2588805, 2519763, 3838931, 4130059,
        1893001, 2066802, 572208, 2529031, 220967, 3880345, 1820301, 2205978,
        3036090, 1648541, 4012391, 1432533, 3068186, 1645476, 1397186, 2112498,
        4168213, 1234734, 1648052, 1803157, 2011730, 1648875, 2547914, 437873,
        2460774, 3403214, 2690605, 2567052, 739775, 1854855, 520305, 3661464,
        1120944, 1245195, 1147367, 2571134, 696367, 3009976, 834907, 1691662,
        1384090, 2795844, 1813845, 3425954, 4194068, 1317042, 2056507, 470026,
        3097617, 2678203, 3077203, 2116013, 4155561, 2844478, 1467696, 4150754,
        992951, 471101, 4062883, 1584992, 2252609, 3322854, 1597940, 3581574,
        1115369, 4153697, 3236495, 4075586, 2066340, 1262360, 2730720, 3664692,
        2681478, 2929295, 3831713, 3683420, 2511172, 3689552, 2645837, 2414330,
        857564, 3703853, 468246, 1574274, 3590547, 2348366, 1565207, 1815326,
        2508730, 1749217, 465029, 260794, 1630097, 3019607, 3872759, 1053481,
        3958758, 3415305, 54348, 2516, 3045515, 3011542, 1951553, 1882613,
        1729323, 801736, 3662451, 909634, 2949838, 2598628, 1652685, 1945350,
        3221627, 2879417, 2732226, 3883548, 1891328, 3215710, 3159721, 1318941,
        2153764, 1870381, 4039453, 3375151, 2655219, 4089723, 1388508, 3436490,
        3956335, 2748982, 4111030, 328986, 1780674, 2570336, 2608795, 2600572,
        2748827, 790335, 1988956, 3946950, 1789942, 710384, 3900335, 457139,
        2550557, 3042298, 1952120, 1998308, 259999, 2361900, 119023, 3680445,
        1893737, 4050016, 2696786, 567472, 3085466, 1580931, 1360307, 3075154,
        904205, 1306381, 3257843, 2926984, 2065676, 3221598, 2551064, 1580354,
        1636374, 699891, 1821560, 670885, 947258, 2908840, 3049868, 1038075,
        1701447, 2439140, 2048478, 3183312, 2224644, 320592, 3304074, 2611056,
        422256, 1752180, 2217951, 2900510, 1321050, 2797671, 312886, 2624042,
        3166863, 908176, 24947, 152205, 2891981, 189908, 1959427, 1365987,
        2071767, 1932065, 3185693, 3889374, 3644713, 79765, 969178, 11268,
        1992233, 1579325, 1224905, 3741957, 1894871, 3060100, 1787540, 4194180,
        1396587, 2745514, 26822, 695515, 2348201, 249698, 2988539, 1081347

    };

    private static final int[] ZETA_INVERSE_I = {            /* 512-Entry */

        1217030, 3955871, 1857368, 3510054, 4178747, 1460055, 2808982, 11389,
        2418029, 1145469, 2310698, 463612, 2980664, 2626244, 2213336, 4194301,
        3236391, 4125804, 560856, 316195, 1019876, 2273504, 2133802, 2839582,
        2246142, 4015661, 1313588, 4053364, 4180622, 3297393, 1038706, 1581527,
        3892683, 1407898, 2884519, 1305059, 1987618, 2453389, 3783313, 1594513,
        901495, 3884977, 1980925, 1022257, 2157091, 1766429, 2504122, 3167494,
        1155701, 1296729, 3258311, 3534684, 2384009, 3505678, 2569195, 2625215,
        1654505, 983971, 2139893, 1278585, 947726, 2899188, 3301364, 1130415,
        2845262, 2624638, 1120103, 3638097, 1508783, 155553, 2311832, 525124,
        4086546, 1843669, 3945570, 2207261, 2253449, 1163271, 1655012, 3748430,
        305234, 3495185, 2415627, 258619, 2216613, 3415234, 1456742, 1604997,
        1596774, 1635233, 2424895, 3876583, 94539, 1456587, 249234, 769079,
        2817061, 115846, 1550350, 830418, 166116, 2335188, 2051805, 2886628,
        1045848, 989859, 2314241, 322021, 1473343, 1326152, 983942, 2260219,
        2552884, 1606941, 1255731, 3295935, 543118, 3403833, 2476246, 2322956,
        2254016, 1194027, 1160054, 4203053, 4151221, 790264, 246811, 3152088,
        332810, 1185962, 2575472, 3944775, 3740540, 2456352, 1696839, 2390243,
        2640362, 1857203, 615022, 2631295, 3737323, 501716, 3348005, 1791239,
        1559732, 516017, 1694397, 522149, 373856, 1276274, 1524091, 540877,
        1474849, 2943209, 2139229, 129983, 969074, 51872, 3090200, 623995,
        2607629, 882715, 1952960, 2620577, 142686, 3734468, 3212618, 54815,
        2737873, 1361091, 50008, 2089556, 1128366, 1527366, 1107952, 3735543,
        2149062, 2888527, 11501, 779615, 2391724, 1409725, 2821479, 2513907,
        3370662, 1195593, 3509202, 1634435, 3058202, 2960374, 3084625, 544105,
        3685264, 2350714, 3465794, 1638517, 1514964, 802355, 1744795, 3767696,
        1657655, 2556694, 2193839, 2402412, 2557517, 2970835, 37356, 2093071,
        2808383, 2560093, 1137383, 2773036, 193178, 2557028, 1169479, 1999591,
        2385268, 325224, 3984602, 1676538, 3633361, 2138767, 2312568, 75510,
        366638, 1685806, 1616764, 4165918, 3148486, 3073571, 16693, 2819130,
        3441065, 1031438, 3176867, 1586823, 3634406, 437568, 888555, 1870218,
        3426932, 2133958, 2430161, 1002489, 533268, 1489931, 505171, 3214601,
        1019619, 1436251, 3715501, 2655770, 3797978, 1766945, 1022310, 580894,
        2526365, 3350452, 3132661, 3884046, 596739, 2863406, 2841812, 2103723,
        2367400, 223819, 2693295, 2102769, 1447210, 2445302, 632523, 3402595,
        902383, 3799635, 1539528, 3670156, 2034135, 2595698, 3474486, 1219933,
        1662524, 3822131, 1748524, 2301093, 2053832, 882669, 2345870, 1970930,
        307664, 22223, 895174, 4009390, 3698770, 3951141, 20225, 1987140,
        2127959, 1232040, 3591316, 3195857, 975552, 2517171, 4066286, 1100725,
        3792509, 2605124, 856554, 2871333, 2710968, 3728963, 4155287, 2123402,
        1675992, 1125921, 4166069, 2507989, 2992712, 2945993, 3044494, 3974689,
        2359217, 91469, 2048487, 2239363, 4190501, 1296571, 2962214, 23332,
        1499197, 2194520, 777851, 1294670, 98362, 3978135, 939533, 2521527,
        2031374, 1733878, 2057388, 2321653, 1902883, 3464501, 649938, 3746448,
        1407025, 2868979, 1866872, 2823992, 2403772, 1729474, 3652637, 2294295,
        1408803, 3588471, 1560876, 822840, 1854479, 349367, 3473822, 71331,
        2066555, 3041419, 184610, 3494127, 43679, 2858834, 1300766, 4092161,
        3013096, 1883, 2384248, 536916, 3200132, 2448265, 2751618, 4198325,
        2335606, 835632, 1475909, 3712761, 507324, 2619333, 4194335, 302949,
        1094234, 298978, 2710313, 2380584, 494715, 733787, 1382960, 3410502,
        3612607, 211939, 1404409, 3461384, 2198058, 339341, 3902634, 2014429,
        1553156, 693353, 1894192, 122604, 1170731, 4114659, 1953642, 3369625,
        245053, 2923218, 2658671, 580673, 2915079, 2384193, 8714, 962214,
        4027734, 789669, 3683359, 3983012, 3463286, 4039167, 2403890, 3783030,
        3034802, 890018, 280701, 1808405, 3566666, 4106178, 3813869, 893295,
        1382006, 3559019, 3168695, 2144872, 2022369, 1623695, 4066035, 2934000,
        2603762, 4010709, 1189812, 1589407, 52974, 1671898, 3022018, 1019883,
        2391510, 2888980, 4187628, 1051723, 3034285, 2085817, 2578902, 3975068,
        86562, 489847, 136654, 2116674, 3358926, 959523, 136014, 3239046,
        2102677, 2619868, 538875, 3195930, 535845, 361370, 3529250, 541241,
        2516284, 3760447, 1830521, 2254047, 1064338, 368446, 2150259, 1551600,
        1328182, 2063531, 3136098, 2824386, 3602412, 348730, 869335, 1406204,
        2606794, 3529876, 857228, 59677, 2739968, 184133, 2849546, 53304,
        3850240, 1953862, 571552, 273335, 3564155, 965995, 3001848, 2484738,
        1843388, 1216365, 1072953, 3528207, 3835396, 2016489, 846038, 3124222

    };


    /**
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-1 and
     * Security Category-3 (Option for Size or Speed)
     *
     * @param message       Message to be Signed
     * @param messageOffset Starting Point of the Message to be Signed
     * @param messageLength Length of the Message to be Signed
     * @param signature     Output Package Containing Signature
     * @param privateKey    Private Key
     * @param secureRandom  Source of Randomness
     * @return 0                                    Successful Execution
     */
    static int generateSignature(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom
    )
    {

        byte[] C = new byte[CRYPTO_C_BYTES];
        byte[] randomness = new byte[CRYPTO_SEEDBYTES];
        byte[] randomnessInput = new byte[CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + HM_BYTES];
        byte[] seed = new byte[CRYPTO_SEEDBYTES * 2];
        byte[] temporaryRandomnessInput = new byte[CRYPTO_RANDOMBYTES];
        int[] positionList = new int[PARAM_H];
        short[] signList = new short[PARAM_H];
        short[] secretPolynomial = new short[PARAM_N];
        short[] errorPolynomial = new short[PARAM_N];

        int[] A = new int[PARAM_N];
        int[] V = new int[PARAM_N];
        int[] Y = new int[PARAM_N];
        int[] Z = new int[PARAM_N];
        int[] SC = new int[PARAM_N];
        int[] EC = new int[PARAM_N];

        /* Domain Separator for Sampling Y */
        int nonce = 0;


        decodePrivateKey(seed, secretPolynomial, errorPolynomial, privateKey);


//        rng.randomByte(randomnessInput, CRYPTO_RANDOMBYTES, CRYPTO_RANDOMBYTES);
        secureRandom.nextBytes(temporaryRandomnessInput);
        System.arraycopy(temporaryRandomnessInput, 0, randomnessInput, CRYPTO_RANDOMBYTES, CRYPTO_RANDOMBYTES);

        System.arraycopy(seed, CRYPTO_SEEDBYTES, randomnessInput, 0, CRYPTO_SEEDBYTES);


        HashUtils.secureHashAlgorithmKECCAK128(
            randomnessInput, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES, HM_BYTES, message, messageOffset, messageLength
        );

        HashUtils.secureHashAlgorithmKECCAK128(
            randomness, 0, CRYPTO_SEEDBYTES, randomnessInput, 0, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + HM_BYTES
        );


        QTesla1Polynomial.polynomialUniform(A, seed, 0);

        /* Loop Due to Possible Rejection */
        while (true)
        {

            /* Sample Y Uniformly Random from -B to B */
            sampleY(Y, randomness, 0, ++nonce);

            /* V = A * Y Modulo Q */
            QTesla1Polynomial.polynomialMultiplication(V, A, Y);

            hashFunction(C, 0, V, randomnessInput, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES);

            /* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
            encodeC(positionList, signList, C, 0, PARAM_N, PARAM_H);

            QTesla1Polynomial.sparsePolynomialMultiplication16(SC, secretPolynomial, positionList, signList);

            /* Z = Y + EC Modulo Q */
            QTesla1Polynomial.polynomialAddition(Z, Y, SC);

            /* Rejection Sampling */
            if (testRejection(Z))
            {

                continue;

            }

            QTesla1Polynomial.sparsePolynomialMultiplication16(EC, errorPolynomial, positionList, signList);

            /* V = V - EC modulo Q */
            QTesla1Polynomial.polynomialSubtractionCorrection(V, V, EC);

            if (testCorrectness(V))
            {
                continue;
            }

            /* Pack Signature */
            encodeSignature(signature, 0, C, 0, Z);


            return 0;

        }

    }

    /**
     * Check bounds for signature vector z during signing. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
     * This function does not leak any information about the coefficient that fails the test.
     *
     * @param Z polynomial to test.
     * @return
     */
    private static boolean testRejection(int[] Z)
    {

        int valid = 0;

        for (int i = 0; i < PARAM_N; i++)
        {
            valid |= (PARAM_B - U) - absolute(Z[i]);

        }

        return (valid >>> 31) > 0;

    }

    private static int absolute(int value)
    {

        return ((value >> 31) ^ value) - (value >> 31);

    }

    private static long absolute(long value)
    {

        return ((value >> 63) ^ value) - (value >> 63);

    }


    private static void hashFunction(byte[] output, int outputOffset, int[] V, final byte[] message, int messageOffset)
    {

        int mask;
        int cL;

        byte[] T = new byte[PARAM_N + HM_BYTES];

        for (int i = 0; i < PARAM_N; i++)
        {
            /* If V[i] > Q / 2 Then V[i] = V[i] - Q */
            mask = (PARAM_Q / 2 - V[i]) >> 31;
            V[i] = ((V[i] - PARAM_Q) & mask) | (V[i] & (~mask));
            cL = V[i] & ((1 << PARAM_D) - 1);
            /* If cL > 2 ^ (d - 1) Then cL = cL - 2 ^ d */
            mask = ((1 << (PARAM_D - 1)) - cL) >> 31;
            cL = ((cL - (1 << PARAM_D)) & mask) | (cL & (~mask));
            T[i] = (byte)((V[i] - cL) >> PARAM_D);

        }

        System.arraycopy(message, messageOffset, T, PARAM_N, HM_BYTES);
        HashUtils.secureHashAlgorithmKECCAK128(output, outputOffset, CRYPTO_C_BYTES, T, 0, PARAM_N + HM_BYTES);

    }

    /**
     * Check bounds for w = v - ec during signature verification.
     * This function leaks the position of the coefficient that fails the test (but this is independent of the secret data).
     * It does not leak the sign of the coefficients.
     *
     * @param V the polynomial to test.
     * @return Returns false if valid, otherwise outputs true if invalid (rejected).
     */
    private static boolean testCorrectness(int[] V)
    {

        int mask;
        int left;
        int right;
        int test1;
        int test2;

        for (int i = 0; i < PARAM_N; i++)
        {

            mask = (PARAM_Q / 2 - V[i]) >> 31;
            right = ((V[i] - PARAM_Q) & mask) | (V[i] & (~mask));
            test1 = (~(absolute(right) - (PARAM_Q / 2 - REJECTION))) >>> 31;
            left = right;
            right = (right + (1 << (PARAM_D - 1)) - 1) >> PARAM_D;
            right = left - (right << PARAM_D);
            test2 = (~(absolute(right) - ((1 << (PARAM_D - 1)) - REJECTION))) >>> 31;

            /* Two Tests Fail */
            if ((test1 | test2) == 1)
            {

                return true;

            }

        }

        return false;

    }

    /**
     * Encode secret and error polynomials into a private key.
     *
     * @param privateKey Private key is encoded here.
     * @param s          The secret polynomial.
     * @param e          The error polynomial.
     * @param seed       The seed.
     * @param seedOffset Offset for reading seed.
     */
    static void encodePrivateKey(byte[] privateKey, final int[] s, final int[] e, final byte[] seed, int seedOffset)
    {

        int j = 0;

        for (int i = 0; i < PARAM_N; i += 8)
        {
            privateKey[j + 0] = (byte)s[i + 0];
            privateKey[j + 1] = (byte)(((s[i + 0] >> 8) & 0x01) | (s[i + 1] << 1));
            privateKey[j + 2] = (byte)(((s[i + 1] >> 7) & 0x03) | (s[i + 2] << 2));
            privateKey[j + 3] = (byte)(((s[i + 2] >> 6) & 0x07) | (s[i + 3] << 3));
            privateKey[j + 4] = (byte)(((s[i + 3] >> 5) & 0x0F) | (s[i + 4] << 4));
            privateKey[j + 5] = (byte)(((s[i + 4] >> 4) & 0x1F) | (s[i + 5] << 5));
            privateKey[j + 6] = (byte)(((s[i + 5] >> 3) & 0x3F) | (s[i + 6] << 6));
            privateKey[j + 7] = (byte)(((s[i + 6] >> 2) & 0x7F) | (s[i + 7] << 7));
            privateKey[j + 8] = (byte)(s[i + 7] >> 1);

            j += 9;
        }

        for (int i = 0; i < PARAM_N; i += 8)
        {
            privateKey[j + 0] = (byte)e[i + 0];
            privateKey[j + 1] = (byte)(((e[i + 0] >> 8) & 0x01) | (e[i + 1] << 1));
            privateKey[j + 2] = (byte)(((e[i + 1] >> 7) & 0x03) | (e[i + 2] << 2));
            privateKey[j + 3] = (byte)(((e[i + 2] >> 6) & 0x07) | (e[i + 3] << 3));
            privateKey[j + 4] = (byte)(((e[i + 3] >> 5) & 0x0F) | (e[i + 4] << 4));
            privateKey[j + 5] = (byte)(((e[i + 4] >> 4) & 0x1F) | (e[i + 5] << 5));
            privateKey[j + 6] = (byte)(((e[i + 5] >> 3) & 0x3F) | (e[i + 6] << 6));
            privateKey[j + 7] = (byte)(((e[i + 6] >> 2) & 0x7F) | (e[i + 7] << 7));
            privateKey[j + 8] = (byte)(e[i + 7] >> 1);
            j += 9;
        }


        System.arraycopy(seed, seedOffset, privateKey, PARAM_N * PARAM_S_BITS * 2 / 8, CRYPTO_SEEDBYTES * 2);


    }


    /**
     * Decode an encoded private key extracting secret and error polynomials and the seed.
     *
     * @param seed       The seed.
     * @param s          secret polynomial.
     * @param e          the error polynomial.
     * @param privateKey encoded private key.
     */
    static void decodePrivateKey(byte[] seed, short[] s, short[] e, final byte[] privateKey)
    {

        int j = 0;
        for (int i = 0; i < PARAM_N; i += 8)
        {

            s[i + 0] = (short)((privateKey[j + 0] & 0xFF) | ((privateKey[j + 1] & 0xFF) << 31) >> 23);
            s[i + 1] = (short)(((privateKey[j + 1] & 0xFF) >>> 1) | ((privateKey[j + 2] & 0xFF) << 30) >> 23);
            s[i + 2] = (short)(((privateKey[j + 2] & 0xFF) >>> 2) | ((privateKey[j + 3] & 0xFF) << 29) >> 23);
            s[i + 3] = (short)(((privateKey[j + 3] & 0xFF) >>> 3) | ((privateKey[j + 4] & 0xFF) << 28) >> 23);
            s[i + 4] = (short)(((privateKey[j + 4] & 0xFF) >>> 4) | ((privateKey[j + 5] & 0xFF) << 27) >> 23);
            s[i + 5] = (short)(((privateKey[j + 5] & 0xFF) >>> 5) | ((privateKey[j + 6] & 0xFF) << 26) >> 23);
            s[i + 6] = (short)(((privateKey[j + 6] & 0xFF) >>> 6) | ((privateKey[j + 7] & 0xFF) << 25) >> 23);
            s[i + 7] = (short)(((privateKey[j + 7] & 0xFF) >>> 7) | (privateKey[j + 8] << 1)); // j+8 is to be treated as signed.
            j += 9;
        }

        for (int i = 0; i < PARAM_N; i += 8)
        {
            e[i + 0] = (short)((privateKey[j + 0] & 0xFF) | ((privateKey[j + 1] & 0xFF) << 31) >> 23);
            e[i + 1] = (short)(((privateKey[j + 1] & 0xFF) >>> 1) | ((privateKey[j + 2] & 0xFF) << 30) >> 23);
            e[i + 2] = (short)(((privateKey[j + 2] & 0xFF) >>> 2) | ((privateKey[j + 3] & 0xFF) << 29) >> 23);
            e[i + 3] = (short)(((privateKey[j + 3] & 0xFF) >>> 3) | ((privateKey[j + 4] & 0xFF) << 28) >> 23);
            e[i + 4] = (short)(((privateKey[j + 4] & 0xFF) >>> 4) | ((privateKey[j + 5] & 0xFF) << 27) >> 23);
            e[i + 5] = (short)(((privateKey[j + 5] & 0xFF) >>> 5) | ((privateKey[j + 6] & 0xFF) << 26) >> 23);
            e[i + 6] = (short)(((privateKey[j + 6] & 0xFF) >>> 6) | ((privateKey[j + 7] & 0xFF) << 25) >> 23);
            e[i + 7] = (short)(((privateKey[j + 7] & 0xFF) >>> 7) | (privateKey[j + 8] << 1)); // j+8 to be treated as signed.
            j += 9;
        }

        System.arraycopy(privateKey, PARAM_N * PARAM_S_BITS * 2 / 8, seed, 0, CRYPTO_SEEDBYTES * 2);


    }


    static void encodePublicKey(byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset)
    {

        int j = 0;

        for (int i = 0; i < PARAM_N * PARAM_Q_LOG / 32; i += PARAM_Q_LOG)
        {

            store32(publicKey, 4 * (i + 0), (int)(T[j + 0] | (T[j + 1] << 23)));
            store32(publicKey, 4 * (i + 1), (int)((T[j + 1] >> 9) | (T[j + 2] << 14)));
            store32(publicKey, 4 * (i + 2), (int)((T[j + 2] >> 18) | (T[j + 3] << 5) | (T[j + 4] << 28)));
            store32(publicKey, 4 * (i + 3), (int)((T[j + 4] >> 4) | (T[j + 5] << 19)));
            store32(publicKey, 4 * (i + 4), (int)((T[j + 5] >> 13) | (T[j + 6] << 10)));
            store32(publicKey, 4 * (i + 5), (int)((T[j + 6] >> 22) | (T[j + 7] << 1) | (T[j + 8] << 24)));
            store32(publicKey, 4 * (i + 6), (int)((T[j + 8] >> 8) | (T[j + 9] << 15)));
            store32(publicKey, 4 * (i + 7), (int)((T[j + 9] >> 17) | (T[j + 10] << 6) | (T[j + 11] << 29)));
            store32(publicKey, 4 * (i + 8), (int)((T[j + 11] >> 3) | (T[j + 12] << 20)));
            store32(publicKey, 4 * (i + 9), (int)((T[j + 12] >> 12) | (T[j + 13] << 11)));
            store32(publicKey, 4 * (i + 10), (int)((T[j + 13] >> 21) | (T[j + 14] << 2) | (T[j + 15] << 25)));
            store32(publicKey, 4 * (i + 11), (int)((T[j + 15] >> 7) | (T[j + 16] << 16)));
            store32(publicKey, 4 * (i + 12), (int)((T[j + 16] >> 16) | (T[j + 17] << 7) | (T[j + 18] << 30)));
            store32(publicKey, 4 * (i + 13), (int)((T[j + 18] >> 2) | (T[j + 19] << 21)));
            store32(publicKey, 4 * (i + 14), (int)((T[j + 19] >> 11) | (T[j + 20] << 12)));
            store32(publicKey, 4 * (i + 15), (int)((T[j + 20] >> 20) | (T[j + 21] << 3) | (T[j + 22] << 26)));
            store32(publicKey, 4 * (i + 16), (int)((T[j + 22] >> 6) | (T[j + 23] << 17)));
            store32(publicKey, 4 * (i + 17), (int)((T[j + 23] >> 15) | (T[j + 24] << 8) | (T[j + 25] << 31)));
            store32(publicKey, 4 * (i + 18), (int)((T[j + 25] >> 1) | (T[j + 26] << 22)));
            store32(publicKey, 4 * (i + 19), (int)((T[j + 26] >> 10) | (T[j + 27] << 13)));
            store32(publicKey, 4 * (i + 20), (int)((T[j + 27] >> 19) | (T[j + 28] << 4) | (T[j + 29] << 27)));
            store32(publicKey, 4 * (i + 21), (int)((T[j + 29] >> 5) | (T[j + 30] << 18)));
            store32(publicKey, 4 * (i + 22), (int)((T[j + 30] >> 14) | (T[j + 31] << 9)));

            j += 32;

        }

        System.arraycopy(seedA, seedAOffset, publicKey, PARAM_N * PARAM_Q_LOG / 8, CRYPTO_SEEDBYTES);

    }


    static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int mask = (1 << PARAM_Q_LOG) - 1;

        for (int i = 0; i < PARAM_N; i += 32)
        {

            publicKey[i + 0] = load32(publicKeyInput, 4 * (j + 0)) & mask;

            publicKey[i + 1] = ((load32(publicKeyInput, 4 * (j + 0)) >>> 23) |
                (load32(publicKeyInput, 4 * (j + 1)) << 9)) & mask;

            publicKey[i + 2] = ((load32(publicKeyInput, 4 * (j + 1)) >>> 14) |
                (load32(publicKeyInput, 4 * (j + 2)) << 18)) & mask;

            publicKey[i + 3] = (load32(publicKeyInput, 4 * (j + 2)) >>> 5) & mask;

            publicKey[i + 4] = ((load32(publicKeyInput, 4 * (j + 2)) >>> 28) |
                (load32(publicKeyInput, 4 * (j + 3)) << 4)) & mask;

            publicKey[i + 5] = ((load32(publicKeyInput, 4 * (j + 3)) >>> 19) |
                (load32(publicKeyInput, 4 * (j + 4)) << 13)) & mask;

            publicKey[i + 6] = ((load32(publicKeyInput, 4 * (j + 4)) >>> 10) |
                (load32(publicKeyInput, 4 * (j + 5)) << 22)) & mask;

            publicKey[i + 7] = (load32(publicKeyInput, 4 * (j + 5)) >>> 1) & mask;

            publicKey[i + 8] = ((load32(publicKeyInput, 4 * (j + 5)) >>> 24) |
                (load32(publicKeyInput, 4 * (j + 6)) << 8)) & mask;

            publicKey[i + 9] = ((load32(publicKeyInput, 4 * (j + 6)) >>> 15) |
                (load32(publicKeyInput, 4 * (j + 7)) << 17)) & mask;

            publicKey[i + 10] = (load32(publicKeyInput, 4 * (j + 7)) >>> 6) & mask;

            publicKey[i + 11] = ((load32(publicKeyInput, 4 * (j + 7)) >>> 29) |
                (load32(publicKeyInput, 4 * (j + 8)) << 3)) & mask;

            publicKey[i + 12] = ((load32(publicKeyInput, 4 * (j + 8)) >>> 20) |
                (load32(publicKeyInput, 4 * (j + 9)) << 12)) & mask;

            publicKey[i + 13] = ((load32(publicKeyInput, 4 * (j + 9)) >>> 11) |
                (load32(publicKeyInput, 4 * (j + 10)) << 21)) & mask;

            publicKey[i + 14] = (load32(publicKeyInput, 4 * (j + 10)) >>> 2) & mask;

            publicKey[i + 15] = ((load32(publicKeyInput, 4 * (j + 10)) >>> 25) |
                (load32(publicKeyInput, 4 * (j + 11)) << 7)) & mask;

            publicKey[i + 16] = ((load32(publicKeyInput, 4 * (j + 11)) >>> 16) |
                (load32(publicKeyInput, 4 * (j + 12)) << 16)) & mask;

            publicKey[i + 17] = (load32(publicKeyInput, 4 * (j + 12)) >>> 7) & mask;

            publicKey[i + 18] = ((load32(publicKeyInput, 4 * (j + 12)) >>> 30) |
                (load32(publicKeyInput, 4 * (j + 13)) << 2)) & mask;

            publicKey[i + 19] = ((load32(publicKeyInput, 4 * (j + 13)) >>> 21) |
                (load32(publicKeyInput, 4 * (j + 14)) << 11)) & mask;

            publicKey[i + 20] = ((load32(publicKeyInput, 4 * (j + 14)) >>> 12) |
                (load32(publicKeyInput, 4 * (j + 15)) << 20)) & mask;

            publicKey[i + 21] = (load32(publicKeyInput, 4 * (j + 15)) >>> 3) & mask;

            publicKey[i + 22] = ((load32(publicKeyInput, 4 * (j + 15)) >>> 26) |
                (load32(publicKeyInput, 4 * (j + 16)) << 6)) & mask;

            publicKey[i + 23] = ((load32(publicKeyInput, 4 * (j + 16)) >>> 17) |
                (load32(publicKeyInput, 4 * (j + 17)) << 15)) & mask;

            publicKey[i + 24] = (load32(publicKeyInput, 4 * (j + 17)) >>> 8) & mask;

            publicKey[i + 25] = ((load32(publicKeyInput, 4 * (j + 17)) >>> 31) |
                (load32(publicKeyInput, 4 * (j + 18)) << 1)) & mask;

            publicKey[i + 26] = ((load32(publicKeyInput, 4 * (j + 18)) >>> 22) |
                (load32(publicKeyInput, 4 * (j + 19)) << 10)) & mask;

            publicKey[i + 27] = ((load32(publicKeyInput, 4 * (j + 19)) >>> 13) |
                (load32(publicKeyInput, 4 * (j + 20)) << 19)) & mask;

            publicKey[i + 28] = (load32(publicKeyInput, 4 * (j + 20)) >>> 4) & mask;

            publicKey[i + 29] = ((load32(publicKeyInput, 4 * (j + 20)) >>> 27) |
                (load32(publicKeyInput, 4 * (j + 21)) << 5)) & mask;

            publicKey[i + 30] = ((load32(publicKeyInput, 4 * (j + 21)) >>> 18) |
                (load32(publicKeyInput, 4 * (j + 22)) << 14)) & mask;

            publicKey[i + 31] = load32(publicKeyInput, 4 * (j + 22)) >>> 9;

            j += PARAM_Q_LOG;

        }

        System.arraycopy(publicKeyInput, PARAM_N * PARAM_Q_LOG / 8, seedA, seedAOffset, CRYPTO_SEEDBYTES);

    }


    /**********************************************************************************************************
     * Description:	Checks Whether the Generated Error Polynomial or the Generated Secret Polynomial
     *				Fulfills Certain Properties Needed in Key Generation Algorithm
     *				For Heuristic qTESLA Security Category-1 and Security Category-3 (Option for Size or Speed)
     *
     * @param        polynomial        Parameter to be Checked
     * @param        bound            Threshold of Summation
     * @param        n                Polynomial Degree
     * @param        h                Number of Non-Zero Entries of Output Elements of Encryption
     *
     * @return false            Fulfillment
     * 				true			No Fulfillment
     **********************************************************************************************************/
    private static boolean checkPolynomial(int[] polynomial, int bound, int n, int h)
    {

        int summation = 0;
        int limit = n;
        int temporary;
        int mask;
        int[] list = new int[n];

        for (int i = 0; i < n; i++)
        {

            list[i] = absolute(polynomial[i]);

        }

        for (int i = 0; i < h; i++)
        {

            for (int j = 0; j < limit - 1; j++)
            {
                /* If list[j + 1] > list[j] Then Exchanges Contents */
                mask = (list[j + 1] - list[j]) >> 31;
                temporary = (list[j + 1] & mask) | (list[j] & (~mask));
                list[j + 1] = (list[j] & mask) | (list[j + 1] & (~mask));
                list[j] = temporary;

            }

            summation += list[limit - 1];
            limit--;

        }

        if (summation > bound)
        {

            return true;

        }

        return false;

    }


    /************************************************************************************************************************************************************
     * Description:	Generates A Pair of Public Key and Private Key for qTESLA Signature Scheme for Heuristic qTESLA Security Category-1 and Security Category-3
     *				(Option for Size or Speed)
     *
     * @param        publicKey                            Contains Public Key
     * @param        privateKey                            Contains Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     ************************************************************************************************************************************************************/
    static int generateKeyPair(

        byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        /* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
        int nonce = 0;

        byte[] randomness = new byte[CRYPTO_RANDOMBYTES];

        /* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
        byte[] randomnessExtended = new byte[CRYPTO_SEEDBYTES * 4];

        int[] secretPolynomial = new int[PARAM_N];
        int[] errorPolynomial = new int[PARAM_N];
        int[] A = new int[PARAM_N];
        int[] T = new int[PARAM_N];

        /* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
        // this.rng.randomByte (randomness, (short) 0, CRYPTO_RANDOMBYTES);
        secureRandom.nextBytes(randomness);


        HashUtils.secureHashAlgorithmKECCAK128(randomnessExtended, 0, CRYPTO_SEEDBYTES * 4, randomness, 0, CRYPTO_RANDOMBYTES);


        /*
         * Sample the Error Polynomial Fulfilling the Criteria
         * Choose All Error Polynomial in R with Entries from D_SIGMA
         * Repeat Step at Iteration if the h Largest Entries of Error Polynomial Summation to L_E
         */
        do
        {
            sample_gauss_poly(++nonce, randomnessExtended, 0, errorPolynomial);
        }
        while (checkPolynomial(errorPolynomial, KEY_GENERATOR_BOUND_E, PARAM_N, PARAM_H));


        /*
         * Sample the Secret Polynomial Fulfilling the Criteria
         * Choose Secret Polynomial in R with Entries from D_SIGMA
         * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
         */
        do
        {

            sample_gauss_poly(++nonce, randomnessExtended, CRYPTO_SEEDBYTES, secretPolynomial);

            //Sample.polynomialGaussSamplerI(secretPolynomial, 0, randomnessExtended, CRYPTO_SEEDBYTES, ++nonce);
        }
        while (checkPolynomial(secretPolynomial, KEY_GENERATOR_BOUND_S, PARAM_N, PARAM_H));

        /* Generate Uniform Polynomial A */
        QTesla1Polynomial.polynomialUniform(A, randomnessExtended, CRYPTO_SEEDBYTES * 2);

        /* Compute the Public Key T = A * secretPolynomial + errorPolynomial */
        QTesla1Polynomial.polynomialMultiplication(T, A, secretPolynomial);
        QTesla1Polynomial.polynomialAdditionCorrection(T, T, errorPolynomial);

        /* Pack Public and Private Keys */

        encodePublicKey(publicKey, T, randomnessExtended, CRYPTO_SEEDBYTES * 2);

        encodePrivateKey(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, CRYPTO_SEEDBYTES * 2);


        return 0;

    }

    private static void sample_gauss_poly(int nonce, byte[] randomnessExtended, int randomOffset, int[] errorPolynomial)
    {
        int dmsp = nonce << 8;

        for (int chunk = 0; chunk < PARAM_N; chunk += CHUNK_SIZE)
        {
            kmxGauss(errorPolynomial, randomnessExtended, randomOffset, dmsp++);
            //Sample.polynomialGaussSamplerI(errorPolynomial, 0, randomnessExtended, randomOffset, dmsp++);
        }

    }


    static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z)
    {


        int j = 0;

        for (int i = 0; i < (PARAM_N * PARAM_D / 32); i += PARAM_D)
        {

            store32(signature, signatureOffset + 4 * (i + 0), (int)(((Z[j + 0] & ((1 << 21) - 1))) | (Z[j + 1] << 21)));
            store32(signature, signatureOffset + 4 * (i + 1), (int)(((Z[j + 1] >>> 11) & ((1 << 10) - 1)) | ((Z[j + 2] & ((1 << 21) - 1)) << 10) | (Z[j + 3] << 31)));
            store32(signature, signatureOffset + 4 * (i + 2), (int)((((Z[j + 3] >>> 1) & ((1 << 20) - 1))) | (Z[j + 4] << 20)));
            store32(signature, signatureOffset + 4 * (i + 3), (int)(((Z[j + 4] >>> 12) & ((1 << 9) - 1)) | ((Z[j + 5] & ((1 << 21) - 1)) << 9) | (Z[j + 6] << 30)));
            store32(signature, signatureOffset + 4 * (i + 4), (int)((((Z[j + 6] >>> 2) & ((1 << 19) - 1))) | (Z[j + 7] << 19)));
            store32(signature, signatureOffset + 4 * (i + 5), (int)(((Z[j + 7] >>> 13) & ((1 << 8) - 1)) | ((Z[j + 8] & ((1 << 21) - 1)) << 8) | (Z[j + 9] << 29)));
            store32(signature, signatureOffset + 4 * (i + 6), (int)((((Z[j + 9] >>> 3) & ((1 << 18) - 1))) | (Z[j + 10] << 18)));
            store32(signature, signatureOffset + 4 * (i + 7), (int)(((Z[j + 10] >>> 14) & ((1 << 7) - 1)) | ((Z[j + 11] & ((1 << 21) - 1)) << 7) | (Z[j + 12] << 28)));
            store32(signature, signatureOffset + 4 * (i + 8), (int)((((Z[j + 12] >>> 4) & ((1 << 17) - 1))) | (Z[j + 13] << 17)));
            store32(signature, signatureOffset + 4 * (i + 9), (int)(((Z[j + 13] >>> 15) & ((1 << 6) - 1)) | ((Z[j + 14] & ((1 << 21) - 1)) << 6) | (Z[j + 15] << 27)));
            store32(signature, signatureOffset + 4 * (i + 10), (int)((((Z[j + 15] >>> 5) & ((1 << 16) - 1))) | (Z[j + 16] << 16)));
            store32(signature, signatureOffset + 4 * (i + 11), (int)(((Z[j + 16] >>> 16) & ((1 << 5) - 1)) | ((Z[j + 17] & ((1 << 21) - 1)) << 5) | (Z[j + 18] << 26)));
            store32(signature, signatureOffset + 4 * (i + 12), (int)((((Z[j + 18] >>> 6) & ((1 << 15) - 1))) | (Z[j + 19] << 15)));
            store32(signature, signatureOffset + 4 * (i + 13), (int)(((Z[j + 19] >>> 17) & ((1 << 4) - 1)) | ((Z[j + 20] & ((1 << 21) - 1)) << 4) | (Z[j + 21] << 25)));
            store32(signature, signatureOffset + 4 * (i + 14), (int)((((Z[j + 21] >>> 7) & ((1 << 14) - 1))) | (Z[j + 22] << 14)));
            store32(signature, signatureOffset + 4 * (i + 15), (int)(((Z[j + 22] >>> 18) & ((1 << 3) - 1)) | ((Z[j + 23] & ((1 << 21) - 1)) << 3) | (Z[j + 24] << 24)));
            store32(signature, signatureOffset + 4 * (i + 16), (int)((((Z[j + 24] >>> 8) & ((1 << 13) - 1))) | (Z[j + 25] << 13)));
            store32(signature, signatureOffset + 4 * (i + 17), (int)(((Z[j + 25] >>> 19) & ((1 << 2) - 1)) | ((Z[j + 26] & ((1 << 21) - 1)) << 2) | (Z[j + 27] << 23)));
            store32(signature, signatureOffset + 4 * (i + 18), (int)((((Z[j + 27] >>> 9) & ((1 << 12) - 1))) | (Z[j + 28] << 12)));
            store32(signature, signatureOffset + 4 * (i + 19), (int)(((Z[j + 28] >>> 20) & ((1 << 1) - 1)) | ((Z[j + 29] & ((1 << 21) - 1)) << 1) | (Z[j + 30] << 22)));
            store32(signature, signatureOffset + 4 * (i + 20), (int)((((Z[j + 30] >>> 10) & ((1 << 11) - 1))) | (Z[j + 31] << 11)));

            j += 32;

        }

        System.arraycopy(C, cOffset, signature, signatureOffset + PARAM_N * PARAM_D / 8, CRYPTO_C_BYTES);

    }


    /*********************************************************************************************************************************
     * Description:	Extracts the Original Message and Checks Whether the Generated Signature is Valid for A Given Signature Package
     * 				for Heuristic qTESLA Security Category-1 and Security Category-3 (Option for Size of Speed)
     *
     * @param        signature                            Given Signature Package
     * @param        signatureOffset                        Starting Point of the Given Signature Package
     * @param        signatureLength                        Length of the Given Signature Package
     * @param        message                                Original (Signed) Message
     * @param        publicKey                            Public Key

     *
     * @return 0                                    Valid Signature
     * 				< 0									Invalid Signature
     *********************************************************************************************************************************/
    static int verifying(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey
    )
    {

        byte[] C = new byte[CRYPTO_C_BYTES];
        byte[] cSignature = new byte[CRYPTO_C_BYTES];
        byte[] seed = new byte[CRYPTO_SEEDBYTES];
        byte[] hashMessage = new byte[HM_BYTES];
        int[] newPublicKey = new int[PARAM_N];

        int[] positionList = new int[PARAM_H];
        short[] signList = new short[PARAM_H];

        int[] W = new int[PARAM_N];
        int[] Z = new int[PARAM_N];
        int[] TC = new int[PARAM_N];
        int[] A = new int[PARAM_N];

        if (signatureLength < SIGNATURE_SIZE)
        {

            return -1;

        }


        decodeSignature(C, Z, signature, signatureOffset);

        /* Check Norm of Z */
        if (testZ(Z))
        {

            return -2;

        }


        decodePublicKey(newPublicKey, seed, 0, publicKey);
        QTesla1Polynomial.polynomialUniform(A, seed, 0);

        encodeC(positionList, signList, C, 0, PARAM_N, PARAM_H);

        /* W = A * Z - TC */
        QTesla1Polynomial.sparsePolynomialMultiplication32(TC, newPublicKey, positionList, signList);

        QTesla1Polynomial.polynomialMultiplication(W, A, Z);

        QTesla1Polynomial.polynomialSubtractionMontgomery(W, W, TC);


        HashUtils.secureHashAlgorithmKECCAK128(
            hashMessage, 0, HM_BYTES, message, 0, message.length
        );

        /* Obtain the Hash Symbol */
        hashFunction(cSignature, 0, W, hashMessage, 0);

        /* Check if Same With One from Signature */
        if (!memoryEqual(C, 0, cSignature, 0, CRYPTO_C_BYTES))
        {
            return -3;
        }

        return 0;

    }

    /**********************************************************************************
     * Description:	Checks Bounds for Signature Vector Z During Signature Verification
     * 				for Heuristic qTESLA Security Category-1 and Security Category-3
     * 				(Option of Size of Speed)
     *
     * @param        Z        Signature Vector
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     *********************************************************************************/
    private static boolean testZ(int[] Z)
    {

        for (int i = 0; i < PARAM_N; i++)
        {

            if ((Z[i] < -(PARAM_B - U)) || (Z[i] > PARAM_B - U))
            {
                return true;
            }
        }

        return false;

    }

    /*************************************************************************************
     * Description:	Checks Bounds for Signature Vector Z During Signature Verification
     * 				for Provably-Secure qTESLA Security Category-1 and Security Category-3
     *
     * @param        Z        Signature Vector
     *
     * @return false    Valid / Accepted
     * 				true	Invalid / Rejected
     *************************************************************************************/
    private static boolean testZ(long[] Z)
    {

        for (int i = 0; i < PARAM_N; i++)
        {
            if ((Z[i] < -(PARAM_B - U)) || (Z[i] > PARAM_B - U))
            {
                return true;
            }
        }

        return false;

    }

    /******************************************************************************************************************************
     * Description:	Decode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
     *
     * @param    C
     * @param    Z
     * @param    signature            Output Package Containing Signature
     * @param    signatureOffset        Starting Point of the Output Package Containing Signature
     *
     * @return none
     ******************************************************************************************************************************/
    static void decodeSignature(byte[] C, int[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;

        for (int i = 0; i < PARAM_N; i += 32)
        {

            Z[i + 0] = (load32(signature, signatureOffset + 4 * (j + 0)) << 11) >> 11;

            Z[i + 1] = ((load32(signature, signatureOffset + 4 * (j + 0)) >>> 21) |
                (load32(signature, signatureOffset + 4 * (j + 1)) << 22) >> 11);

            Z[i + 2] = (load32(signature, signatureOffset + 4 * (j + 1)) << 1) >> 11;

            Z[i + 3] = (load32(signature, signatureOffset + 4 * (j + 1)) >>> 31) |
                ((load32(signature, signatureOffset + 4 * (j + 2)) << 12) >> 11);

            Z[i + 4] = (load32(signature, signatureOffset + 4 * (j + 2)) >>> 20) |
                ((load32(signature, signatureOffset + 4 * (j + 3)) << 23) >> 11);

            Z[i + 5] = (load32(signature, signatureOffset + 4 * (j + 3)) << 2) >> 11;

            Z[i + 6] = (load32(signature, signatureOffset + 4 * (j + 3)) >>> 30) |
                ((load32(signature, signatureOffset + 4 * (j + 4)) << 13) >> 11);

            Z[i + 7] = (load32(signature, signatureOffset + 4 * (j + 4)) >>> 19) |
                ((load32(signature, signatureOffset + 4 * (j + 5)) << 24) >> 11);

            Z[i + 8] = (load32(signature, signatureOffset + 4 * (j + 5)) << 3) >> 11;

            Z[i + 9] = (load32(signature, signatureOffset + 4 * (j + 5)) >>> 29) |
                ((load32(signature, signatureOffset + 4 * (j + 6)) << 14) >> 11);

            Z[i + 10] = (load32(signature, signatureOffset + 4 * (j + 6)) >>> 18) |
                ((load32(signature, signatureOffset + 4 * (j + 7)) << 25) >> 11);

            Z[i + 11] = (load32(signature, signatureOffset + 4 * (j + 7)) << 4) >> 11;

            Z[i + 12] = (load32(signature, signatureOffset + 4 * (j + 7)) >>> 28) |
                ((load32(signature, signatureOffset + 4 * (j + 8)) << 15) >> 11);

            Z[i + 13] = (load32(signature, signatureOffset + 4 * (j + 8)) >>> 17) |
                ((load32(signature, signatureOffset + 4 * (j + 9)) << 26) >> 11);

            Z[i + 14] = (load32(signature, signatureOffset + 4 * (j + 9)) << 5) >> 11;

            Z[i + 15] = (load32(signature, signatureOffset + 4 * (j + 9)) >>> 27) |
                ((load32(signature, signatureOffset + 4 * (j + 10)) << 16) >> 11);

            Z[i + 16] = (load32(signature, signatureOffset + 4 * (j + 10)) >>> 16) |
                ((load32(signature, signatureOffset + 4 * (j + 11)) << 27) >> 11);

            Z[i + 17] = (load32(signature, signatureOffset + 4 * (j + 11)) << 6) >> 11;

            Z[i + 18] = (load32(signature, signatureOffset + 4 * (j + 11)) >>> 26) |
                ((load32(signature, signatureOffset + 4 * (j + 12)) << 17) >> 11);

            Z[i + 19] = (load32(signature, signatureOffset + 4 * (j + 12)) >>> 15) |
                ((load32(signature, signatureOffset + 4 * (j + 13)) << 28) >> 11);

            Z[i + 20] = (load32(signature, signatureOffset + 4 * (j + 13)) << 7) >> 11;

            Z[i + 21] = (load32(signature, signatureOffset + 4 * (j + 13)) >>> 25) |
                ((load32(signature, signatureOffset + 4 * (j + 14)) << 18) >> 11);

            Z[i + 22] = (load32(signature, signatureOffset + 4 * (j + 14)) >>> 14) |
                ((load32(signature, signatureOffset + 4 * (j + 15)) << 29) >> 11);

            Z[i + 23] = (load32(signature, signatureOffset + 4 * (j + 15)) << 8) >> 11;

            Z[i + 24] = (load32(signature, signatureOffset + 4 * (j + 15)) >>> 24) |
                ((load32(signature, signatureOffset + 4 * (j + 16)) << 19) >> 11);

            Z[i + 25] = (load32(signature, signatureOffset + 4 * (j + 16)) >>> 13) |
                ((load32(signature, signatureOffset + 4 * (j + 17)) << 30) >> 11);

            Z[i + 26] = (load32(signature, signatureOffset + 4 * (j + 17)) << 9) >> 11;

            Z[i + 27] = (load32(signature, signatureOffset + 4 * (j + 17)) >>> 23) |
                ((load32(signature, signatureOffset + 4 * (j + 18)) << 20) >> 11);

            Z[i + 28] = (load32(signature, signatureOffset + 4 * (j + 18)) >>> 12) |
                ((load32(signature, signatureOffset + 4 * (j + 19)) << 31) >> 11);

            Z[i + 29] = (load32(signature, signatureOffset + 4 * (j + 19)) << 10) >> 11;

            Z[i + 30] = (load32(signature, signatureOffset + 4 * (j + 19)) >>> 22) |
                ((load32(signature, signatureOffset + 4 * (j + 20)) << 21) >> 11);

            Z[i + 31] = load32(signature, signatureOffset + 4 * (j + 20)) >> 11;

            j += PARAM_D;

        }

        System.arraycopy(signature, signatureOffset + PARAM_N * PARAM_D / 8, C, 0, CRYPTO_C_BYTES);


    }


    static final int CHUNK_SIZE = 512;
    static final int CDT_ROWS = 207;
    static final int CDT_COLS = 2;

    private static final int RADIX = 32;
    private static final int RADIX32 = 32;


    static long[] cdt_v = new long[]{
        0x00000000L, 0x00000000L, // 0
        0x023A1B3FL, 0x4A499901L, // 1
        0x06AD3C4CL, 0x0CA08592L, // 2
        0x0B1D1E95L, 0x401E5DB9L, // 3
        0x0F879D85L, 0x73D5BFB7L, // 4
        0x13EA9C5CL, 0x2939948AL, // 5
        0x18440933L, 0x7FE9008DL, // 6
        0x1C91DFF1L, 0x48F0AE83L, // 7
        0x20D22D0FL, 0x100BC806L, // 8
        0x25031040L, 0x60F31377L, // 9
        0x2922BEEBL, 0x50B180CFL, // 10
        0x2D2F866AL, 0x1E289169L, // 11
        0x3127CE19L, 0x102CF7B2L, // 12
        0x350A1928L, 0x118E580DL, // 13
        0x38D5082CL, 0x6A7E620AL, // 14
        0x3C875A73L, 0x599D6D36L, // 15
        0x401FEF0EL, 0x33E6A3E9L, // 16
        0x439DC59EL, 0x183BDACEL, // 17
        0x46FFFEDAL, 0x27E0518BL, // 18
        0x4A45DCD3L, 0x174E5549L, // 19
        0x4D6EC2F3L, 0x49172E12L, // 20
        0x507A35C1L, 0x7D9AA338L, // 21
        0x5367DA64L, 0x752F8E31L, // 22
        0x563775EDL, 0x2DC9F137L, // 23
        0x58E8EC6BL, 0x2865CAFCL, // 24
        0x5B7C3FD0L, 0x5CCC8CBEL, // 25
        0x5DF18EA7L, 0x3326C087L, // 26
        0x6049129FL, 0x01DAE6B6L, // 27
        0x62831EF8L, 0x2B524213L, // 28
        0x64A01ED3L, 0x0A5D1038L, // 29
        0x66A09363L, 0x6544ED52L, // 30
        0x68851217L, 0x1F7909FBL, // 31
        0x6A4E42A8L, 0x589BF09CL, // 32
        0x6BFCDD30L, 0x162DC445L, // 33
        0x6D91A82DL, 0x7BCBF55CL, // 34
        0x6F0D7697L, 0x75D3528FL, // 35
        0x707125EDL, 0x13F82E79L, // 36
        0x71BD9C54L, 0x260C26C7L, // 37
        0x72F3C6C7L, 0x7D9C0191L, // 38
        0x74149755L, 0x04472E63L, // 39
        0x7521036DL, 0x21A138EAL, // 40
        0x761A0251L, 0x35015867L, // 41
        0x77008B94L, 0x30C0BD22L, // 42
        0x77D595B9L, 0x2DE3507FL, // 43
        0x789A14EEL, 0x19C5DB94L, // 44
        0x794EF9E2L, 0x6BE2990AL, // 45
        0x79F530BEL, 0x20A7F127L, // 46
        0x7A8DA031L, 0x08443399L, // 47
        0x7B1928A5L, 0x4D9D53CFL, // 48
        0x7B98A38CL, 0x72C68357L, // 49
        0x7C0CE2C7L, 0x5D698B25L, // 50
        0x7C76B02AL, 0x6EF32779L, // 51
        0x7CD6CD1DL, 0x09F74C79L, // 52
        0x7D2DF24DL, 0x5037123AL, // 53
        0x7D7CCF81L, 0x52E6CC5DL, // 54
        0x7DC40B76L, 0x6127DAEAL, // 55
        0x7E0443D9L, 0x16F11331L, // 56
        0x7E3E0D4BL, 0x48A00B90L, // 57
        0x7E71F37EL, 0x64E0EF47L, // 58
        0x7EA07957L, 0x6735C829L, // 59
        0x7ECA1921L, 0x78D7B202L, // 60
        0x7EEF44CBL, 0x639ED1AEL, // 61
        0x7F10662DL, 0x02BA119FL, // 62
        0x7F2DDF53L, 0x66EE6A14L, // 63
        0x7F480AD7L, 0x6F81453BL, // 64
        0x7F5F3C32L, 0x2587B359L, // 65
        0x7F73C018L, 0x34C60C54L, // 66
        0x7F85DCD8L, 0x6B4FC49DL, // 67
        0x7F95D2B9L, 0x3769ED08L, // 68
        0x7FA3DC55L, 0x2996B8DEL, // 69
        0x7FB02EFAL, 0x0EEEE30FL, // 70
        0x7FBAFB03L, 0x45D73B72L, // 71
        0x7FC46C34L, 0x7C8C59F2L, // 72
        0x7FCCAA10L, 0x15CAA326L, // 73
        0x7FD3D828L, 0x7BEA4849L, // 74
        0x7FDA1675L, 0x3608E7C2L, // 75
        0x7FDF819AL, 0x1D3DFF35L, // 76
        0x7FE43333L, 0x1952FF5FL, // 77
        0x7FE84217L, 0x5506F15AL, // 78
        0x7FEBC29AL, 0x61880546L, // 79
        0x7FEEC6C7L, 0x4786A8A8L, // 80
        0x7FF15E99L, 0x0A1CB795L, // 81
        0x7FF3982EL, 0x24C17DCCL, // 82
        0x7FF57FFAL, 0x11B43169L, // 83
        0x7FF720EFL, 0x69B7A428L, // 84
        0x7FF884ABL, 0x30B995E4L, // 85
        0x7FF9B396L, 0x651D9C1EL, // 86
        0x7FFAB50BL, 0x68EE9B1AL, // 87
        0x7FFB8F72L, 0x5D4208A6L, // 88
        0x7FFC485EL, 0x08AD19C4L, // 89
        0x7FFCE4A3L, 0x61DC95CCL, // 90
        0x7FFD6873L, 0x573AAF25L, // 91
        0x7FFDD76BL, 0x6C207ED1L, // 92
        0x7FFE34AAL, 0x43673438L, // 93
        0x7FFE82DEL, 0x2E535443L, // 94
        0x7FFEC454L, 0x55D51370L, // 95
        0x7FFEFB06L, 0x12FD6DC5L, // 96
        0x7FFF28A2L, 0x0A588B08L, // 97
        0x7FFF4E98L, 0x1CA2A14FL, // 98
        0x7FFF6E21L, 0x3E0B4535L, // 99
        0x7FFF8847L, 0x43F95CC4L, // 100
        0x7FFF9DEBL, 0x38044301L, // 101
        0x7FFFAFCBL, 0x3DA0CF24L, // 102
        0x7FFFBE88L, 0x16D5DC7CL, // 103
        0x7FFFCAA8L, 0x532DED04L, // 104
        0x7FFFD49EL, 0x330C43AAL, // 105
        0x7FFFDCC8L, 0x488C8B03L, // 106
        0x7FFFE376L, 0x5E2582C2L, // 107
        0x7FFFE8EBL, 0x2A699905L, // 108
        0x7FFFED5DL, 0x5773C7A7L, // 109
        0x7FFFF0FBL, 0x63D3499FL, // 110
        0x7FFFF3EBL, 0x621D490AL, // 111
        0x7FFFF64DL, 0x1BAFE266L, // 112
        0x7FFFF83AL, 0x1AA50219L, // 113
        0x7FFFF9C8L, 0x1E74DD87L, // 114
        0x7FFFFB08L, 0x7E5630D3L, // 115
        0x7FFFFC0AL, 0x7C050D38L, // 116
        0x7FFFFCDAL, 0x093EEF3BL, // 117
        0x7FFFFD80L, 0x01F3172BL, // 118
        0x7FFFFE04L, 0x5CDFCE2EL, // 119
        0x7FFFFE6EL, 0x54177CDFL, // 120
        0x7FFFFEC3L, 0x06B266A3L, // 121
        0x7FFFFF06L, 0x14C2B342L, // 122
        0x7FFFFF3BL, 0x367771F9L, // 123
        0x7FFFFF65L, 0x4F37BDD3L, // 124
        0x7FFFFF86L, 0x7D6081B5L, // 125
        0x7FFFFFA1L, 0x2734F6F5L, // 126
        0x7FFFFFB6L, 0x057B565CL, // 127
        0x7FFFFFC6L, 0x2C2BD768L, // 128
        0x7FFFFFD3L, 0x118798A8L, // 129
        0x7FFFFFDDL, 0x13DF050CL, // 130
        0x7FFFFFE4L, 0x7E436700L, // 131
        0x7FFFFFEBL, 0x0C554F26L, // 132
        0x7FFFFFEFL, 0x6D58FEBAL, // 133
        0x7FFFFFF3L, 0x46B2EA4DL, // 134
        0x7FFFFFF6L, 0x35E875C6L, // 135
        0x7FFFFFF8L, 0x523C11B9L, // 136
        0x7FFFFFFAL, 0x2DF7BE14L, // 137
        0x7FFFFFFBL, 0x577585A6L, // 138
        0x7FFFFFFCL, 0x59F2AC82L, // 139
        0x7FFFFFFDL, 0x3E37F0C9L, // 140
        0x7FFFFFFEL, 0x0B1F4CF2L, // 141
        0x7FFFFFFEL, 0x45FE12ACL, // 142
        0x7FFFFFFEL, 0x72F8E740L, // 143
        0x7FFFFFFFL, 0x154618FFL, // 144
        0x7FFFFFFFL, 0x2F61E68CL, // 145
        0x7FFFFFFFL, 0x43379BB6L, // 146
        0x7FFFFFFFL, 0x5241D483L, // 147
        0x7FFFFFFFL, 0x5DA3C063L, // 148
        0x7FFFFFFFL, 0x663CDF59L, // 149
        0x7FFFFFFFL, 0x6CB865F1L, // 150
        0x7FFFFFFFL, 0x71993691L, // 151
        0x7FFFFFFFL, 0x75432D5CL, // 152
        0x7FFFFFFFL, 0x780253E4L, // 153
        0x7FFFFFFFL, 0x7A10727DL, // 154
        0x7FFFFFFFL, 0x7B995BC9L, // 155
        0x7FFFFFFFL, 0x7CBE3B28L, // 156
        0x7FFFFFFFL, 0x7D981EEFL, // 157
        0x7FFFFFFFL, 0x7E39EAD2L, // 158
        0x7FFFFFFFL, 0x7EB1D52CL, // 159
        0x7FFFFFFFL, 0x7F0A8A07L, // 160
        0x7FFFFFFFL, 0x7F4C08CCL, // 161
        0x7FFFFFFFL, 0x7F7C4CC9L, // 162
        0x7FFFFFFFL, 0x7F9FCD06L, // 163
        0x7FFFFFFFL, 0x7FB9DD06L, // 164
        0x7FFFFFFFL, 0x7FCCF5DEL, // 165
        0x7FFFFFFFL, 0x7FDAED50L, // 166
        0x7FFFFFFFL, 0x7FE51F3EL, // 167
        0x7FFFFFFFL, 0x7FEC8CC3L, // 168
        0x7FFFFFFFL, 0x7FF1F385L, // 169
        0x7FFFFFFFL, 0x7FF5DF23L, // 170
        0x7FFFFFFFL, 0x7FF8B62FL, // 171
        0x7FFFFFFFL, 0x7FFAC3DFL, // 172
        0x7FFFFFFFL, 0x7FFC3F40L, // 173
        0x7FFFFFFFL, 0x7FFD5084L, // 174
        0x7FFFFFFFL, 0x7FFE14FBL, // 175
        0x7FFFFFFFL, 0x7FFEA1F4L, // 176
        0x7FFFFFFFL, 0x7FFF06ECL, // 177
        0x7FFFFFFFL, 0x7FFF4F19L, // 178
        0x7FFFFFFFL, 0x7FFF8298L, // 179
        0x7FFFFFFFL, 0x7FFFA744L, // 180
        0x7FFFFFFFL, 0x7FFFC155L, // 181
        0x7FFFFFFFL, 0x7FFFD3D3L, // 182
        0x7FFFFFFFL, 0x7FFFE0EBL, // 183
        0x7FFFFFFFL, 0x7FFFEA2CL, // 184
        0x7FFFFFFFL, 0x7FFFF0B3L, // 185
        0x7FFFFFFFL, 0x7FFFF54CL, // 186
        0x7FFFFFFFL, 0x7FFFF886L, // 187
        0x7FFFFFFFL, 0x7FFFFACAL, // 188
        0x7FFFFFFFL, 0x7FFFFC60L, // 189
        0x7FFFFFFFL, 0x7FFFFD7CL, // 190
        0x7FFFFFFFL, 0x7FFFFE42L, // 191
        0x7FFFFFFFL, 0x7FFFFECBL, // 192
        0x7FFFFFFFL, 0x7FFFFF2BL, // 193
        0x7FFFFFFFL, 0x7FFFFF6DL, // 194
        0x7FFFFFFFL, 0x7FFFFF9BL, // 195
        0x7FFFFFFFL, 0x7FFFFFBBL, // 196
        0x7FFFFFFFL, 0x7FFFFFD1L, // 197
        0x7FFFFFFFL, 0x7FFFFFE0L, // 198
        0x7FFFFFFFL, 0x7FFFFFEAL, // 199
        0x7FFFFFFFL, 0x7FFFFFF1L, // 200
        0x7FFFFFFFL, 0x7FFFFFF6L, // 201
        0x7FFFFFFFL, 0x7FFFFFF9L, // 202
        0x7FFFFFFFL, 0x7FFFFFFCL, // 203
        0x7FFFFFFFL, 0x7FFFFFFDL, // 204
        0x7FFFFFFFL, 0x7FFFFFFEL, // 205
        0x7FFFFFFFL, 0x7FFFFFFFL, // 206
    }; // cdt_v


    private static void kmxGauss(int[] z, byte[] seed, int seedOffset, int nonce)
    {
        int[] sampk = new int[(CHUNK_SIZE + CDT_ROWS) * CDT_COLS];
        int[] sampg = new int[CHUNK_SIZE + CDT_ROWS];

        {
            // In the C Implementation they cast between uint_8 and int32 a lot, this is one of those situations.
            byte[] sampkBytes = new byte[sampk.length * 4];
            HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                sampkBytes, 0, CHUNK_SIZE * CDT_COLS * 4, (short)nonce, seed, seedOffset, CRYPTO_SEEDBYTES);
            int i, t;

            int offset = CHUNK_SIZE * CDT_COLS * 4;

            for (i = 0; i < cdt_v.length; i++)
            {
                sampkBytes[offset++] = (byte)(cdt_v[i]);
                sampkBytes[offset++] = (byte)(cdt_v[i] >>> 8);
                sampkBytes[offset++] = (byte)(cdt_v[i] >>> 16);
                sampkBytes[offset++] = (byte)(cdt_v[i] >>> 24);
            }

            for (i = 0, t = 0; t < sampkBytes.length; t += 4, i++)
            {
                sampk[i] = org.bouncycastle.util.Pack.littleEndianToInt(sampkBytes, t);
            }

        }

        for (int i = 0; i < CHUNK_SIZE; i++)
        {
            sampg[i] = i << 16;
        }

        for (int i = 0; i < CDT_ROWS; i++)
        {
            sampg[CHUNK_SIZE + i] = (int)(0xFFFF0000L ^ i);
        }

        knuthMergeExchangeKG(sampk, sampg, CHUNK_SIZE + CDT_ROWS);


        int prev_inx = 0;
        for (int i = 0; i < CHUNK_SIZE + CDT_ROWS; i++)
        {
            int curr_inx = sampg[i] & 0xFFFF;
            // prev_inx < curr_inx => prev_inx - curr_inx < 0 => (prev_inx - curr_inx) >> 31 = 0xF...F else 0x0...0
            prev_inx ^= (curr_inx ^ prev_inx) & ((prev_inx - curr_inx) >> (RADIX32 - 1));
            int neg = (sampk[i * CDT_COLS] >> (RADIX - 1));  // Only the (so far unused) msb of the leading word
            sampg[i] |= ((neg & -prev_inx) ^ (~neg & prev_inx)) & 0xFFFFL;
        }


        knuthMergeExchangeG(sampg, CHUNK_SIZE + CDT_ROWS);


        for (int i = 0; i < CHUNK_SIZE; i++)
        {
            z[i] = (sampg[i] << (RADIX32 - 16)) >> (RADIX32 - 16);
        }


    }


    static void knuthMergeExchangeKG(int[] a, int g[], int n)
    {


        int t = 1;
        while (t < n - t)
        {
            t += t;
        }
        for (int p = t; p > 0; p >>= 1)
        {
            int apPtr = p * 2;
            int a_iPtr = 0;
            int ap_iPtr = apPtr;
            int gpPtr = p;

            int neg = ~0;

            for (int i = 0; i < n - p; i++, a_iPtr += 2, ap_iPtr += 2)
            {
                if (!((i & p) != 0))
                {
                    {
                        int diff = 0, swapa;
                        int swapg;
                        {

                            {
                                diff = (diff + (a[ap_iPtr + 1] & ((neg >>> 1))) -
                                    (a[a_iPtr + 1] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;

                            {
                                {
                                    diff = (diff + (a[ap_iPtr] & ((neg >>> 1))) -
                                        (a[a_iPtr] & (neg >>> 1))) >> (32 - 1);
                                }
                                ;
                                {

                                    swapa = (a[a_iPtr] ^ a[ap_iPtr]) & diff;
                                    a[a_iPtr] ^= swapa;
                                    a[ap_iPtr] ^= swapa;
                                }
                                ;
                            }
                            ;
                            {
                                swapa = (a[a_iPtr + 1] ^ a[ap_iPtr + 1]) & diff;
                                a[a_iPtr + 1] ^= swapa;
                                a[ap_iPtr + 1] ^= swapa;
                            }
                            ;
                        }
                        ;
                        {
                            swapg = (g[i] ^ g[gpPtr + i]) & diff;
                            g[i] ^= swapg;
                            g[gpPtr + i] ^= swapg;
                        }
                        ;
                    }
                    ;
                }
            }


            for (int q = t; q > p; q >>= 1)
            {
                int ap_iPtr_ = apPtr;
                int aq_iPtr = q * 2;
                int gqPtr = q;
                for (int i = 0; i < n - q; i++, ap_iPtr_ += 2, aq_iPtr += 2)
                {
                    if ((i & p) == 0)
                    {
                        {
                            int diff = 0, swapa;
                            int swapg;
                            {
                                {
                                    diff = (diff + (a[aq_iPtr + 1] & ((neg >>> 1))) -
                                        (a[ap_iPtr_ + 1] & ((neg >>> 1)))) >> (32 - 1);
                                }

                                {
                                    {
                                        diff = (diff + (a[aq_iPtr] & ((neg >>> 1))) -
                                            (a[ap_iPtr_] & ((neg >>> 1)))) >> (32 - 1);
                                    }

                                    {
                                        swapa = (a[ap_iPtr_] ^ a[aq_iPtr]) & diff;
                                        a[ap_iPtr_] ^= swapa;
                                        a[aq_iPtr] ^= swapa;
                                    }

                                }

                                {
                                    swapa = (a[ap_iPtr_ + 1] ^ a[aq_iPtr + 1]) & diff;
                                    a[ap_iPtr_ + 1] ^= swapa;
                                    a[aq_iPtr + 1] ^= swapa;
                                }

                            }

                            {
                                swapg = (g[gpPtr + i] ^ g[gqPtr + i]) & diff;
                                g[gpPtr + i] ^= swapg;
                                g[gqPtr + i] ^= swapg;
                            }

                        }

                    }
                }
            }

        }
    }


    static void knuthMergeExchangeG(int a[], int n)
    {
        int t = 1;
        while (t < n - t)
        {
            t += t;
        }
        for (int p = t; p > 0; p >>= 1)
        {

            int apPtr = p;
            for (int i = 0; i < n - p; i++)
            {
                if (!((i & p) != 0))
                {
                    int diff = ((a[apPtr + i] & 0x7FFFFFFF) - (a[i] & 0x7FFFFFFF)) >> (32 - 1);
                    int swap = (a[i] ^ a[apPtr + i]) & diff;
                    a[i] ^= swap;
                    a[apPtr + i] ^= swap;
                }
            }

            for (int q = t; q > p; q >>= 1)
            {
                int aqPtr = q;
                for (int i = 0; i < n - q; i++)
                {
                    if (!((i & p) != 0))
                    {

                        int diff = ((a[aqPtr + i] & 0x7FFFFFFF) - (a[apPtr + i] & 0x7FFFFFFF)) >> (32 - 1);
                        int swap = (a[apPtr + i] ^ a[aqPtr + i]) & diff;
                        a[apPtr + i] ^= swap;
                        a[aqPtr + i] ^= swap;

                    }
                }
            }
        }
    }

    /******************************************************************************************************************
     * Description:	Samples Polynomial Y, Such That Each Coefficient is in the Range [-B, B], for Heuristic qTESLA
     * 				Security Category-1 and Security Category-3 (Option for Size or Speed)
     *
     * @param        Y                Polynomial Y
     * @param        seed            Kappa-Bit Seed
     * @param        seedOffset        Starting Point of the Kappa-Bit Seed
     * @param        nonce            Domain Separator for Error Polynomial and Secret Polynomial

     * @return none
     ******************************************************************************************************************/
    private static void sampleY(int[] Y, final byte[] seed, int seedOffset, int nonce)
    {


        int i = 0;
        int position = 0;
        int numberOfByte = (PARAM_B_BITS + 1 + 7) / 8;
        int numberOfBlock = PARAM_N;
        byte[] buffer = new byte[PARAM_N * numberOfByte];
        int[] y = new int[4];

        short dualModeSampler = (short)(nonce << 8);


        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
            buffer, 0, PARAM_N * numberOfByte, dualModeSampler++, seed, seedOffset, CRYPTO_RANDOMBYTES
        );


        while (i < PARAM_N)
        {

            if (position > numberOfBlock * numberOfByte * 4)
            {


                numberOfBlock =
                    HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE /
                        ((PARAM_B_BITS + 1 + 7) / 8);

                HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                    buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE,
                    dualModeSampler++,
                    seed, seedOffset, CRYPTO_RANDOMBYTES
                );


                position = 0;

            }

            y[0] = (load32(buffer, position) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;
            y[1] = (load32(buffer, position + numberOfByte) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;
            y[2] = (load32(buffer, position + numberOfByte * 2) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;
            y[3] = (load32(buffer, position + numberOfByte * 3) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;

            if (i < PARAM_N && y[0] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[0];

            }

            if (i < PARAM_N && y[1] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[1];

            }

            if (i < PARAM_N && y[2] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[2];

            }

            if (i < PARAM_N && y[3] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[3];

            }

            position += numberOfByte * 4;

        }

    }

    private static void encodeC(int[] positionList, short[] signList, byte[] output, int outputOffset, int n, int h)
    {

        int count = 0;
        int position;
        short domainSeparator = 0;
        short[] C = new short[n];
        byte[] randomness = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE];

        /* Use the Hash Value as Key to Generate Some Randomness */
        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
            randomness, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE,
            domainSeparator++,
            output, outputOffset, CRYPTO_RANDOMBYTES
        );

        /* Use Rejection Sampling to Determine Positions to be Set in the New Vector */
        Arrays.fill(C, (short)0);

        /* Sample A Unique Position k times.
         * Use Two Bytes
         */
        for (int i = 0; i < h; )
        {

            if (count > HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE - 3)
            {

                HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                    randomness, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE,
                    domainSeparator++,
                    output, outputOffset, CRYPTO_RANDOMBYTES
                );

                count = 0;

            }

            position = (randomness[count] << 8) | (randomness[count + 1] & 0xFF);
            position &= (n - 1);

            /* Position is between [0, n - 1] and Has not Been Set Yet
             * Determine Signature
             */
            if (C[position] == 0)
            {

                if ((randomness[count + 2] & 1) == 1)
                {

                    C[position] = -1;

                }
                else
                {

                    C[position] = 1;

                }

                positionList[i] = position;
                signList[i] = C[position];
                i++;

            }

            count += 3;

        }


    }

    // TODO migrate to same logic as other versions.


    static int load32(final byte[] load, int loadOffset)
    {

        int number = 0;

        if (load.length - loadOffset >= 4)
        {

            for (int i = 0; i < 4; i++)
            {

                number ^= (int)(load[loadOffset + i] & 0xFF) << (8 * i);

            }

        }
        else
        {


            for (int i = 0; i < load.length - loadOffset; i++)
            {

                number ^= (int)(load[loadOffset + i] & 0xFF) << (8 * i);

            }

        }

        return number;

    }

    static void store32(byte[] store, int storeOffset, int number)
    {

        if (store.length - storeOffset >= 4)
        {

            for (int i = 0; i < 4; i++)
            {

                store[storeOffset + i] = (byte)((number >> (8 * i)) & 0xFF);

            }

        }
        else
        {

            for (int i = 0; i < store.length - storeOffset; i++)
            {

                store[storeOffset + i] = (byte)((number >> (8 * i)) & 0xFF);

            }

        }

    }

    //TODO use Arrays lib.
    static boolean memoryEqual(byte[] left, int leftOffset, byte[] right, int rightOffset, int length)
    {

        if ((leftOffset + length <= left.length) && (rightOffset + length <= right.length))
        {

            for (int i = 0; i < length; i++)
            {

                if (left[leftOffset + i] != right[rightOffset + i])
                {

                    return false;

                }

            }

            return true;

        }
        else
        {

            return false;

        }

    }


    static class QTesla1Polynomial
    {

        static final int RANDOM = 32;

        static void polynomialUniform(int[] A, byte[] seed, int seedOffset)
        {


            long qInverse = PARAM_QINV;


            int position = 0;
            int i = 0;
            int numberOfByte = (PARAM_Q_LOG + 7) / 8;
            int numberOfBlock = GENERATOR_A;
            short dualModeSampler = 0;
            int value1;
            int value2;
            int value3;
            int value4;
            int mask = (1 << PARAM_Q_LOG) - 1;

            byte[] buffer = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * GENERATOR_A];

            HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * GENERATOR_A,
                dualModeSampler++,
                seed, seedOffset, CRYPTO_RANDOMBYTES
            );


            while (i < PARAM_N)
            {

                if (position > (HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock - 4 * numberOfByte))
                {

                    numberOfBlock = 1;

                    HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                        buffer, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * numberOfBlock,
                        dualModeSampler++,
                        seed, seedOffset, CRYPTO_RANDOMBYTES
                    );

                    position = 0;

                }

                value1 = load32(buffer, position) & mask;
                position += numberOfByte;

                value2 = load32(buffer, position) & mask;
                position += numberOfByte;

                value3 = load32(buffer, position) & mask;
                position += numberOfByte;

                value4 = load32(buffer, position) & mask;
                position += numberOfByte;

                if (value1 < PARAM_Q && i < PARAM_N)
                {
                    A[i++] = montgomery((long)value1 * INVERSE_NUMBER_THEORETIC_TRANSFORM);
                }

                if (value2 < PARAM_Q && i < PARAM_N)
                {
                    A[i++] = montgomery((long)value2 * INVERSE_NUMBER_THEORETIC_TRANSFORM);
                }

                if (value3 < PARAM_Q && i < PARAM_N)
                {
                    A[i++] = montgomery((long)value3 * INVERSE_NUMBER_THEORETIC_TRANSFORM);
                }

                if (value4 < PARAM_Q && i < PARAM_N)
                {
                    A[i++] = montgomery((long)value4 * INVERSE_NUMBER_THEORETIC_TRANSFORM);
                }

            }

        }

        static void polynomialMultiplication(int[] product, int[] multiplicand, int[] multiplier)
        {
            int[] multiplierNumberTheoreticTransform = new int[PARAM_N];
            for (int i = 0; i < PARAM_N; i++)
            {
                multiplierNumberTheoreticTransform[i] = multiplier[i];
            }
            numberTheoreticTransform(multiplierNumberTheoreticTransform, ZETA_I);
            componentWisePolynomialMultiplication(product, multiplicand, multiplierNumberTheoreticTransform);
            inverseNumberTheoreticTransformI(product, ZETA_INVERSE_I);
        }

        private static void componentWisePolynomialMultiplication(int[] product, int[] multiplicand, int[] multiplier)
        {

            for (int i = 0; i < PARAM_N; i++)
            {

                product[i] = montgomery((long)multiplicand[i] * multiplier[i]);

            }

        }


        private static void inverseNumberTheoreticTransformI(int destination[], int source[])
        {

            int jTwiddle = 0;

            for (int numberOfProblem = 1; numberOfProblem < PARAM_N; numberOfProblem *= 2)
            {

                int j = 0;
                int jFirst;

                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + numberOfProblem)
                {

                    long omega = source[jTwiddle++];

                    for (j = jFirst; j < jFirst + numberOfProblem; j++)
                    {

                        int temporary = destination[j];

                        destination[j] = temporary + destination[j + numberOfProblem];

                        destination[j + numberOfProblem] = montgomery(
                            omega * (temporary - destination[j + numberOfProblem])

                        );

                    }

                }

            }

            for (int i = 0; i < PARAM_N / 2; i++)
            {

                destination[i] = montgomery((long)PARAM_R * destination[i]);

            }

        }


        private static void numberTheoreticTransform(int destination[], int source[])
        {

            int jTwiddle = 0;
            int numberOfProblem = PARAM_N >> 1;

            for (; numberOfProblem > 0; numberOfProblem >>= 1)
            {

                int j = 0;
                int jFirst;

                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + numberOfProblem)
                {

                    long omega = source[jTwiddle++];

                    for (j = jFirst; j < jFirst + numberOfProblem; j++)
                    {
                        int temporary = montgomery(omega * destination[j + numberOfProblem]);
                        destination[j + numberOfProblem] = destination[j] - temporary;
                        destination[j] = destination[j] + temporary;

                    }

                }

            }

        }

        static void sparsePolynomialMultiplication16(int[] product, final short[] privateKey, final int[] positionList, final short[] signList)
        {

            int position;

            Arrays.fill(product, 0);

            for (int i = 0; i < PARAM_H; i++)
            {

                position = positionList[i];

                for (int j = 0; j < position; j++)
                {

                    product[j] -= signList[i] * privateKey[PARAM_N + j - position];

                }

                for (int j = position; j < PARAM_N; j++)
                {

                    product[j] += signList[i] * privateKey[j - position];

                }

            }

        }

        static void polynomialAddition(int[] summation, int[] augend, int[] addend)
        {

            for (int i = 0; i < PARAM_N; i++)
            {

                summation[i] = augend[i] + addend[i];

            }

        }

        static void polynomialAdditionCorrection(int[] summation, int[] augend, int[] addend)
        {

            for (int i = 0; i < PARAM_N; i++)
            {

                summation[i] = augend[i] + addend[i];
                /* If summation[i] < 0 Then Add Q */
                summation[i] += (summation[i] >> 31) & PARAM_Q;
                summation[i] -= PARAM_Q;
                /* If summation[i] >= Q Then Subtract Q */
                summation[i] += (summation[i] >> 31) & PARAM_Q;

            }

        }

        static void polynomialSubtractionCorrection(int[] difference, int[] minuend, int[] subtrahend)
        {

            for (int i = 0; i < PARAM_N; i++)
            {

                difference[i] = minuend[i] - subtrahend[i];
                /* If difference[i] < 0 Then Add Q */
                difference[i] += (difference[i] >> 31) & PARAM_Q;

            }

        }

        static void sparsePolynomialMultiplication32(int[] product, final int[] publicKey, final int[] positionList, final short[] signList)
        {

            int position;

            Arrays.fill(product, 0);

            for (int i = 0; i < PARAM_H; i++)
            {

                position = positionList[i];

                for (int j = 0; j < position; j++)
                {
                    product[j] -= (signList[i] * publicKey[PARAM_N + j - position]);
                }

                for (int j = position; j < PARAM_N; j++)
                {
                    product[j] += signList[i] * publicKey[j - position];
                }

            }

        }

        static void polynomialSubtractionMontgomery(int[] difference, int[] minuend, int[] subtrahend)
        {

            for (int i = 0; i < PARAM_N; i++)
            {

                difference[i] = montgomery((long)PARAM_R * (minuend[i] - subtrahend[i]));

            }

        }


        static long barrett(long number, int q, int barrettMultiplication, int barrettDivision)
        {

            return number - ((number * barrettMultiplication) >> barrettDivision) * q;

        }

        static int barrett(int number, int q, int barrettMultiplication, int barrettDivision)
        {

            return number - (int)(((long)number * barrettMultiplication) >> barrettDivision) * q;

        }

        static int montgomery(long number)
        {

            return (int)((number + ((number * PARAM_QINV) & 0xFFFFFFFFL) * PARAM_Q) >> 32);

        }
    }

}
