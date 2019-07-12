package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class QTesla5Size
{
    private static final int PARAM_LGM = 8;
    private static final int PARAM_M = (1 << PARAM_LGM);
    private static final int PARAM_N = (6 * PARAM_M);

    private static final double PARAM_SIGMA = 10.2;
    private static final int PARAM_Q = 33564673;
    private static final int PARAM_Q_LOG = 26;
    //    private static final long PARAM_QINV = 4034936831L;
//    private static final int PARAM_BARR_MULT = 511;
//    private static final int PARAM_BARR_DIV = 32;
    private static final int PARAM_B_BITS = 23;
    private static final int PARAM_B = ((1 << PARAM_B_BITS) - 1);
    private static final int PARAM_S_BITS = 9;
    private static final int PARAM_K = 1;
    private static final double PARAM_SIGMA_E = PARAM_SIGMA;
    private static final int PARAM_H = 77;
    private static final int PARAM_D = 24;
    private static final int PARAM_GEN_A = 73;
    private static final int PARAM_KEYGEN_BOUND_E = 1792;
    private static final int PARAM_E = (2 * PARAM_KEYGEN_BOUND_E);
    private static final int PARAM_KEYGEN_BOUND_S = 1792;
    private static final int PARAM_S = (2 * PARAM_KEYGEN_BOUND_S);
    private static final int PARAM_R2_INVN = 3118783;
    private static final int PARAM_R = 15873;
    private static final long RING_QREC = 549588076538L;


    public static final String CRYPTO_ALGNAME = "qTesla-V-Speed";

    private static final int CRYPTO_RANDOMBYTES = 32;
    private static final int CRYPTO_SEEDBYTES = 32;
    private static final int CRYPTO_C_BYTES = 32;
    private static final int HM_BYTES = 64;
    private static final int RADIX32 = 32;

    // Contains signature (z,c). z is a polynomial bounded by B, c is the output of a hashed string
    public static final int CRYPTO_BYTES = ((PARAM_N * (PARAM_B_BITS + 1) + 7) / 8 + CRYPTO_C_BYTES);
    // Contains polynomial s and e, and seeds seed_a and seed_y
    public static final int CRYPTO_SECRETKEYBYTES = (2 * PARAM_S_BITS * PARAM_N / 8 + 2 * CRYPTO_SEEDBYTES);
    // Contains seed_a and polynomial t
    public static final int CRYPTO_PUBLICKEYBYTES = ((PARAM_N * PARAM_Q_LOG + 7) / 8 + CRYPTO_SEEDBYTES);

    /******************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-1 and
     * 				Security Category-3 (Option for Size or Speed)
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     ******************************************************************************************************************************************************/
    public static int generateSignature(

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
        int[] secretPolynomial = new int[PARAM_N];
        int[] errorPolynomial = new int[PARAM_N];

        int[] A = new int[PARAM_N];
        int[] V = new int[PARAM_N];
        int[] Y = new int[PARAM_N];
        int[] Z = new int[PARAM_N];
        int[] Sc = new int[PARAM_N];
        int[] EC = new int[PARAM_N];


        /* Domain Separator for Sampling Y */
        int nonce = 0;

        decodePrivateKey(seed, secretPolynomial, errorPolynomial, privateKey);


        secureRandom.nextBytes(temporaryRandomnessInput);
        System.arraycopy(temporaryRandomnessInput, 0, randomnessInput, CRYPTO_RANDOMBYTES, CRYPTO_RANDOMBYTES);

        System.arraycopy(seed, CRYPTO_SEEDBYTES, randomnessInput, 0, CRYPTO_SEEDBYTES);


        HashUtils.secureHashAlgorithmKECCAK256(
            randomnessInput, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES, HM_BYTES, message, 0, messageLength);

        HashUtils.secureHashAlgorithmKECCAK256(
            randomness, 0, CRYPTO_SEEDBYTES, randomnessInput, 0, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + HM_BYTES);


        PolynomialLib.poly_uniform(A, seed, 0);





        /* Loop Due to Possible Rejection */
        while (true)
        {

            /* Sample Y Uniformly Random from -B to B */
            sampleY(Y, randomness, 0, ++nonce); //n, q, b, bBit);

            /* V = A * Y Modulo Q */
            PolynomialLib.poly_mul(V, A, Y);

            hashFunction(C, 0, V, randomnessInput, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES); //, n, d, q);


//
//            /* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
            encodeC(positionList, signList, C, 0);


            int c_ntt[] = new int[PARAM_N];

            for (int i = 0; i < PARAM_H; i++)
            {
                c_ntt[positionList[i]] = signList[i];
            }


            PolynomialLib.ntt(c_ntt);
            PolynomialLib.poly_mul(Sc, c_ntt, secretPolynomial);
            PolynomialLib.poly_add(Z, Y, Sc);


            if (testRejection(Z)) // PARAM_N, b, u))
            {
                continue;
            }


            //sparse_mul16(Ec, e, pos_list, sign_list);
            PolynomialLib.poly_mul(EC, c_ntt, errorPolynomial);
            PolynomialLib.poly_sub_correct(V, V, EC);

            if (test_correctness(V))
            {
                continue;
            }


            encodeSignature(signature, 0, C, 0, Z);
//
//
            return 0;

        }

    }


    public static int verifying(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey)
    {
        byte c[] = new byte[CRYPTO_C_BYTES];
        byte c_sig[] = new byte[CRYPTO_C_BYTES];
        byte seed[] = new byte[CRYPTO_SEEDBYTES];
        byte hm[] = new byte[HM_BYTES];
        int pos_list[] = new int[PARAM_H];
        short sign_list[] = new short[PARAM_H];
        int pk_t[] = new int[PARAM_N];
        int[] w = new int[PARAM_N];
        int[] z = new int[PARAM_N];
        int[] a = new int[PARAM_N];
        int[] Tc = new int[PARAM_N];

        if (signatureLength < CRYPTO_BYTES)
        {
            return -1;
        }

        decodeSignature(c, z, signature, signatureOffset);

        if (testZ(z))
        {
            return -2;
        }

        decodePublicKey(pk_t, seed, 0, publicKey);

        PolynomialLib.poly_uniform(a, seed, 0);
        encodeC(pos_list, sign_list, c, 0);

        int c_ntt[] = new int[PARAM_N];

        for (int i = 0; i < PARAM_H; i++)
        {
            c_ntt[pos_list[i]] = sign_list[i];
        }
        PolynomialLib.ntt(c_ntt);

        PolynomialLib.poly_mul(Tc, c_ntt, pk_t);
        PolynomialLib.poly_mul(w, a, z);
        PolynomialLib.poly_sub_reduce(w, w, Tc);

        HashUtils.secureHashAlgorithmKECCAK256(
            hm, 0, HM_BYTES, message, 0, message.length
        );
        hashFunction(c_sig, 0, w, hm, 0);

        if (!memoryEqual(c, 0, c_sig, 0, CRYPTO_C_BYTES))
        {
            return -3;
        }

        return 0;
    }


    public static int generateKeyPair(

        byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {

        byte[] randomness = new byte[CRYPTO_RANDOMBYTES];
        byte[] randomness_extended = new byte[4 * CRYPTO_SEEDBYTES];
        int[] s = new int[PARAM_N];
        int[] e = new int[PARAM_N];
        int[] a = new int[PARAM_N];
        int[] t = new int[PARAM_N];
        int nonce = 0;  // Initialize domain separator for error and secret polynomials

        secureRandom.nextBytes(randomness);
        HashUtils.secureHashAlgorithmKECCAK256(randomness_extended, 0, CRYPTO_SEEDBYTES * 4, randomness, 0, CRYPTO_RANDOMBYTES);


        do
        {  // Sample the error polynomial
            sample_gauss_poly(randomness_extended, 0, e, ++nonce);
        }
        while (checkPolynomial(e, PARAM_KEYGEN_BOUND_E));


        do
        {  // Sample the error polynomial
            sample_gauss_poly(randomness_extended, CRYPTO_SEEDBYTES, s, ++nonce);
        }
        while (checkPolynomial(s, PARAM_KEYGEN_BOUND_S));


        // Generate uniform polynomial "a"
        PolynomialLib.poly_uniform(a, randomness_extended, 2 * CRYPTO_SEEDBYTES);


        // Compute the public key t = as+e
        PolynomialLib.poly_mul(t, a, s);
        PolynomialLib.poly_add_correct(t, t, e);

        // Pack public and private keys

        encodePrivateKey(privateKey, s, e, randomness_extended, CRYPTO_SEEDBYTES * 2);
        encodePublicKey(publicKey, t, randomness_extended, CRYPTO_SEEDBYTES * 2);

        return 0;
    }

    private static boolean checkPolynomial(int[] polynomial, int bound)
    {

        int i, j, sum = 0, limit = PARAM_N;
        int temp, mask;
        int[] list = new int[PARAM_N];

        for (j = 0; j < PARAM_N; j++)
        {
            list[j] = absolute(polynomial[j]);
        }

        for (j = 0; j < PARAM_H; j++)
        {
            for (i = 0; i < limit - 1; i++)
            {
                // If list[i+1] > list[i] then exchange contents
                mask = (list[i + 1] - list[i]) >> (RADIX32 - 1);
                temp = (list[i + 1] & mask) | (list[i] & ~mask);
                list[i + 1] = (list[i] & mask) | (list[i + 1] & ~mask);
                list[i] = temp;
            }
            sum += list[limit - 1];
            limit -= 1;
        }

        return (sum > bound);
    }


    private static void sample_gauss_poly(byte[] randomnessExtended, int randomOffset, int[] poly, int nonce)
    {
        int dmsp = nonce << 8;

        for (int chunk = 0; chunk < PARAM_N; chunk += CHUNK_SIZE)
        {
            kmxGauss(poly, chunk, randomnessExtended, randomOffset, dmsp++);
        }

    }

    public static final int RADIX = 32;


    private static final int CHUNK_SIZE = 512;
    private static final int CDT_ROWS = 177;
    private static final int CDT_COLS = 7;

    private static long[] cdt_v = new long[]{
        0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, // 0
        0x05019F23L, 0x215AA886L, 0x266BD84AL, 0x1962528BL, 0x1B78B6C3L, 0x10702362L, 0x075CEACEL, // 1
        0x0EF8936EL, 0x23BFC791L, 0x31B19042L, 0x50351AA0L, 0x24A6BDB7L, 0x0EBAFAAAL, 0x281A6107L, // 2
        0x18CB03FCL, 0x0746C256L, 0x407022E8L, 0x334F94BAL, 0x7DF18AC4L, 0x798AFB36L, 0x7039E38CL, // 3
        0x2261C15EL, 0x4527ABF1L, 0x7CCF6441L, 0x00EF6D46L, 0x0B270487L, 0x3013B648L, 0x71EA5FC1L, // 4
        0x2BA749FEL, 0x4A371856L, 0x3A2CA997L, 0x5153CB0AL, 0x6E86FC2DL, 0x71393406L, 0x38CDCEFBL, // 5
        0x3488598AL, 0x0435B2D7L, 0x4DD990AEL, 0x0E7429C0L, 0x57C70926L, 0x77D180B7L, 0x1C885AC4L, // 6
        0x3CF45E22L, 0x01E1BF49L, 0x4CFF5AEEL, 0x26AE280CL, 0x1B580293L, 0x1BBE8EA6L, 0x64E2ACB5L, // 7
        0x44DDCECBL, 0x5BEB1ED9L, 0x2BD797BFL, 0x29192D65L, 0x01E8AAA2L, 0x5E55256FL, 0x7B92EE1FL, // 8
        0x4C3A608EL, 0x22F7BD95L, 0x7BAF5E4AL, 0x611E8A2EL, 0x24A3263DL, 0x5C654D5AL, 0x721F6EE1L, // 9
        0x530319A4L, 0x2AAB68C5L, 0x135B9B19L, 0x7D19FFA3L, 0x0F4BED85L, 0x700FDB24L, 0x33FED619L, // 10
        0x59344411L, 0x6FBA748BL, 0x4409DF71L, 0x76C2A4C2L, 0x458B7E7BL, 0x0B19F872L, 0x383591D2L, // 11
        0x5ECD42A3L, 0x12258E6CL, 0x70ABD8BFL, 0x33F8D6F8L, 0x1D4E8E7FL, 0x2EA9987CL, 0x5C71DE6AL, // 12
        0x63D04CBCL, 0x4B03A25AL, 0x17893AFDL, 0x00512D3CL, 0x4D0128C2L, 0x1DDA6A23L, 0x45DD76CEL, // 13
        0x68421661L, 0x279CDBF3L, 0x64BB398DL, 0x603BDA52L, 0x1EF54067L, 0x5CC606F2L, 0x71328EA3L, // 14
        0x6C296A64L, 0x58D40125L, 0x5D5E3204L, 0x45948D02L, 0x685E0BD9L, 0x1BA23EE0L, 0x1CE3F4BDL, // 15
        0x6F8EBCDCL, 0x2CBC9B6CL, 0x078DBD24L, 0x11153742L, 0x199011B0L, 0x48F8E372L, 0x12BA1FF2L, // 16
        0x727BBBA2L, 0x6464E481L, 0x6C03A4A4L, 0x4FBBF658L, 0x5E1F7EA0L, 0x51CCDF9DL, 0x6BFB1A05L, // 17
        0x74FAE221L, 0x32614E4BL, 0x4B399625L, 0x5284D9C8L, 0x3387DBE7L, 0x1B54382CL, 0x2C0B9401L, // 18
        0x771714BEL, 0x64DE7817L, 0x5BAFF2C0L, 0x3A75B025L, 0x7B3E1C06L, 0x187323D5L, 0x537D368BL, // 19
        0x78DB474CL, 0x64906B4AL, 0x36C15D1AL, 0x49AAA0FBL, 0x70260138L, 0x61C1FBC3L, 0x258DA96BL, // 20
        0x7A5230BFL, 0x213597F2L, 0x3ECC4E7BL, 0x5FFE21CAL, 0x0BA66FF1L, 0x66E2BEE1L, 0x4C4A36E6L, // 21
        0x7B860D68L, 0x0DD17AC2L, 0x34CE2917L, 0x13D0DE15L, 0x3DAE2C15L, 0x72433BD4L, 0x6A1E26E2L, // 22
        0x7C806FFEL, 0x7068EFBDL, 0x603BDD00L, 0x24292429L, 0x086F0A5DL, 0x52B3EB35L, 0x09480B65L, // 23
        0x7D4A20E9L, 0x2D5BC71BL, 0x470F64CEL, 0x63129FAFL, 0x04D4D45DL, 0x4AC6220BL, 0x33074061L, // 24
        0x7DEB0A96L, 0x00A6501CL, 0x4C461A13L, 0x790CAB85L, 0x74FC097EL, 0x05E7BEAFL, 0x5AA87152L, // 25
        0x7E6A3144L, 0x75C93242L, 0x16023571L, 0x06B7110BL, 0x1328C0AEL, 0x1F40DF96L, 0x6B478CC1L, // 26
        0x7ECDB456L, 0x661A7E35L, 0x162E551AL, 0x75DB9DA9L, 0x46974129L, 0x031C68B0L, 0x2B74986FL, // 27
        0x7F1AD71FL, 0x20516B1FL, 0x5FF00AE2L, 0x43DFF254L, 0x3B9EAE78L, 0x06866816L, 0x447D78BCL, // 28
        0x7F560F41L, 0x3300DE7CL, 0x4B8F0799L, 0x5C3E4574L, 0x5B305708L, 0x0B96B8DCL, 0x5736634BL, // 29
        0x7F8316C3L, 0x1226EADBL, 0x51D0E0B1L, 0x5870949AL, 0x74462F50L, 0x56567448L, 0x12F77EB5L, // 30
        0x7FA5003CL, 0x3183FE96L, 0x56A3015DL, 0x5471CE29L, 0x22B635B1L, 0x43887505L, 0x1A18922DL, // 31
        0x7FBE4BCBL, 0x237FBE88L, 0x06124F61L, 0x189877D0L, 0x48CAA53FL, 0x1265E21AL, 0x62BF19B0L, // 32
        0x7FD0FBBEL, 0x4900A57BL, 0x1231A728L, 0x21713D51L, 0x223431D3L, 0x5B78BFB2L, 0x176771CFL, // 33
        0x7FDEA82DL, 0x4264689CL, 0x090BD52BL, 0x35B3EF58L, 0x45E2BC10L, 0x1CBD0BB0L, 0x0E4BD14EL, // 34
        0x7FE890F4L, 0x7F427C59L, 0x3FEA77A7L, 0x76B5CEC4L, 0x45944DB0L, 0x6431AACAL, 0x406F6970L, // 35
        0x7FEFADC9L, 0x235461F2L, 0x76530FE7L, 0x458AFED6L, 0x1600521DL, 0x496DF752L, 0x557C7C91L, // 36
        0x7FF4BC39L, 0x47D62996L, 0x080C04AEL, 0x5578E91DL, 0x1A4B652DL, 0x1F2C5708L, 0x7FC057F8L, // 37
        0x7FF84BA5L, 0x449EAC84L, 0x43D826FAL, 0x01AFCF15L, 0x082E7148L, 0x174C9617L, 0x0EF4B981L, // 38
        0x7FFAC73EL, 0x68B27237L, 0x1032E3F9L, 0x63DED627L, 0x790A03A1L, 0x12C02669L, 0x32E13A7AL, // 39
        0x7FFC7E40L, 0x6CDCE391L, 0x74D2C6E0L, 0x56F439FAL, 0x25E1A719L, 0x2F7BA7D3L, 0x6BBB03FDL, // 40
        0x7FFDAA93L, 0x2A0A579FL, 0x4E3FD638L, 0x555547D0L, 0x3DC84165L, 0x1B63F1D7L, 0x65F61784L, // 41
        0x7FFE760EL, 0x7D0DA319L, 0x04AE9E8DL, 0x47F8B424L, 0x2790150FL, 0x1465810DL, 0x60758064L, // 42
        0x7FFEFE9CL, 0x00E6F118L, 0x5B12C69BL, 0x63045184L, 0x4D76C4FCL, 0x005448BAL, 0x6BBC8934L, // 43
        0x7FFF595EL, 0x1329625AL, 0x788CC79FL, 0x61B72C9CL, 0x288DD9B9L, 0x63482AE8L, 0x51A31E34L, // 44
        0x7FFF951CL, 0x7C94755BL, 0x7F1054DFL, 0x57D6E351L, 0x3556F636L, 0x322AA171L, 0x09AB76A4L, // 45
        0x7FFFBC11L, 0x0D63DD99L, 0x16E1DEEDL, 0x5FA47FD6L, 0x3E02C7F5L, 0x1292E768L, 0x5C9950B6L, // 46
        0x7FFFD538L, 0x56FC93F8L, 0x4BF6F51DL, 0x65D1F42EL, 0x66614419L, 0x743999F4L, 0x4775F539L, // 47
        0x7FFFE54FL, 0x26D25196L, 0x4AF51374L, 0x7A3F204DL, 0x325CBC6EL, 0x35468E0BL, 0x0E6AFF8BL, // 48
        0x7FFFEF80L, 0x25C7892BL, 0x5FC036B7L, 0x563D2EF5L, 0x272F2784L, 0x60F8917AL, 0x2B7798D4L, // 49
        0x7FFFF5E5L, 0x17797BB9L, 0x4AED0883L, 0x55F4708EL, 0x2F8E9E16L, 0x42ADBC77L, 0x2C514F20L, // 50
        0x7FFFF9DEL, 0x2C7B5848L, 0x63C7FD09L, 0x7144559BL, 0x642F3815L, 0x3BC263D4L, 0x2E151167L, // 51
        0x7FFFFC50L, 0x2F236C2DL, 0x04B38B5DL, 0x67E03136L, 0x1505949DL, 0x555E169AL, 0x2B0CDB87L, // 52
        0x7FFFFDCDL, 0x7C5C8A99L, 0x47780740L, 0x3CCCFB88L, 0x658A4A5AL, 0x62742D3FL, 0x7EE61718L, // 53
        0x7FFFFEB4L, 0x2E1E4A11L, 0x366AC9FCL, 0x2F9E887BL, 0x5CAE301EL, 0x50530164L, 0x7CFA1FA4L, // 54
        0x7FFFFF3EL, 0x0FEBD46FL, 0x6BC1CE85L, 0x72F069E6L, 0x7A679EADL, 0x4D21ABE8L, 0x30D0A287L, // 55
        0x7FFFFF8FL, 0x5B6E489EL, 0x28751892L, 0x56C780B4L, 0x62C86BA2L, 0x7679DF3EL, 0x5A88A82AL, // 56
        0x7FFFFFBFL, 0x495E9E5FL, 0x7EAA1ACBL, 0x351B085FL, 0x3C5DFCC9L, 0x7033F18AL, 0x3BAFCD90L, // 57
        0x7FFFFFDBL, 0x3057607BL, 0x28E384A2L, 0x5C5256A0L, 0x32AE45A9L, 0x34190D12L, 0x2E65E081L, // 58
        0x7FFFFFEBL, 0x3035C5A3L, 0x15A78AB7L, 0x0FC670CFL, 0x3A9031EAL, 0x1B601810L, 0x73E214C7L, // 59
        0x7FFFFFF4L, 0x3F4D8780L, 0x66D50D33L, 0x63B5CAFFL, 0x61595249L, 0x3E0FEE39L, 0x4EC7BC6CL, // 60
        0x7FFFFFF9L, 0x5212DCE2L, 0x6CD045D5L, 0x07DDE51EL, 0x0FB442F9L, 0x726ABB1BL, 0x399494D3L, // 61
        0x7FFFFFFCL, 0x425CE8A8L, 0x02F46379L, 0x69404141L, 0x0DE16EC1L, 0x01DFD140L, 0x16EDF35DL, // 62
        0x7FFFFFFEL, 0x0E49947FL, 0x0E07EA75L, 0x3B58DBEAL, 0x2C87E79EL, 0x17451064L, 0x5BB480FBL, // 63
        0x7FFFFFFEL, 0x7E1F309BL, 0x2F0778A7L, 0x2D18E896L, 0x16CBED25L, 0x35E62E74L, 0x4A06DE56L, // 64
        0x7FFFFFFFL, 0x3ADDCA91L, 0x5A24C395L, 0x56E970E7L, 0x46AD989DL, 0x29A487F6L, 0x6717F088L, // 65
        0x7FFFFFFFL, 0x5B8B8969L, 0x73D05913L, 0x5979C1D5L, 0x3E870DF4L, 0x4BF68805L, 0x3B5B26F9L, // 66
        0x7FFFFFFFL, 0x6CF50016L, 0x4970EBFFL, 0x7B2F8760L, 0x2C756F1BL, 0x37E84584L, 0x462E2ED6L, // 67
        0x7FFFFFFFL, 0x7625525CL, 0x0AF78928L, 0x125CBC7DL, 0x7A62F256L, 0x7143E720L, 0x66C80349L, // 68
        0x7FFFFFFFL, 0x7AF2D44BL, 0x4619F7B3L, 0x318AF6FCL, 0x1683F758L, 0x6B101249L, 0x3BDF8061L, // 69
        0x7FFFFFFFL, 0x7D6F51AFL, 0x18D38DD1L, 0x73C75828L, 0x585FD26AL, 0x291F5F7BL, 0x7042595CL, // 70
        0x7FFFFFFFL, 0x7EB5AA16L, 0x20B148BBL, 0x23D956F7L, 0x7BD5B5C7L, 0x72795377L, 0x5F107BB5L, // 71
        0x7FFFFFFFL, 0x7F5B63C8L, 0x7DDB2AD8L, 0x2773EA98L, 0x110B0D21L, 0x507254BFL, 0x567857BFL, // 72
        0x7FFFFFFFL, 0x7FAEBE67L, 0x62813FEFL, 0x732DBF3BL, 0x4DFFDC9DL, 0x7EDF0637L, 0x5186F8DAL, // 73
        0x7FFFFFFFL, 0x7FD8444FL, 0x2E032276L, 0x5B2AFA19L, 0x04581C6EL, 0x79E07CBFL, 0x2DAE29FEL, // 74
        0x7FFFFFFFL, 0x7FECC0FAL, 0x55F8D363L, 0x07F7A470L, 0x403014C4L, 0x412437E0L, 0x550DD47CL, // 75
        0x7FFFFFFFL, 0x7FF6C3E2L, 0x30CFCC16L, 0x21550403L, 0x0968F238L, 0x05F08F1AL, 0x6AA46C1AL, // 76
        0x7FFFFFFFL, 0x7FFB9C50L, 0x5FBBDCD2L, 0x06635365L, 0x59089E37L, 0x17D6E9BAL, 0x276CEAC0L, // 77
        0x7FFFFFFFL, 0x7FFDEEEFL, 0x0D5AA5B2L, 0x756EF80AL, 0x090472C8L, 0x525340F4L, 0x430EF28AL, // 78
        0x7FFFFFFFL, 0x7FFF093FL, 0x0AEFA9CBL, 0x71B85E69L, 0x35A7E2A7L, 0x2531F904L, 0x413AA3A6L, // 79
        0x7FFFFFFFL, 0x7FFF8E00L, 0x09F364F6L, 0x34A17AD8L, 0x76BD8136L, 0x5683F3CEL, 0x10FED6E7L, // 80
        0x7FFFFFFFL, 0x7FFFCBD4L, 0x1CD513A4L, 0x5CB1E269L, 0x5939D904L, 0x5CA9B01BL, 0x20A0DBE4L, // 81
        0x7FFFFFFFL, 0x7FFFE859L, 0x400469ACL, 0x7530AE2CL, 0x628AD0A7L, 0x141964ABL, 0x7C5DAC00L, // 82
        0x7FFFFFFFL, 0x7FFFF561L, 0x1F898BDBL, 0x04826122L, 0x418CA3EBL, 0x47670ABDL, 0x485EB10BL, // 83
        0x7FFFFFFFL, 0x7FFFFB46L, 0x5697977EL, 0x7C47A5FBL, 0x73E767F1L, 0x0F3FFBAFL, 0x5AF66E4BL, // 84
        0x7FFFFFFFL, 0x7FFFFDEBL, 0x14C7AD1BL, 0x6DFCE35AL, 0x4FBD3EDBL, 0x29519FBCL, 0x3BF06C9FL, // 85
        0x7FFFFFFFL, 0x7FFFFF17L, 0x38F29E00L, 0x15864C26L, 0x3ED1C921L, 0x2DD8365AL, 0x6FF5D263L, // 86
        0x7FFFFFFFL, 0x7FFFFF9BL, 0x3B053D45L, 0x67D04FC5L, 0x2633B08BL, 0x3C36A297L, 0x6B5049E6L, // 87
        0x7FFFFFFFL, 0x7FFFFFD4L, 0x790609C5L, 0x5E96D83FL, 0x7D309D5EL, 0x49685B8CL, 0x6525899BL, // 88
        0x7FFFFFFFL, 0x7FFFFFEDL, 0x5E4DD5C7L, 0x7D8F388AL, 0x4FA72501L, 0x759163C3L, 0x5965B99FL, // 89
        0x7FFFFFFFL, 0x7FFFFFF8L, 0x29C05963L, 0x0645E13DL, 0x57138B46L, 0x704839F7L, 0x7E47F4ABL, // 90
        0x7FFFFFFFL, 0x7FFFFFFCL, 0x672F2508L, 0x3FCB5C25L, 0x75E8C19BL, 0x79B927A6L, 0x459388BFL, // 91
        0x7FFFFFFFL, 0x7FFFFFFEL, 0x57757A13L, 0x73F0B7CEL, 0x4BA283D2L, 0x4A67664DL, 0x7958BF63L, // 92
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x3B2C73A1L, 0x6BA2B500L, 0x01AEDEAFL, 0x4CB02493L, 0x05131E4AL, // 93
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x6428E338L, 0x5026719CL, 0x0658B0CAL, 0x12B28E84L, 0x1CE29302L, // 94
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x74D85FA8L, 0x5D9E5301L, 0x2D5735E5L, 0x4DFDEDC4L, 0x302571CBL, // 95
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7B92AB00L, 0x044C95FAL, 0x0AA5A52BL, 0x7E3C7C97L, 0x10174031L, // 96
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E42777FL, 0x7055A4A5L, 0x77909EC2L, 0x0A72199CL, 0x7C047649L, // 97
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F528317L, 0x1E611B25L, 0x77B0E768L, 0x76EF5F68L, 0x5C5E0880L, // 98
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FBD15BEL, 0x591E5FD1L, 0x42A39695L, 0x5753E03DL, 0x4888BA10L, // 99
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FE66F66L, 0x4ED42CB5L, 0x25B46819L, 0x29F65AF3L, 0x480D7FB5L, // 100
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF65357L, 0x3C11F581L, 0x1EE81339L, 0x0B548369L, 0x4C176653L, // 101
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC5FA6L, 0x13A72C4CL, 0x41D2C974L, 0x4D7D4F15L, 0x137E1A5CL, // 102
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFEA751L, 0x0087E172L, 0x6450815CL, 0x06BD4974L, 0x35A068B7L, // 103
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF813CL, 0x68963485L, 0x2D62B319L, 0x7F6D36F5L, 0x053AFCFFL, // 104
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFD1D2L, 0x6710A409L, 0x035B53E9L, 0x6B754C14L, 0x67E4986EL, // 105
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFEF56L, 0x56112414L, 0x147B7548L, 0x01A3C15AL, 0x5C3AEECDL, // 106
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFA0BL, 0x4B034EF2L, 0x2FE56ACCL, 0x5AB28803L, 0x2EDA5188L, // 107
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFDE4L, 0x2CC83513L, 0x334F55FEL, 0x0629A93FL, 0x38A4E0E3L, // 108
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF42L, 0x631F9BC6L, 0x69E7B1D4L, 0x0ACC308EL, 0x1A5D01F4L, // 109
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFBEL, 0x23B1C1ECL, 0x1AD56ACDL, 0x1D531D5CL, 0x2361A1E2L, // 110
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFE9L, 0x32023A0BL, 0x2448F18BL, 0x1283D5AEL, 0x6C85EB4BL, // 111
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF8L, 0x25DDC591L, 0x10460958L, 0x160127B6L, 0x0D23122BL, // 112
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFDL, 0x332A0006L, 0x39060F98L, 0x583A2EE5L, 0x7F6F4B30L, // 113
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x10BAC302L, 0x0B63D3F3L, 0x34548417L, 0x6417CEF7L, // 114
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x5B278E34L, 0x3CFCAA9CL, 0x63C0AB49L, 0x7EF44CC5L, // 115
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x73EA444EL, 0x71B589C1L, 0x40C37AB8L, 0x05AC3C2BL, // 116
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7C12EEC8L, 0x581AE332L, 0x1F6B2998L, 0x7B3F4742L, // 117
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7EBC95AFL, 0x0FCE42E4L, 0x1A12647DL, 0x312F2344L, // 118
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F98EB42L, 0x773D755CL, 0x6BA5569EL, 0x0B59780DL, // 119
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FDF7528L, 0x257E6D28L, 0x0DD3B8AAL, 0x7A8DB84CL, // 120
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF5D2FBL, 0x06D06F83L, 0x59078672L, 0x01289F57L, // 121
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFCD92AL, 0x3D1F735FL, 0x3DD750C7L, 0x724A384AL, // 122
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF087BL, 0x157C8C2CL, 0x592F1FD5L, 0x5BCAB49DL, // 123
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFB4C9L, 0x75D8D62BL, 0x5E6F960FL, 0x6E7A0825L, // 124
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFE95DL, 0x0AB518E5L, 0x5EBFD0F1L, 0x6EF5DC28L, // 125
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF940L, 0x3E71644DL, 0x1DCD2F7FL, 0x20F92853L, // 126
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFE01L, 0x74E02F84L, 0x5CDE6F58L, 0x782A7B08L, // 127
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF6AL, 0x68B9722FL, 0x24BE2517L, 0x653EBEA0L, // 128
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFD4L, 0x6475CC5AL, 0x1C2EEA1AL, 0x0328E2D1L, // 129
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF3L, 0x4CDD3713L, 0x39FF33E5L, 0x26D4E741L, // 130
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFCL, 0x3CF1DAA4L, 0x4F9A6798L, 0x61EA76B6L, // 131
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x0108514BL, 0x67772555L, 0x64F8745AL, // 132
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x5C999EB3L, 0x08168B63L, 0x46AF07F6L, // 133
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x76395C01L, 0x6F3CFAEAL, 0x131AD6A3L, // 134
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7D5374F0L, 0x5731E351L, 0x7C6F380DL, // 135
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F468A5EL, 0x4EA7CE39L, 0x036A7B8EL, // 136
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FCE3B9BL, 0x7CED4D0CL, 0x4046A3D8L, // 137
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF2C5BAL, 0x616952F6L, 0x04D4F456L, // 138
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC8488L, 0x300FEBA6L, 0x4F2917BBL, // 139
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF178CL, 0x1CEB1D35L, 0x54FDFB4FL, // 140
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFC3F6L, 0x7CDFB395L, 0x0DE10FC7L, // 141
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF0A4L, 0x3AAF842EL, 0x4F2D7D3EL, // 142
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFC1BL, 0x6D46EB35L, 0x39A589F1L, // 143
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF06L, 0x00F9D719L, 0x7C80C709L, // 144
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFC1L, 0x6E09C112L, 0x40F91447L, // 145
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF0L, 0x59BA3B04L, 0x533C64C9L, // 146
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFCL, 0x2277000DL, 0x3FFCCF35L, // 147
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x0CA8F6AFL, 0x04FDBCC1L, // 148
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x64683B2DL, 0x4DC73C3EL, // 149
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x79763BB9L, 0x6D56EF81L, // 150
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E772DC4L, 0x19BE9910L, // 151
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FA4AFACL, 0x238F593BL, // 152
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FEAF9D0L, 0x20A7706EL, // 153
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFB349CL, 0x425A62E3L, // 154
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFEEAC4L, 0x14FBA4D6L, // 155
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFC1FAL, 0x18FE5A04L, // 156
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF241L, 0x574E3E93L, // 157
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFCFBL, 0x68B2B84CL, // 158
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF58L, 0x1212FAD2L, // 159
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFDBL, 0x6DDE1CBEL, // 160
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF8L, 0x2571DA8CL, // 161
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFEL, 0x2F9DBF36L, // 162
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x54677433L, // 163
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x76F75F40L, // 164
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E255C0FL, // 165
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F9F83B6L, // 166
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FEC92C7L, // 167
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC203AL, // 168
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF3C1BL, // 169
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFD9ADL, // 170
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF893L, // 171
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFE93L, // 172
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFBAL, // 173
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF3L, // 174
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFDL, // 175
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, // 176
    }; // cdt_v


    private static void kmxGauss(int[] z, int chunk, byte[] seed, int seedOffset, int nonce)
    {
        int[] sampk = new int[(CHUNK_SIZE + CDT_ROWS) * CDT_COLS];
        int[] sampg = new int[CHUNK_SIZE + CDT_ROWS];


        {
            // In the C Implementation they cast between uint_8 and int32 a lot, this is one of those situations.
            byte[] sampkBytes = new byte[sampk.length * 4];
            HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
                sampkBytes, 0, CHUNK_SIZE * CDT_COLS * 4, (short)nonce, seed, seedOffset, CRYPTO_RANDOMBYTES);
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
                sampk[i] = Pack.littleEndianToInt(sampkBytes, t);
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
            z[i + chunk] = (sampg[i] << (RADIX32 - 16)) >> (RADIX32 - 16);
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
            int apPtr = p * CDT_COLS;
            int a_iPtr = 0;
            int ap_iPtr = apPtr;
            int gpPtr = p;

            int neg = ~0;

            for (int i = 0; i < n - p; i++, a_iPtr += CDT_COLS, ap_iPtr += CDT_COLS)
            {
                if (!((i & p) != 0))
                {
                    {
                        int diff = 0, swapa;
                        int swapg;
                        {

                            {
                                diff = (diff + (a[ap_iPtr + 6] & ((neg >>> 1))) - (a[a_iPtr + 6] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                diff = (diff + (a[ap_iPtr + 5] & ((neg >>> 1))) - (a[a_iPtr + 5] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                diff = (diff + (a[ap_iPtr + 4] & ((neg >>> 1))) - (a[a_iPtr + 4] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                diff = (diff + (a[ap_iPtr + 3] & ((neg >>> 1))) - (a[a_iPtr + 3] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                {
                                    diff = (diff + (a[ap_iPtr + 2] & (neg >>> 1))) - (a[a_iPtr + 2] & ((neg >>> 1))) >> (32 - 1);
                                }
                                ;
                                {
                                    {
                                        diff = (diff + (a[ap_iPtr + 1] & (neg >>> 1))) - (a[a_iPtr + 1] & ((neg >>> 1))) >> (32 - 1);
                                    }
                                    ;
                                    {
                                        {
                                            diff = (diff + (a[ap_iPtr] & ((neg >>> 1))) - (a[a_iPtr] & ((neg >>> 1)))) >> (32 - 1);
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
                                    swapa = (a[a_iPtr + 2] ^ a[ap_iPtr + 2]) & diff;
                                    a[a_iPtr + 2] ^= swapa;
                                    a[ap_iPtr + 2] ^= swapa;
                                }
                                ;
                            }
                            ;
                            {
                                swapa = (a[a_iPtr + 3] ^ a[ap_iPtr + 3]) & diff;
                                a[a_iPtr + 3] ^= swapa;
                                a[ap_iPtr + 3] ^= swapa;
                            }

                            {
                                swapa = (a[a_iPtr + 4] ^ a[ap_iPtr + 4]) & diff;
                                a[a_iPtr + 4] ^= swapa;
                                a[ap_iPtr + 4] ^= swapa;
                            }
                            {
                                swapa = (a[a_iPtr + 5] ^ a[ap_iPtr + 5]) & diff;
                                a[a_iPtr + 5] ^= swapa;
                                a[ap_iPtr + 5] ^= swapa;
                            }

                            {
                                swapa = (a[a_iPtr + 6] ^ a[ap_iPtr + 6]) & diff;
                                a[a_iPtr + 6] ^= swapa;
                                a[ap_iPtr + 6] ^= swapa;
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
                int aq_iPtr = q * CDT_COLS;
                int gqPtr = q;
                for (int i = 0; i < n - q; i++, ap_iPtr_ += CDT_COLS, aq_iPtr += CDT_COLS)
                {
                    if (!((i & p) != 0))
                    {
                        {
                            int diff = 0, swapa;
                            int swapg;
                            {
                                {
                                    diff = (diff + (a[aq_iPtr + 6] & (neg >>> 1))) - (a[ap_iPtr_ + 6] & (neg >>> 1)) >> (32 - 1);
                                }

                                {
                                    diff = (diff + (a[aq_iPtr + 5] & (neg >>> 1))) - (a[ap_iPtr_ + 5] & (neg >>> 1)) >> (32 - 1);
                                }

                                {
                                    diff = (diff + (a[aq_iPtr + 4] & (neg >>> 1))) - (a[ap_iPtr_ + 4] & (neg >>> 1)) >> (32 - 1);
                                }

                                {
                                    diff = (diff + (a[aq_iPtr + 3] & (neg >>> 1))) - (a[ap_iPtr_ + 3] & (neg >>> 1)) >> (32 - 1);
                                }
                                ;
                                {
                                    {
                                        diff = (diff + (a[aq_iPtr + 2] & (neg >>> 1))) - (a[ap_iPtr_ + 2] & (neg >>> 1)) >> (32 - 1);
                                    }
                                    ;
                                    {
                                        {
                                            diff = (diff + (a[aq_iPtr + 1] & (neg >>> 1))) - (a[ap_iPtr_ + 1] & (neg >>> 1)) >> (32 - 1);
                                        }
                                        ;
                                        {
                                            {
                                                diff = (diff + (a[aq_iPtr] & (neg >>> 1))) - (a[ap_iPtr_] & (neg >>> 1)) >> (32 - 1);
                                            }
                                            ;
                                            {
                                                swapa = (a[ap_iPtr_] ^ a[aq_iPtr]) & diff;
                                                a[ap_iPtr_] ^= swapa;
                                                a[aq_iPtr] ^= swapa;
                                            }
                                            ;
                                        }
                                        ;
                                        {
                                            swapa = (a[ap_iPtr_ + 1] ^ a[aq_iPtr + 1]) & diff;
                                            a[ap_iPtr_ + 1] ^= swapa;
                                            a[aq_iPtr + 1] ^= swapa;
                                        }
                                        ;
                                    }
                                    ;
                                    {
                                        swapa = (a[ap_iPtr_ + 2] ^ a[aq_iPtr + 2]) & diff;
                                        a[ap_iPtr_ + 2] ^= swapa;
                                        a[aq_iPtr + 2] ^= swapa;
                                    }
                                    ;
                                }
                                ;
                                {
                                    swapa = (a[ap_iPtr_ + 3] ^ a[aq_iPtr + 3]) & diff;
                                    a[ap_iPtr_ + 3] ^= swapa;
                                    a[aq_iPtr + 3] ^= swapa;
                                }
                                ;
                                {
                                    swapa = (a[ap_iPtr_ + 4] ^ a[aq_iPtr + 4]) & diff;
                                    a[ap_iPtr_ + 4] ^= swapa;
                                    a[aq_iPtr + 4] ^= swapa;
                                }
                                ;

                                {
                                    swapa = (a[ap_iPtr_ + 5] ^ a[aq_iPtr + 5]) & diff;
                                    a[ap_iPtr_ + 5] ^= swapa;
                                    a[aq_iPtr + 5] ^= swapa;
                                }
                                ;
                                {
                                    swapa = (a[ap_iPtr_ + 6] ^ a[aq_iPtr + 6]) & diff;
                                    a[ap_iPtr_ + 6] ^= swapa;
                                    a[aq_iPtr + 6] ^= swapa;
                                }
                                ;
                            }
                            ;
                            {
                                swapg = (g[gpPtr + i] ^ g[gqPtr + i]) & diff;
                                g[gpPtr + i] ^= swapg;
                                g[gqPtr + i] ^= swapg;
                            }
                            ;
                        }
                        ;

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


    private static boolean testZ(int[] Z)
    {
        // Returns false if valid, otherwise outputs 1 if invalid (rejected)

        for (int i = 0; i < PARAM_N; i++)
        {

            if ((Z[i] < -(PARAM_B - PARAM_S)) || (Z[i] > PARAM_B - PARAM_S))
            {

                return true;

            }

        }

        return false;

    }


    static boolean test_correctness(int[] v)
    { // Check bounds for w = v - ec during signature verification. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
        // This function leaks the position of the coefficient that fails the test (but this is independent of the secret data).
        // It does not leak the sign of the coefficients.
        int mask, left, val;
        int t0, t1;

        for (int i = 0; i < PARAM_N; i++)
        {
            // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
            mask = (PARAM_Q / 2 - v[i]) >> (RADIX32 - 1);
            val = ((v[i] - PARAM_Q) & mask) | (v[i] & ~mask);
            // If (Abs(val) < PARAM_Q/2 - PARAM_E) then t0 = 0, else t0 = 1
            t0 = (~(absolute(val) - (PARAM_Q / 2 - PARAM_E))) >>> (RADIX32 - 1);

            left = val;
            val = (val + (1 << (PARAM_D - 1)) - 1) >> PARAM_D;
            val = left - (val << PARAM_D);
            // If (Abs(val) < (1<<(PARAM_D-1))-PARAM_E) then t1 = 0, else t1 = 1
            t1 = (~(absolute(val) - ((1 << (PARAM_D - 1)) - PARAM_E))) >>> (RADIX32 - 1);

            if ((t0 | t1) == 1)  // Returns 1 if any of the two tests failed
            {
                return true;
            }
        }
        return false;
    }


    private static int absolute(int value)
    {

        return ((value >> 31) ^ value) - (value >> 31);

    }

    private static long absolute(long value)
    {

        return ((value >> 63) ^ value) - (value >> 63);

    }


    private static boolean testRejection(int[] Z) //, int n, int b, int u)
    {

        int valid = 0;

        for (int i = 0; i < PARAM_N; i++)
        {
            valid |= (PARAM_B - PARAM_S) - absolute(Z[i]);

        }

        return (valid >>> 31) != 0;

    }


    private static void hashFunction(byte[] output, int outputOffset, int[] v, final byte[] message, int messageOffset) //, int n, int d, int q)
    {

        int mask;
        int cL;

        byte[] T = new byte[PARAM_N + HM_BYTES];

        for (int i = 0; i < PARAM_N; i++)
        {
            /* If V[i] > Q / 2 Then V[i] = V[i] - Q */
            // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
            mask = (PARAM_Q / 2 - v[i]) >> (RADIX32 - 1);
            v[i] = ((v[i] - PARAM_Q) & mask) | (v[i] & ~mask);

            cL = v[i] & ((1 << PARAM_D) - 1);
            // If cL > 2^(d-1) then cL -= 2^d
            mask = ((1 << (PARAM_D - 1)) - cL) >> (RADIX32 - 1);
            cL = ((cL - (1 << PARAM_D)) & mask) | (cL & ~mask);
            T[i] = (byte)((v[i] - cL) >> PARAM_D);

        }

        System.arraycopy(message, messageOffset, T, PARAM_N, HM_BYTES);
        HashUtils.secureHashAlgorithmKECCAK256(output, outputOffset, CRYPTO_C_BYTES, T, 0, PARAM_N + HM_BYTES);

    }

    public static void encodeC(int[] positionList, short[] signList, byte[] output, int outputOffset)
    {

        int count = 0;
        int position;
        short domainSeparator = 0;
        short[] C = new short[PARAM_N];
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
        for (int i = 0; i < PARAM_H; )
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
            position &= (PARAM_N - 1);

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


    public static void encodePrivateKey(byte[] privateKey, final int[] secretPolynomial, final int[] errorPolynomial, final byte[] seed, int seedOffset)
    {
        byte[] sk = privateKey;
        int[] s = secretPolynomial;
        int[] e = errorPolynomial;

        int j = 0;

        for (int i = 0; i < PARAM_N; i += 8)
        {
            sk[j + 0] = (byte)s[i + 0];
            sk[j + 1] = (byte)(((s[i + 0] >> 8) & 0x01) | (s[i + 1] << 1));
            sk[j + 2] = (byte)(((s[i + 1] >> 7) & 0x03) | (s[i + 2] << 2));
            sk[j + 3] = (byte)(((s[i + 2] >> 6) & 0x07) | (s[i + 3] << 3));
            sk[j + 4] = (byte)(((s[i + 3] >> 5) & 0x0F) | (s[i + 4] << 4));
            sk[j + 5] = (byte)(((s[i + 4] >> 4) & 0x1F) | (s[i + 5] << 5));
            sk[j + 6] = (byte)(((s[i + 5] >> 3) & 0x3F) | (s[i + 6] << 6));
            sk[j + 7] = (byte)(((s[i + 6] >> 2) & 0x7F) | (s[i + 7] << 7));
            sk[j + 8] = (byte)(s[i + 7] >> 1);
            j += 9;
        }
        for (int i = 0; i < PARAM_N; i += 8)
        {
            sk[j + 0] = (byte)e[i + 0];
            sk[j + 1] = (byte)(((e[i + 0] >> 8) & 0x01) | (e[i + 1] << 1));
            sk[j + 2] = (byte)(((e[i + 1] >> 7) & 0x03) | (e[i + 2] << 2));
            sk[j + 3] = (byte)(((e[i + 2] >> 6) & 0x07) | (e[i + 3] << 3));
            sk[j + 4] = (byte)(((e[i + 3] >> 5) & 0x0F) | (e[i + 4] << 4));
            sk[j + 5] = (byte)(((e[i + 4] >> 4) & 0x1F) | (e[i + 5] << 5));
            sk[j + 6] = (byte)(((e[i + 5] >> 3) & 0x3F) | (e[i + 6] << 6));
            sk[j + 7] = (byte)(((e[i + 6] >> 2) & 0x7F) | (e[i + 7] << 7));
            sk[j + 8] = (byte)(e[i + 7] >> 1);
            j += 9;
        }
        System.arraycopy(seed, seedOffset, privateKey, 2 * PARAM_S_BITS * PARAM_N / 8, CRYPTO_SEEDBYTES * 2);

    }


    public static void decodePrivateKey(byte[] seed, int[] s, int[] e, final byte[] sk)
    {

        int j = 0;

        for (int i = 0; i < PARAM_N; i += 8)
        {

            s[i + 0] = (short)((sk[j + 0] & 0xFF) | ((sk[j + 1] & 0xFF) << 31) >> 23);
            s[i + 1] = (short)(((sk[j + 1] & 0xFF) >>> 1) | ((sk[j + 2] & 0xFF) << 30) >> 23);
            s[i + 2] = (short)(((sk[j + 2] & 0xFF) >>> 2) | ((sk[j + 3] & 0xFF) << 29) >> 23);
            s[i + 3] = (short)(((sk[j + 3] & 0xFF) >>> 3) | ((sk[j + 4] & 0xFF) << 28) >> 23);
            s[i + 4] = (short)(((sk[j + 4] & 0xFF) >>> 4) | ((sk[j + 5] & 0xFF) << 27) >> 23);
            s[i + 5] = (short)(((sk[j + 5] & 0xFF) >>> 5) | ((sk[j + 6] & 0xFF) << 26) >> 23);
            s[i + 6] = (short)(((sk[j + 6] & 0xFF) >>> 6) | ((sk[j + 7] & 0xFF) << 25) >> 23);
            s[i + 7] = (short)(((sk[j + 7] & 0xFF) >>> 7) | (sk[j + 8] << 1)); // j+8 is to be treated as signed.

            j += 9;
        }

        for (int i = 0; i < PARAM_N; i += 8)
        {
            e[i + 0] = (short)((sk[j + 0] & 0xFF) | ((sk[j + 1] & 0xFF) << 31) >> 23);
            e[i + 1] = (short)(((sk[j + 1] & 0xFF) >>> 1) | ((sk[j + 2] & 0xFF) << 30) >> 23);
            e[i + 2] = (short)(((sk[j + 2] & 0xFF) >>> 2) | ((sk[j + 3] & 0xFF) << 29) >> 23);
            e[i + 3] = (short)(((sk[j + 3] & 0xFF) >>> 3) | ((sk[j + 4] & 0xFF) << 28) >> 23);
            e[i + 4] = (short)(((sk[j + 4] & 0xFF) >>> 4) | ((sk[j + 5] & 0xFF) << 27) >> 23);
            e[i + 5] = (short)(((sk[j + 5] & 0xFF) >>> 5) | ((sk[j + 6] & 0xFF) << 26) >> 23);
            e[i + 6] = (short)(((sk[j + 6] & 0xFF) >>> 6) | ((sk[j + 7] & 0xFF) << 25) >> 23);
            e[i + 7] = (short)(((sk[j + 7] & 0xFF) >>> 7) | (sk[j + 8] << 1)); // j+8 to be treated as signed.


            j += 9;
        }


        System.arraycopy(sk, 2 * PARAM_S_BITS * PARAM_N / 8, seed, 0, CRYPTO_SEEDBYTES * 2);


    }


    public static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {
        int maskq = ((1 << PARAM_Q_LOG) - 1);

        int j = 0;
        for (int i = 0; i < PARAM_N; i += 32)
        {
            publicKey[i + 0] = (at(publicKeyInput, j, 0)) & maskq;
            publicKey[i + 1] = ((at(publicKeyInput, j, 0) >>> 26) | (at(publicKeyInput, j, 1) << 6)) & maskq;
            publicKey[i + 2] = ((at(publicKeyInput, j, 1) >>> 20) | (at(publicKeyInput, j, 2) << 12)) & maskq;
            publicKey[i + 3] = ((at(publicKeyInput, j, 2) >>> 14) | (at(publicKeyInput, j, 3) << 18)) & maskq;
            publicKey[i + 4] = ((at(publicKeyInput, j, 3) >>> 8) | (at(publicKeyInput, j, 4) << 24)) & maskq;
            publicKey[i + 5] = ((at(publicKeyInput, j, 4) >>> 2)) & maskq;
            publicKey[i + 6] = ((at(publicKeyInput, j, 4) >>> 28) | (at(publicKeyInput, j, 5) << 4)) & maskq;
            publicKey[i + 7] = ((at(publicKeyInput, j, 5) >>> 22) | (at(publicKeyInput, j, 6) << 10)) & maskq;
            publicKey[i + 8] = ((at(publicKeyInput, j, 6) >>> 16) | (at(publicKeyInput, j, 7) << 16)) & maskq;
            publicKey[i + 9] = ((at(publicKeyInput, j, 7) >>> 10) | (at(publicKeyInput, j, 8) << 22)) & maskq;
            publicKey[i + 10] = ((at(publicKeyInput, j, 8) >>> 4)) & maskq;
            publicKey[i + 11] = ((at(publicKeyInput, j, 8) >>> 30) | (at(publicKeyInput, j, 9) << 2)) & maskq;
            publicKey[i + 12] = ((at(publicKeyInput, j, 9) >>> 24) | (at(publicKeyInput, j, 10) << 8)) & maskq;
            publicKey[i + 13] = ((at(publicKeyInput, j, 10) >>> 18) | (at(publicKeyInput, j, 11) << 14)) & maskq;
            publicKey[i + 14] = ((at(publicKeyInput, j, 11) >>> 12) | (at(publicKeyInput, j, 12) << 20)) & maskq;
            publicKey[i + 15] = ((at(publicKeyInput, j, 12) >>> 6)) & maskq;
            publicKey[i + 16] = (at(publicKeyInput, j, 13)) & maskq;
            publicKey[i + 17] = ((at(publicKeyInput, j, 13) >>> 26) | (at(publicKeyInput, j, 14) << 6)) & maskq;
            publicKey[i + 18] = ((at(publicKeyInput, j, 14) >>> 20) | (at(publicKeyInput, j, 15) << 12)) & maskq;
            publicKey[i + 19] = ((at(publicKeyInput, j, 15) >>> 14) | (at(publicKeyInput, j, 16) << 18)) & maskq;
            publicKey[i + 20] = ((at(publicKeyInput, j, 16) >>> 8) | (at(publicKeyInput, j, 17) << 24)) & maskq;
            publicKey[i + 21] = (at(publicKeyInput, j, 17) >>> 2) & maskq;
            publicKey[i + 22] = ((at(publicKeyInput, j, 17) >>> 28) | (at(publicKeyInput, j, 18) << 4)) & maskq;
            publicKey[i + 23] = ((at(publicKeyInput, j, 18) >>> 22) | (at(publicKeyInput, j, 19) << 10)) & maskq;
            publicKey[i + 24] = ((at(publicKeyInput, j, 19) >>> 16) | (at(publicKeyInput, j, 20) << 16)) & maskq;
            publicKey[i + 25] = ((at(publicKeyInput, j, 20) >>> 10) | (at(publicKeyInput, j, 21) << 22)) & maskq;
            publicKey[i + 26] = ((at(publicKeyInput, j, 21) >>> 4)) & maskq;
            publicKey[i + 27] = ((at(publicKeyInput, j, 21) >>> 30) | (at(publicKeyInput, j, 22) << 2)) & maskq;
            publicKey[i + 28] = ((at(publicKeyInput, j, 22) >>> 24) | (at(publicKeyInput, j, 23) << 8)) & maskq;
            publicKey[i + 29] = ((at(publicKeyInput, j, 23) >>> 18) | (at(publicKeyInput, j, 24) << 14)) & maskq;
            publicKey[i + 30] = ((at(publicKeyInput, j, 24) >>> 12) | (at(publicKeyInput, j, 25) << 20)) & maskq;
            publicKey[i + 31] = ((at(publicKeyInput, j, 25) >>> 6)) & maskq;

            j += PARAM_Q_LOG;
        }

        System.arraycopy(publicKeyInput, PARAM_N * PARAM_Q_LOG / 8, seedA, seedAOffset, CRYPTO_SEEDBYTES);

    }

    private static void at(byte[] bufer, int base, int offset, int v)
    {
        Pack.intToLittleEndian(v, bufer, base * 4 + offset * 4);
    }


    private static int at(byte[] bufer, int base, int offset)
    {
        return Pack.littleEndianToInt(bufer, base * 4 + offset * 4);
    }


    public static void encodePublicKey(byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset)
    {

        int[] t = T;
        int j = 0;
        for (int i = 0; i < (PARAM_N * PARAM_Q_LOG / 32); i += PARAM_Q_LOG)
        {
            at(publicKey, i, 0, (t[j + 0] | (t[j + 1] << 26)));
            at(publicKey, i, 1, ((t[j + 1] >> 6) | (t[j + 2] << 20)));
            at(publicKey, i, 2, ((t[j + 2] >> 12) | (t[j + 3] << 14)));
            at(publicKey, i, 3, ((t[j + 3] >> 18) | (t[j + 4] << 8)));

            at(publicKey, i, 4, ((t[j + 4] >> 24) | (t[j + 5] << 2) | (t[j + 6] << 28)));
            at(publicKey, i, 5, ((t[j + 6] >> 4) | (t[j + 7] << 22)));
            at(publicKey, i, 6, ((t[j + 7] >> 10) | (t[j + 8] << 16)));
            at(publicKey, i, 7, ((t[j + 8] >> 16) | (t[j + 9] << 10)));

            at(publicKey, i, 8, ((t[j + 9] >> 22) | (t[j + 10] << 4) | (t[j + 11] << 30)));
            at(publicKey, i, 9, ((t[j + 11] >> 2) | (t[j + 12] << 24)));
            at(publicKey, i, 10, ((t[j + 12] >> 8) | (t[j + 13] << 18)));
            at(publicKey, i, 11, ((t[j + 13] >> 14) | (t[j + 14] << 12)));

            at(publicKey, i, 12, ((t[j + 14] >> 20) | (t[j + 15] << 6)));
            at(publicKey, i, 13, (t[j + 16] | (t[j + 17] << 26)));
            at(publicKey, i, 14, ((t[j + 17] >> 6) | (t[j + 18] << 20)));
            at(publicKey, i, 15, ((t[j + 18] >> 12) | (t[j + 19] << 14)));

            at(publicKey, i, 16, ((t[j + 19] >> 18) | (t[j + 20] << 8)));
            at(publicKey, i, 17, ((t[j + 20] >> 24) | (t[j + 21] << 2) | (t[j + 22] << 28)));
            at(publicKey, i, 18, ((t[j + 22] >> 4) | (t[j + 23] << 22)));
            at(publicKey, i, 19, ((t[j + 23] >> 10) | (t[j + 24] << 16)));


            at(publicKey, i, 20, ((t[j + 24] >> 16) | (t[j + 25] << 10)));
            at(publicKey, i, 21, ((t[j + 25] >> 22) | (t[j + 26] << 4) | (t[j + 27] << 30)));
            at(publicKey, i, 22, ((t[j + 27] >> 2) | (t[j + 28] << 24)));
            at(publicKey, i, 23, ((t[j + 28] >> 8) | (t[j + 29] << 18)));

            at(publicKey, i, 24, ((t[j + 29] >> 14) | (t[j + 30] << 12)));
            at(publicKey, i, 25, (t[j + 30] >> 20 | (t[j + 31] << 6)));


            j += 32;
        }
        System.arraycopy(seedA, seedAOffset, publicKey, PARAM_N * PARAM_Q_LOG / 8, CRYPTO_SEEDBYTES);


    }

    public static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z)
    {

        int j = 0;

        for (int i = 0; i < (PARAM_N * (PARAM_B_BITS + 1) / 32); i += ((PARAM_B_BITS + 1) / 2))
        {
            at(signature, i, 0, ((Z[j + 0] & ((1 << 24) - 1)) | (Z[j + 1] << 24)));
            at(signature, i, 1, (((Z[j + 1] >>> 8) & ((1 << 16) - 1)) | (Z[j + 2] << 16)));
            at(signature, i, 2, (((Z[j + 2] >>> 16) & ((1 << 8) - 1)) | (Z[j + 3] << 8)));
            at(signature, i, 3, ((Z[j + 4] & ((1 << 24) - 1)) | (Z[j + 5] << 24)));
            at(signature, i, 4, (((Z[j + 5] >>> 8) & ((1 << 16) - 1)) | (Z[j + 6] << 16)));
            at(signature, i, 5, (((Z[j + 6] >>> 16) & ((1 << 8) - 1)) | (Z[j + 7] << 8)));
            at(signature, i, 6, ((Z[j + 8] & ((1 << 24) - 1)) | (Z[j + 9] << 24)));
            at(signature, i, 7, (((Z[j + 9] >>> 8) & ((1 << 16) - 1)) | (Z[j + 10] << 16)));
            at(signature, i, 8, (((Z[j + 10] >>> 16) & ((1 << 8) - 1)) | (Z[j + 11] << 8)));
            at(signature, i, 9, ((Z[j + 12] & ((1 << 24) - 1)) | (Z[j + 13] << 24)));
            at(signature, i, 10, (((Z[j + 13] >>> 8) & ((1 << 16) - 1)) | (Z[j + 14] << 16)));
            at(signature, i, 11, (((Z[j + 14] >>> 16) & ((1 << 8) - 1)) | (Z[j + 15] << 8)));

            j += 16;
        }
        System.arraycopy(C, cOffset, signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, CRYPTO_C_BYTES);

    }


    public static void decodeSignature(byte[] C, int[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;

        for (int i = 0; i < PARAM_N; i += 16)
        {
            Z[i] = (at(signature, j, 0) << 8) >> 8;
            Z[i + 1] = (at(signature, j, 0) >>> 24) | ((at(signature, j, 1) << 16) >> 8);
            Z[i + 2] = (at(signature, j, 1) >>> 16) | ((at(signature, j, 2) << 24) >> 8);
            Z[i + 3] = (at(signature, j, 2) >> 8);

            Z[i + 4] = (at(signature, j, 3) << 8) >> 8;
            Z[i + 5] = (at(signature, j, 3) >>> 24) | ((at(signature, j, 4) << 16) >> 8);
            Z[i + 6] = (at(signature, j, 4) >>> 16) | ((at(signature, j, 5) << 24) >> 8);
            Z[i + 7] = (at(signature, j, 5) >> 8);

            Z[i + 8] = (at(signature, j, 6) << 8) >> 8;
            Z[i + 9] = (at(signature, j, 6) >>> 24) | ((at(signature, j, 7) << 16) >> 8);
            Z[i + 10] = (at(signature, j, 7) >>> 16) | ((at(signature, j, 8) << 24) >> 8);
            Z[i + 11] = (at(signature, j, 8) >> 8);


            Z[i + 12] = (at(signature, j, 9) << 8) >> 8;
            Z[i + 13] = (at(signature, j, 9) >>> 24) | ((at(signature, j, 10) << 16) >> 8);
            Z[i + 14] = (at(signature, j, 10) >>> 16) | ((at(signature, j, 11) << 24) >> 8);
            Z[i + 15] = (at(signature, j, 11) >> 8);

            j += 12;

        }

        System.arraycopy(signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, C, 0, CRYPTO_C_BYTES);


    }


    private static final int SHAKE_RATE = HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE;
    private static final int NBLOCKS_SHAKE = SHAKE_RATE / (((PARAM_B_BITS + 1) + 7) / 8);
    private static final int BPLUS1BYTES = ((PARAM_B_BITS + 1) + 7) / 8;

    public static void sampleY(int[] Y, final byte[] seed, int seedOffset, int nonce) //   int n, int b, int bBit)
    {

        int i = 0;
        int position = 0;
        int numberOfByte = (PARAM_B_BITS + 1 + 7) / 8;
        int numberOfBlock = PARAM_N;
        byte[] buffer = new byte[PARAM_N * numberOfByte];
        int[] y = new int[4];

        short dualModeSampler = (short)(nonce << 8);

        HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
            buffer, 0, PARAM_N * numberOfByte, dualModeSampler++, seed, seedOffset, CRYPTO_RANDOMBYTES
        );


        while (i < PARAM_N)
        {

            if (position >= numberOfBlock * numberOfByte * 4)
            {
                numberOfBlock =
                    SHAKE_RATE /
                        ((PARAM_B_BITS + 1 + 7) / 8);

                HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
                    buffer, 0, SHAKE_RATE,
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


    private static class PolynomialLib
    {

        public static final int[] rev_tab = new int[]{
            0, 128, 64, 192, 32, 160, 96, 224,
            16, 144, 80, 208, 48, 176, 112, 240,
            8, 136, 72, 200, 40, 168, 104, 232,
            24, 152, 88, 216, 56, 184, 120, 248,
            4, 132, 68, 196, 36, 164, 100, 228,
            20, 148, 84, 212, 52, 180, 116, 244,
            12, 140, 76, 204, 44, 172, 108, 236,
            28, 156, 92, 220, 60, 188, 124, 252,
            2, 130, 66, 194, 34, 162, 98, 226,
            18, 146, 82, 210, 50, 178, 114, 242,
            10, 138, 74, 202, 42, 170, 106, 234,
            26, 154, 90, 218, 58, 186, 122, 250,
            6, 134, 70, 198, 38, 166, 102, 230,
            22, 150, 86, 214, 54, 182, 118, 246,
            14, 142, 78, 206, 46, 174, 110, 238,
            30, 158, 94, 222, 62, 190, 126, 254,
            1, 129, 65, 193, 33, 161, 97, 225,
            17, 145, 81, 209, 49, 177, 113, 241,
            9, 137, 73, 201, 41, 169, 105, 233,
            25, 153, 89, 217, 57, 185, 121, 249,
            5, 133, 69, 197, 37, 165, 101, 229,
            21, 149, 85, 213, 53, 181, 117, 245,
            13, 141, 77, 205, 45, 173, 109, 237,
            29, 157, 93, 221, 61, 189, 125, 253,
            3, 131, 67, 195, 35, 163, 99, 227,
            19, 147, 83, 211, 51, 179, 115, 243,
            11, 139, 75, 203, 43, 171, 107, 235,
            27, 155, 91, 219, 59, 187, 123, 251,
            7, 135, 71, 199, 39, 167, 103, 231,
            23, 151, 87, 215, 55, 183, 119, 247,
            15, 143, 79, 207, 47, 175, 111, 239,
            31, 159, 95, 223, 63, 191, 127, 255,


        };

        public static final int[] twiddle = new int[]{
            1, 20349512, 29475602, 17791697, 24835380, 17178032, 11708223, 8415094,
            21754869, 15322485, 20902680, 9686916, 31442912, 22429089, 33308953, 22563934,
            16978151, 32232983, 2663422, 10235835, 9175386, 24042369, 21625705, 6932474,
            7974996, 1837226, 3783875, 31812506, 8735396, 20168277, 4808176, 26159215,
            4070676, 33297705, 8758145, 27246749, 23805553, 13082561, 23554360, 22859934,
            23442917, 9325363, 14217049, 15164721, 27899289, 4869100, 21501702, 32076751,
            3531198, 17555098, 1599504, 19153009, 27454015, 15385892, 29250598, 21060944,
            7350388, 5605608, 15781, 22422281, 15236728, 2280712, 26009832, 18223844,
            27506971, 16752026, 14112245, 4231493, 25151509, 15700554, 14033313, 13976724,
            25808113, 27391270, 18981045, 29650081, 8491986, 18505659, 32331817, 31126270,
            23220214, 14102887, 19452799, 26950707, 1778108, 6343125, 3172265, 15349951,
            21664476, 6658688, 30118507, 16126790, 26527504, 17484839, 19611677, 33156191,
            16166358, 33077723, 2847371, 16027071, 12975937, 31908284, 10863968, 9730603,
            13079905, 14374018, 8478458, 27755269, 1138528, 3754664, 32576304, 31481843,
            22303942, 5365218, 30527813, 19186493, 14087250, 7233695, 27051869, 10586616,
            32337348, 8363900, 29158115, 8357758, 3732990, 17056436, 13705304, 29591261,
            33564672, 13215161, 4089071, 15772976, 8729293, 16386641, 21856450, 25149579,
            11809804, 18242188, 12661993, 23877757, 2121761, 11135584, 255720, 11000739,
            16586522, 1331690, 30901251, 23328838, 24389287, 9522304, 11938968, 26632199,
            25589677, 31727447, 29780798, 1752167, 24829277, 13396396, 28756497, 7405458,
            29493997, 266968, 24806528, 6317924, 9759120, 20482112, 10010313, 10704739,
            10121756, 24239310, 19347624, 18399952, 5665384, 28695573, 12062971, 1487922,
            30033475, 16009575, 31965169, 14411664, 6110658, 18178781, 4314075, 12503729,
            26214285, 27959065, 33548892, 11142392, 18327945, 31283961, 7554841, 15340829,
            6057702, 16812647, 19452428, 29333180, 8413164, 17864119, 19531360, 19587949,
            7756560, 6173403, 14583628, 3914592, 25072687, 15059014, 1232856, 2438403,
            10344459, 19461786, 14111874, 6613966, 31786565, 27221548, 30392408, 18214722,
            11900197, 26905985, 3446166, 17437883, 7037169, 16079834, 13952996, 408482,
            17398315, 486950, 30717302, 17537602, 20588736, 1656389, 22700705, 23834070,
            20484768, 19190655, 25086215, 5809404, 32426145, 29810009, 988369, 2082830,
            11260731, 28199455, 3036860, 14378180, 19477423, 26330978, 6512804, 22978057,
            1227325, 25200773, 4406558, 25206915, 29831683, 16508237, 19859369, 3973412,
        };

        public static final int[] psi_phi_tab = new int[]{
            1, 97738, 20349512, 12340568, 29475602, 30504686, 17791697, 6302602,
            24835380, 30348426, 17178032, 7983483, 11708223, 17902985, 8415094, 5710180,
            21754869, 22481118, 15322485, 459016, 20902680, 5186349, 9686916, 21064697,
            31442912, 19437849, 22429089, 31942379, 33308953, 12120025, 22563934, 20506500,
            16978151, 6653991, 32232983, 7084674, 2663422, 23500321, 10235835, 1397792,
            9175386, 2943654, 24042369, 23869265, 21625705, 18567134, 6932474, 29654634,
            7974996, 21322642, 1837226, 29358911, 3783875, 12807636, 31812506, 27228073,
            8735396, 29111820, 20168277, 20941482, 4808176, 2519215, 26159215, 27519241,
            4070676, 17661819, 33297705, 20397210, 8758145, 3720491, 27246749, 21597942,
            23805553, 4006754, 13082561, 17129083, 23554360, 22245956, 22859934, 18206374,
            23442917, 4984074, 9325363, 27198252, 14217049, 2037635, 15164721, 20670764,
            27899289, 26673762, 4869100, 16162006, 21501702, 15608873, 32076751, 9207673,
            3531198, 20262338, 17555098, 7649237, 1599504, 21639791, 19153009, 7851086,
            27454015, 6299758, 15385892, 21832550, 29250598, 23924549, 21060944, 278928,
            7350388, 27526125, 5605608, 4757325, 15781, 31993093, 22422281, 4270862,
            15236728, 9909600, 2280712, 9236063, 26009832, 27756342, 18223844, 19127454,
            27506971, 13153644, 16752026, 24768248, 14112245, 29494221, 4231493, 27326801,
            25151509, 15100795, 15700554, 31026638, 14033313, 1148522, 13976724, 8423885,
            25808113, 14607771, 27391270, 16064107, 18981045, 16334827, 29650081, 32879304,
            8491986, 2493724, 18505659, 6565391, 32331817, 296342, 31126270, 18110559,
            23220214, 21911037, 14102887, 21108188, 19452799, 6766577, 26950707, 19793072,
            1778108, 24407583, 6343125, 24840940, 3172265, 13952069, 15349951, 33321757,
            21664476, 15159083, 6658688, 21402947, 30118507, 121047, 16126790, 3156940,
            26527504, 8455394, 17484839, 21433060, 19611677, 28305615, 33156191, 17747154,
            16166358, 10516729, 33077723, 1187214, 2847371, 11642955, 16027071, 24141161,
            12975937, 961201, 31908284, 23834470, 10863968, 4074029, 9730603, 28231232,
            13079905, 26054339, 14374018, 4818196, 8478458, 22880980, 27755269, 14044989,
            1138528, 10558669, 3754664, 10780123, 32576304, 31484245, 31481843, 31667878,
            22303942, 17865865, 5365218, 4790605, 30527813, 29345332, 19186493, 24736997,
            14087250, 3189367, 7233695, 609838, 27051869, 5586093, 10586616, 16500037,
            32337348, 3850452, 8363900, 3247285, 29158115, 13718132, 8357758, 7104603,
            3732990, 6981110, 17056436, 5327877, 13705304, 30032268, 29591261, 23489227,
            6766491, 18545239, 15098036, 14558796, 6856286, 984623, 5165283, 31747934,
            26248461, 23429809, 32856617, 6378398, 15192095, 10976936, 2562996, 8948449,
            8824001, 29501676, 28010150, 20616801, 23317256, 7799574, 27475109, 20540077,
            9389023, 6170154, 2031861, 21424950, 32508649, 31260436, 7439924, 18216040,
            28367581, 14383286, 4407809, 7858087, 6859620, 24761058, 16234158, 24912548,
            20542985, 25093743, 8032551, 7768168, 12300724, 28704798, 12789546, 9095082,
            8324784, 6500399, 23866918, 27187330, 20792149, 9932177, 27207793, 6924463,
            18662995, 11651125, 8994379, 264159, 7138805, 23665439, 3931206, 13400197,
            14913926, 10680344, 14131572, 5290186, 21976376, 22918199, 6916534, 15685872,
            5753588, 1652502, 32598673, 2517149, 25620545, 8398045, 17608668, 7384909,
            11507650, 16068143, 10675537, 14210428, 26207797, 9643191, 10184118, 14947269,
            13785197, 18045493, 7522703, 19783749, 30377578, 13439003, 14926705, 17781345,
            1459016, 18574904, 27933928, 22188371, 33482268, 1421630, 23091393, 17956514,
            4143508, 20405159, 13690028, 13832192, 12882602, 8176027, 792142, 22238858,
            409070, 6158117, 323110, 29332560, 12769658, 12032772, 20057162, 2172991,
            20108287, 31456637, 18304979, 27837256, 5333548, 30942734, 3204373, 30609184,
            27556629, 33314336, 1208911, 8894358, 25296177, 23934446, 14998413, 11361192,
            106837, 3421403, 29813988, 8907976, 13705341, 83901, 10535726, 10184821,
            16527737, 20941435, 214490, 19467668, 16751960, 18317540, 13631373, 20568885,
            5592795, 27897905, 25663062, 1905139, 21234451, 8346229, 21482083, 11273412,
            13221485, 1590430, 7446677, 6947294, 1286182, 9155931, 14637225, 19604444,
            26224794, 26227000, 6884317, 21939988, 24283193, 32689604, 28857555, 6673727,
            14439117, 23741061, 10846182, 11068957, 1179130, 18285531, 6650320, 9083515,
            18988220, 12746844, 31071131, 32847330, 4931763, 31947814, 27480215, 16120210,
            31334360, 16219141, 461941, 4704273, 17343720, 23824841, 9555610, 9183955,
            1343751, 30534462, 7911834, 23894918, 11548144, 13239301, 31092315, 22319396,
            17898632, 19302329, 1456491, 6739165, 32930491, 10270715, 20467259, 8014015,
            8588942, 13541466, 27182845, 18777968, 4716744, 27906090, 20096440, 14753433,
            32682474, 3279075, 14734546, 32761883, 11116454, 11516042, 30733287, 6724017,
            29240879, 13819771, 7207132, 22439838, 8458605, 29239500, 13297761, 5296712,
            22085777, 8422450, 19812775, 14323561, 7258861, 10063217, 13090227, 27965785,
            14313248, 6227057, 25446230, 22052459, 7761047, 21166559, 18523187, 7918732,
            31401819, 30850975, 30195595, 16061239, 7185845, 22900758, 14066399, 12699382,
            24155049, 27774361, 437197, 2931657, 26243138, 6640530, 25604012, 3599995,
            31408924, 20421332, 16867071, 24871003, 21343208, 31601227, 19515066, 17412810,
            30043988, 317066, 9203529, 1281002, 6343186, 30802958, 2599596, 28303911,
            869331, 14485915, 32888457, 30406402, 11206583, 26599918, 3908923, 17208088,
            25470260, 21169489, 2813470, 21129644, 1944928, 16629665, 14472418, 22740918,
            32762097, 32032386, 2904120, 20005672, 4344321, 12132448, 28434880, 13377040,
            428151, 25039880, 13224318, 9964800, 27070632, 26951845, 30324897, 33463067,
            4375980, 18469874, 33301726, 10625632, 3473123, 16557725, 31782028, 2060533,
            4336354, 5441281, 21243366, 6999001, 20323998, 2439038, 10388398, 9885474,
            27345507, 7381522, 16115774, 544668, 1189606, 1683956, 18899809, 31318160,
            10403172, 10585747, 32259734, 3629418, 20592220, 3911261, 10766821, 7923002,
            7798693, 8497277, 16155387, 12302667, 17221694, 12706568, 21642184, 18087332,
            1892779, 21520999, 22037371, 9935715, 3793434, 7274334, 11953006, 10891990,
            24149752, 13526270, 18801809, 18925965, 3273467, 3654610, 32586787, 15566836,
            18354551, 6027807, 18660070, 27849532, 30401681, 19690907, 18647892, 12359723,
            22025304, 5294824, 5379798, 20094379, 14703453, 14614819, 11390561, 17576954,
            29236566, 28616526, 11381771, 31141432, 23168503, 2482269, 6551078, 9559416,
            11963380, 17885812, 8194070, 18915880, 24525927, 26801485, 2201318, 2864754,
            32388959, 13505420, 28409562, 22632158, 9213885, 6515540, 26872364, 15450382,
            14797646, 24129851, 15193366, 943242, 21994538, 19108086, 14139075, 195594,
            18667435, 9267096, 4727943, 14839743, 10151658, 31015724, 21390317, 4015795,
            24050321, 29094362, 25656596, 7660018, 14808019, 31025935, 12452845, 27556957,
            31807727, 30043593, 28839902, 26667809, 27198900, 10421927, 31169595, 23460611,
            22561923, 25343420, 9445906, 27629763, 32009879, 18383372, 3502173, 2849420,
            10520079, 24853293, 2201551, 25637708, 7641689, 2295886, 15466863, 14513320,
            26224507, 31740867, 6827475, 4487637, 23083015, 4659702, 24470812, 10319295,
            2395733, 6993106, 14757929, 2207100, 30951102, 15523805, 8174798, 14930832,
            18369995, 5083194, 30490099, 1803757, 13939070, 20311263, 33203182, 12193311,
            2550980, 9292196, 7730614, 397229, 23606014, 2538985, 11688441, 31200903,
            29056672, 460733, 20895461, 4473860, 19133509, 15146447, 13534221, 23929168,
            2607344, 13590456, 15619226, 3453402, 2252988, 18286264, 11162928, 22560999,
            3725492, 12564392, 21418918, 13552474, 29013213, 15578462, 13457657, 25639015,
            1126563, 15887054, 33546199, 6880530, 21017585, 25170457, 20983404, 7290506,
            15032311, 1581289, 20269790, 7475868, 7020047, 29872893, 26605783, 6542852,
            11118780, 3901919, 3944596, 13089770, 16864192, 12000685, 5452545, 14529989,
            10750252, 33171057, 27439323, 13614001, 897999, 30571040, 25117060, 4591733,
            27121944, 7383151, 7507611, 21567465, 32300424, 19957224, 1752590, 14115101,
            6551892, 21988802, 29082359, 27270937, 2592903, 11872264, 7028549, 21724544,
            12267492, 2884190, 18838366, 514020, 26535952, 28593866, 11907109, 22677186,
            13188386, 22333649, 1242080, 28557472, 12685675, 27047203, 19446007, 14223541,
            32388617, 13643697, 16763769, 31306700, 31524574, 12526231, 17317803, 8099570,
            12959955, 16452116, 14124197, 22895242, 11978359, 5057702, 22738805, 27629741,
            29859643, 7034857, 527061, 25679636, 10710447, 2647362, 31367672, 16294116,
            11269777, 27155258, 7653602, 25449798, 1570240, 14432164, 15462207, 29350614,
            31968514, 3211762, 14372460, 20365757, 22554747, 28833665, 21240017, 15321169,
            6094500, 25553942, 10300593, 20556672, 20246829, 12146741, 15687848, 31060511,
            1809960, 16043770, 11599046, 20727373, 22578686, 19056537, 10543863, 33491448,
            25974972, 10641635, 23599379, 25340815, 23355800, 15769670, 6222300, 30411986,
            19940807, 8292148, 5366966, 7813264, 22921409, 18573457, 20765734, 12662728,
            33086408, 10924919, 20355746, 17475146, 13869470, 31375082, 2109890, 28642581,
            7030213, 16537211, 7100403, 29574139, 28252841, 10525948, 27878174, 10380945,
            19866966, 7625185, 332238, 15238853, 16214812, 13694888, 18933450, 29984264,
            3265856, 31758171, 19852177, 5458842, 25822061, 1705802, 5945085, 22663427,
            10998164, 29900207, 11047675, 2128740, 24946866, 18248369, 33060121, 26165934,
            12927403, 23528675, 29195901, 14732170, 1924433, 27369735, 25850676, 12610813,
            27283761, 14092114, 8681577, 5039386, 11497266, 8096941, 24524137, 19673830,
            27809716, 32367541, 1162662, 19840451, 581936, 18704706, 27075410, 24038587,
            23435552, 23566510, 1434428, 32049416, 22713283, 16946307, 15799708, 21949793,
            9228766, 17673779, 27480630, 23116807, 18084244, 2159892, 15295799, 10267242,
            16669915, 21360177, 11883699, 17028370, 14516355, 20777280, 33511467, 2276287,
            13086162, 33436891, 30465913, 21004272, 33006710, 8405931, 16383057, 10934928,
            25239871, 25304990, 12617942, 19199830, 19246456, 11582916, 21753064, 13887393,
            4205587, 12676648, 17447775, 23856512, 17065892, 23292234, 12420467, 18075255,
            28949306, 12465274, 449658, 12516647, 20407655, 22691365, 22863895, 2570516,
            5515403, 15810034, 24252191, 23436698, 1315566, 28092118, 10048338, 2127464,
            927197, 31327959, 28326990, 7731542, 23968747, 11042251, 9032596, 9838602,
            10965499, 25932372, 9022287, 9197750, 7052541, 17127530, 6025938, 3811113,
            23386113, 24810440, 9419162, 31769185, 22268973, 23662389, 7912363, 8468974,
            2179959, 29853211, 16112828, 14690577, 31597905, 30476160, 15585368, 17142825,
            24083036, 4384424, 4652721, 13455294, 29636832, 13406116, 22825707, 29395148,
            21225116, 2208170, 1272070, 6028868, 21666069, 3032352, 33521859, 11029393,
            27774966, 26004014, 29716099, 7364699, 16538377, 20368892, 26881320, 18110412,
            8852728, 17788670, 12531733, 18037511, 32930139, 9431612, 6714384, 27541569,
            4660995, 16587354, 7534679, 15530482, 23042637, 18826152, 15070316, 23999949,
            6278084, 11586879, 6312682, 3094230, 6148010, 19425334, 7566247, 12973750,
            22160906, 717265, 21009346, 25459227, 16895671, 745271, 5956588, 5744759,
            11405198, 4887121, 32135508, 12440256, 5461503, 17385495, 11939685, 17946339,
            16599548, 24588296, 13852321, 33499770, 233783, 25505214, 13906895, 30670375,
            166120, 24499501, 28456918, 19188012, 5377654, 11932145, 19424625, 5399351,
            17979132, 33077847, 13306726, 8836384, 31463102, 12452362, 13914176, 3877947,
            10496370, 23545488, 27795918, 26365537, 20650404, 18269316, 32932954, 16046698,
            29258526, 26803934, 6608969, 28844910, 12669618, 1643095, 19423478, 27552557,
            4536603, 9173684, 4416943, 27915481, 31707827, 33337236, 24140693, 799226,
            9756717, 29646216, 24333337, 33221618, 1598737, 13804091, 18650250, 7873216,
            8692210, 3782677, 29976204, 21049728, 11683729, 7000196, 2862216, 19282626,
            22475711, 23887887, 29210399, 22021428, 29238412, 7652836, 17711836, 21416993,
            26794862, 26176004, 23773546, 30785850, 8731542, 21640971, 225157, 21534051,
            22256173, 14508890, 29585916, 4549712, 14963552, 27713420, 18697533, 30858869,
            29751888, 14583989, 18948591, 32989710, 25093581, 25763668, 485178, 27009088,
            19840840, 5037345, 13402046, 27808123, 10929599, 7864164, 30214005, 2925477,
            26386412, 13486101, 19830828, 33424679, 11653012, 25602620, 1807391, 33472232,
            27463252, 2859493, 21659436, 26029658, 18758896, 20279296, 30327125, 16270620,
            30780166, 23788191, 18877921, 6603215, 3495226, 28721667, 16862891, 19102239,
            13264430, 3364715, 27413289, 20018057, 6501223, 3709011, 12848718, 19324262,
            30569646, 23128980, 33085363, 9482728, 1553715, 10416018, 24235194, 6852889,
            7949577, 20706222, 2767301, 6330104, 27652016, 25269848, 1505792, 25572064,
            2580960, 19350885, 14603926, 20800063, 11443230, 29944707, 30545858, 14099873,
            28607913, 8681202, 1952309, 33175710, 12308815, 13950804, 25970073, 1728595,
            18418901, 18874256, 17604848, 3237152, 12154478, 33463948, 23353812, 22854564,
            30388082, 33138765, 26363089, 16340491, 12638672, 31428190, 23819952, 1619950,
            6110559, 17588853, 17457473, 31908792, 6356028, 10496780, 30053395, 13492261,
            17732794, 22364944, 5567547, 10430010, 15633697, 8103734, 17164911, 1020759,
            12734986, 13292809, 24768231, 12450699, 19199247, 29394548, 29711662, 10041942,
            14724003, 9250339, 11601254, 1580166, 11204035, 12516205, 10772132, 23539425,
            5809865, 31012229, 15442737, 6013442, 24369966, 21846809, 13180474, 21018072,
            5639517, 29617213, 9070655, 3970441, 21777905, 25140595, 22457799, 18567827,
            7535562, 1139117, 997005, 7028971, 29405307, 7205268, 8079571, 5048727,
            18221753, 16145334, 3118070, 20259493, 8007872, 12348522, 1331502, 8105255,
            31565717, 6000005, 20086707, 3280323, 2452878, 20495398, 5960411, 10185730,
            4677560, 24513020, 7190020, 28180832, 21091636, 12797727, 3137508, 6904376,
            2150823, 1591375, 32679741, 4678505, 16181411, 4921231, 9511388, 16856936,
            7671890, 390000, 21916145, 9878496, 16623203, 20618249, 30583188, 4110056,
            6646864, 6947717, 9064683, 24443219, 32173174, 1725734, 7307867, 63406,
            21275796, 21563079, 6397632, 15463099, 15838891, 25245125, 1785674, 25470485,
            9595866, 16658142, 11889585, 21714797, 32990723, 23408156, 31110102, 15422206,
            13234944, 8023925, 3797005, 20650002, 12543313, 8644669, 22709966, 28396091,
            15025807, 3622124, 12549381, 31119412, 19116815, 28177252, 6836326, 30449850,
            28578409, 11581128, 14820885, 13065469, 24824837, 6836882, 17662832, 31612280,
            25743644, 23695173, 23511020, 15429834, 20357602, 31053509, 22306617, 10797631,
            31974885, 21736446, 781613, 95646, 17269654, 1166828, 24240883, 25849603,
            8431958, 9294835, 30708485, 32847270, 32632156, 19305322, 25468941, 26511759,
            13545542, 22786857, 25081897, 24991758, 8930502, 83111, 452052, 11548708,
            1234187, 29098917, 947764, 27625025, 5267984, 136372, 3551355, 10051497,
            8799749, 8686810, 13032245, 33350806, 7858433, 7112295, 17110880, 23357215,
            19810248, 2292346, 5121073, 7029098, 8253360, 7113471, 31356749, 22771478,
            32379480, 26857762, 31561045, 19273491, 2320579, 12254841, 8293653, 18203964,
            22847048, 647407, 6856761, 13845500, 4557659, 19699959, 30690770, 13216923,
        };

        public static final long[] iph_ips_tab = new long[]{
            32441320, 27327219, 20183796, 12146787, 13811923, 1945586, 4967858, 32838745,
            29529542, 2712592, 2191014, 24939490, 31389739, 5120292, 21067175, 4525392,
            16852096, 13822617, 6164780, 3759768, 14556017, 8370884, 19210708, 24662185,
            16781902, 19190876, 18915482, 25927322, 14007467, 15782456, 26793382, 12471725,
            10879851, 15782424, 6461167, 19581233, 32101583, 18011403, 9129866, 28352417,
            20544392, 3208391, 1524451, 27283289, 23183867, 30021900, 4743552, 26410705,
            12139639, 24312173, 29274641, 29535687, 23071250, 17290483, 15224784, 26061216,
            24436975, 31741734, 1256536, 2300205, 23676755, 1691560, 20297204, 6163816,
            24784994, 10559571, 26729110, 6642602, 25340644, 12496436, 2481643, 26097831,
            27571322, 15364659, 15580542, 8020268, 21339876, 18157931, 1939449, 31648095,
            15961899, 374142, 32657375, 7380661, 12072135, 12374388, 23372936, 21505559,
            9265894, 24828296, 23902609, 30901736, 12629051, 15250149, 28328784, 15319336,
            13517649, 29103510, 25638271, 2247912, 13051158, 18948387, 6638058, 24727992,
            15106382, 28711690, 6966119, 3750504, 18979886, 19128397, 20566963, 15440482,
            600447, 7533496, 12793651, 3168819, 10725906, 8351957, 2151579, 4760781,
            19781083, 31686740, 31365769, 28066580, 1358836, 16447521, 1969652, 9453542,
            31218560, 21071563, 10908099, 32118665, 7136831, 15184844, 19612573, 20135639,
            19806653, 18411012, 31245438, 29127387, 5486349, 21640338, 8262094, 32966529,
            3029599, 8383129, 9309030, 10316275, 6217630, 21108396, 28785929, 9263908,
            19537648, 20404532, 30562063, 10412992, 23541876, 2090950, 17593847, 9443056,
            8117735, 9632524, 25508261, 22006623, 23639181, 2830323, 18980220, 27860061,
            5099651, 20500197, 21389112, 6950247, 21938437, 21005189, 5800147, 18506338,
            30092939, 21264894, 14725843, 21163086, 23691028, 17473186, 8509310, 10041535,
            23895246, 23320168, 24791351, 18773709, 11510425, 7374950, 1049551, 9937404,
            22176454, 19679267, 27177703, 29453246, 18190295, 2875598, 7327127, 17441081,
            32633854, 22971348, 31062788, 32806731, 30708828, 8011494, 28725354, 29136290,
            22375831, 19762032, 7165208, 22231372, 29388290, 1514073, 18261096, 4532575,
            23345726, 24868963, 4537107, 3747045, 8142746, 3047546, 19519040, 28768742,
            2721513, 32615159, 27453254, 26746797, 16207047, 18653426, 26287218, 838201,
            7974443, 29668714, 24904056, 11898203, 15042719, 16494022, 24578364, 3560089,
            26073803, 3176510, 151135, 24011219, 16057977, 23905610, 25544809, 21379548,
            9560886, 15435905, 3144807, 13279538, 23148352, 33536063, 28466337, 4230131,
            28857636, 9683905, 10482835, 5982736, 4388902, 31009712, 20805071, 24733975,
            14347092, 4282529, 29165917, 3412811, 28731145, 7077729, 7039045, 1468857,
            20201389, 14430152, 2835380, 19337028, 16165418, 12065700, 23827614, 30747542,
            13763005, 28501163, 6620985, 25587559, 11247439, 2113833, 18285828, 6330695,
            16408766, 19465604, 14591206, 9599279, 9177858, 2912938, 31625783, 28790501,
            23471664, 27489219, 25952479, 1591993, 19311946, 12251863, 4460053, 1217451,
            17801604, 26610706, 22706857, 33487637, 11005069, 14050928, 20017104, 25009729,
            9511128, 3349765, 23599154, 26064049, 4638770, 10687802, 6287347, 9500634,
            339391, 13937492, 12404971, 3475141, 2683822, 29690295, 31152488, 4363060,
            22502641, 14226874, 2669852, 12383564, 4991317, 30299193, 32704729, 31788523,
            5467145, 33115199, 28924448, 30865042, 19086622, 19809733, 3462167, 18248753,
            416062, 17508663, 24904275, 3152459, 12538449, 18103238, 10372685, 11518581,
            16393022, 18288378, 21743150, 12078120, 31765990, 6890599, 17205494, 15082266,
            23923801, 11303742, 3411598, 24756119, 20641885, 18509924, 11489474, 4934301,
            28048452, 12624214, 16223043, 7927896, 13494908, 15843922, 22375695, 25652969,
            3815944, 11729714, 13687946, 21247212, 21973955, 14152691, 27562271, 17719454,
            33557986, 23355982, 13014972, 8337557, 15810558, 15395446, 3628678, 27787100,
            23952091, 14467966, 3147201, 897375, 3129548, 31816037, 10654082, 3868333,
            16222610, 8667268, 4805835, 30287515, 15825206, 16661273, 5024672, 13729774,
            18968312, 9590395, 15898485, 13156726, 32709018, 14077593, 30142002, 12368048,
            18618015, 3578229, 1455085, 17517259, 3017078, 23329570, 1062764, 19312284,
            27720638, 4886389, 20406786, 17333726, 4715949, 30755245, 23399567, 24712023,
            29351570, 14527432, 20205987, 22082120, 13401644, 16033486, 68847, 16698544,
            5411014, 19431150, 1022888, 19963398, 9200286, 17637190, 33103304, 7376888,
            26188886, 24099743, 20784052, 8456458, 6106688, 1718510, 15362334, 18310346,
            122443, 31843136, 30115054, 3889137, 14418309, 1740917, 19890258, 3475561,
            5222344, 20289685, 4352303, 21259136, 62719, 33363776, 24294876, 22067395,
            8313954, 10766825, 10648372, 2921195, 17759038, 11003191, 22838912, 9306774,
            3393720, 3967849, 6830217, 1323247, 12801486, 177333, 27957055, 27454580,
            28048339, 15297698, 3568236, 11542207, 18219302, 13729909, 3001929, 8966247,
            22867738, 8997701, 18303756, 27421170, 27502996, 11884493, 32872127, 16479781,
            29128953, 8238475, 974352, 1837279, 18286512, 17177794, 15484061, 18974168,
            16530810, 25401873, 3289830, 13775087, 20970764, 15902379, 9840713, 31861093,
            7746733, 29518296, 8582924, 25344098, 6521019, 32260107, 9483729, 15640236,
            6318305, 8651713, 28266215, 16426848, 14635132, 33426770, 8973770, 31416362,
            28417207, 9365555, 33094634, 22103887, 14061344, 9130169, 26827312, 16160000,
            33022243, 10836791, 24040862, 24043401, 29319969, 14846464, 21855068, 30654113,
            29737629, 21874795, 18983849, 6160025, 25367082, 17892856, 27686282, 5336262,
            17389205, 27885114, 18907329, 13570915, 8688876, 14573925, 29340477, 17966044,
            13562320, 7086846, 31934899, 10783894, 3051694, 24451163, 30227275, 20940025,
            8005556, 12974292, 30980953, 24875566, 7525159, 26176868, 5165226, 30848315,
            15324513, 14599749, 24312885, 20152171, 5607826, 20793135, 26433878, 14584409,
            32290410, 21458259, 25462021, 11044823, 26088303, 23686614, 17646267, 24192721,
            25578810, 2001683, 11733473, 26338316, 21023435, 8673842, 17688010, 4617736,
            11101960, 5575109, 21079886, 24292003, 8059163, 4690098, 32263179, 14625335,
            4420928, 16477086, 29622440, 7023822, 13510009, 16491259, 11234983, 670804,
            33358631, 9980318, 19748512, 26142995, 5177932, 237696, 20229193, 21369878,
            18243785, 24092450, 13625571, 30240214, 21945887, 32469061, 3677961, 20219956,
            29313405, 2024730, 20129621, 3572063, 4464772, 19670157, 5680625, 14387420,
            26502152, 31176151, 9769439, 30701724, 25490619, 29496499, 7741901, 13739074,
            8049096, 7617022, 7450118, 32457580, 24910266, 15867391, 19896584, 1432930,
            1086579, 12211497, 2149558, 16040926, 11472278, 8406911, 5365255, 21445964,
            1496821, 28108171, 27855690, 2176161, 5652286, 20996437, 33457399, 16205742,
            27548212, 9944200, 22974550, 3425454, 1096215, 30174837, 26220370, 19717084,
            24151189, 22933829, 15751640, 15074696, 11734637, 6521910, 14150129, 25503156,
            7933829, 12433413, 27696872, 2213935, 5722343, 11443669, 13384021, 13568798,
            26101722, 27593644, 2596498, 32217140, 14947801, 33538383, 8923976, 25825569,
            6522741, 29242178, 4505901, 23235833, 1749936, 30767921, 26172298, 11108362,
            30843568, 16841376, 16159211, 4758177, 30893985, 22841176, 29703551, 3866124,
            12940595, 25344486, 22291999, 29969005, 3905276, 1200618, 20111755, 2995126,
            4769375, 11307667, 10352354, 12825274, 23121561, 29362543, 10363528, 19945636,
            15964870, 28400565, 22899531, 29977940, 7562300, 25777477, 31357810, 23595663,
            28459367, 29232100, 30861611, 21844586, 14290399, 627565, 17039904, 21179937,
            1350867, 11916163, 22900736, 20478744, 29340194, 19612031, 30285606, 14356421,
            31361671, 23436662, 30747538, 7025894, 12607515, 26056038, 13279429, 32558947,
            3210231, 12645595, 21262655, 11262505, 19331963, 2334388, 25537720, 22166998,
            2803865, 13462918, 23881201, 22342466, 2706337, 14732178, 9105450, 21751298,
            7621970, 17217521, 24001778, 16055573, 2662659, 5829493, 21340197, 30167489,
            1947127, 24351218, 13531478, 1923948, 28583118, 15277442, 22110573, 14194589,
            25706458, 14957350, 14054746, 22954674, 24264549, 3234872, 3824300, 21956606,
            20057021, 1111152, 23118007, 1168877, 19584613, 18965968, 22274763, 33199851,
            23673637, 2984860, 16562925, 1337770, 30094137, 8366922, 8689853, 23835478,
            17861933, 11964410, 15784839, 4275332, 15874735, 3868043, 14469821, 31141343,
            20913248, 10629588, 16934578, 29020782, 15666192, 22227338, 31858129, 16683759,
            33525351, 10712480, 1046151, 22952137, 5574200, 25655201, 3880506, 19311626,
            10317751, 8425787, 12046733, 6526721, 19733023, 9724678, 18609746, 30798314,
            5126124, 9325824, 17839806, 9128834, 1976102, 14873314, 16315788, 14670846,
            21045981, 3972494, 18122725, 30816510, 7697614, 11224934, 17132391, 12937640,
            24266507, 28495089, 30325533, 24082958, 3245516, 7741289, 23465954, 26542081,
            27488907, 3927916, 3780350, 24835795, 25593240, 22088700, 19607149, 14204179,
            16540031, 24074575, 23063639, 28348782, 15356425, 26229834, 16502035, 2523924,
            23200441, 2651056, 6185614, 2136790, 26138007, 28733438, 17580383, 22046378,
            12187329, 10473245, 15149163, 28836350, 22000819, 15410963, 77426, 24916803,
            25169467, 15033926, 269391, 27191241, 24010122, 6071132, 28480136, 10433919,
            19124532, 13988853, 30823336, 8677033, 13479462, 29893707, 5276187, 6718964,
            3548917, 5539660, 18280025, 8177923, 17629281, 28934592, 31759981, 14205677,
            5455289, 1733957, 11387995, 5818593, 22588853, 18404859, 30977231, 15805295,
            20506488, 2352601, 31568427, 24484766, 28582662, 19234267, 22727043, 14522213,
            32295904, 27812806, 4785426, 17696899, 14709666, 20725232, 22153899, 830947,
            24546953, 5027500, 10683685, 11611993, 30523854, 24496088, 16458747, 29543111,
            7526237, 12553604, 25789891, 12408183, 9462921, 10707426, 30915681, 13002343,
            9205366, 14776545, 12103118, 28458906, 16376368, 11611021, 4510185, 22277019,
            6557733, 25923418, 17263039, 10460934, 31364865, 15889779, 814399, 11797336,
            6200131, 26106111, 10487124, 21836479, 29063759, 10262561, 10498638, 31011835,
            30280228, 1990055, 28720828, 8493628, 29377847, 8881350, 9855408, 3202787,
            28069726, 13660640, 30743317, 5009019, 23171963, 18489345, 31436034, 33196854,
            31019662, 13814520, 20998581, 19564211, 9774128, 15408434, 28425972, 11995082,
            19920240, 3440533, 15036451, 32313080, 24219314, 15129729, 5356395, 1459911,
            6408478, 13275107, 19862216, 15236143, 17517400, 13938698, 12981221, 29226447,
            50781, 14912787, 16585369, 9445793, 28016904, 9907116, 27074922, 2329316,
            8307914, 7825134, 9981087, 14327023, 27311580, 2858864, 166242, 17981886,
            28757737, 20117875, 6420345, 21227563, 13976855, 12009701, 31080190, 23866271,
            32798072, 22007041, 6026811, 19047562, 18679898, 5037399, 26880156, 6620625,
            23411683, 24100058, 5905607, 18188337, 11180054, 14390567, 15314729, 15880686,
            16341211, 30714841, 7433527, 22804534, 23049546, 13655094, 3935673, 20456228,
            658192, 4120984, 9364963, 9377723, 19371093, 3887310, 19271, 25851234,
            10603539, 3819911, 5498453, 817040, 4264533, 27803247, 24208622, 31061427,
            14511309, 26807449, 156528, 19685910, 30407519, 9431511, 22250283, 19498975,
            24970231, 25872781, 9933537, 29012125, 27115297, 28189479, 29245147, 12381432,
            5531165, 17282405, 20104021, 16666468, 19641435, 13331219, 9936156, 1207548,
            28432695, 15708426, 15689408, 21575537, 9305044, 26502100, 10723054, 4540053,
            14840029, 33308294, 4464046, 21995075, 7545391, 776538, 7844975, 5712785,
            7377638, 30721961, 16902846, 18478635, 268396, 4395025, 31096596, 15618822,
            4435705, 8453200, 6553814, 12305992, 19469683, 29175688, 5409768, 18613136,
            17723140, 15558931, 1590513, 10366678, 5419878, 12589641, 12004879, 15361409,
            29501890, 16830373, 20141792, 20074860, 31733104, 16225299, 14850451, 15744689,
            30122101, 16273704, 22115391, 23176259, 4177191, 16795429, 3611865, 30218133,
            12675405, 49238, 8943208, 27945812, 29986577, 29556986, 7476442, 30452038,
            33486686, 28752401, 28144165, 17167249, 2096036, 8056532, 12283342, 16829510,
            18282201, 14616950, 4088159, 29137755, 14448101, 557510, 13178891, 15635466,
            11052621, 19516718, 28160211, 6743924, 20150961, 31859138, 12712854, 14937299,
            17053787, 1039691, 17471924, 14307525, 30296541, 30101645, 42548, 2072852,
            29040548, 27726919, 19354110, 5290846, 18120678, 15087770, 30338789, 30361267,
            11823051, 10583134, 31531079, 20276561, 19010619, 137217, 27157585, 28690865,
            32138765, 27929222, 30408977, 31669678, 8796550, 785823, 13617434, 11267578,
            13072542, 20649664, 21892903, 7597589, 27610282, 15890084, 19440186, 15359768,
            9514120, 8007843, 30153616, 22147814, 14399608, 12899493, 25298468, 32810793,
            8269420, 3403325, 11674420, 8419276, 29753542, 14004072, 12045073, 30058188,
            1422724, 13242775, 5693609, 32447603, 28381159, 13014680, 19998549, 30337809,
            24438049, 11381359, 5987553, 3295126, 5507033, 19110745, 27996398, 26938428,
            9749821, 32961393, 12264709, 8260281, 25365043, 15638338, 14985407, 19167162,
            3131452, 16472265, 23979105, 16632853, 1074715, 920706, 19955155, 29864583,
            23922922, 16060380, 1508442, 7722040, 17886494, 2659587, 687887, 32559505,
            20008708, 14541073, 12028938, 16448317, 67821, 17210232, 23580408, 20168304,
            32631478, 15323501, 21908989, 30980701, 3213649, 13165525, 8692306, 1740515,
            30886399, 17268241, 28476473, 25215521, 31584458, 30753116, 20601080, 23615471,
            27348077, 25418811, 18396646, 18258178, 7034695, 8741695, 21665784, 21088636,
            10048532, 2412935, 170015, 3865135, 17032382, 22706759, 19469446, 24386769,
            3521968, 20549976, 10106907, 2808206, 16205085, 20220771, 17457010, 18146902,
            12477818, 10785412, 25652507, 14449439, 22070385, 26385813, 9374463, 33232000,
            6527968, 30626483, 30562511, 26546618, 24702783, 7068759, 19952814, 5645943,
            19579851, 3609833, 31362391, 27788414, 5042300, 33007019, 12802497, 16357320,
            17315827, 7296024, 631271, 32726404, 11753362, 2221327, 3409788, 13816298,
            11606187, 2144744, 13796367, 15330520, 20698452, 28116266, 26435670, 11989567,
            3369365, 7804822, 1333216, 29421044, 4807421, 33160523, 7498114, 13755212,
            18320632, 22014448, 20587254, 13892025, 2758793, 22986496, 1785992, 7028345,
            3926333, 31133680, 11518450, 5531843, 1241501, 28903517, 28545275, 24859744,
            26015297, 25484733, 633861, 14815950, 32100504, 21559221, 18096462, 9695471,
            6546615, 12428591, 11978091, 7849554, 23319317, 9578420, 27432070, 26254340,
            23647123, 3842023, 25025704, 22153943, 7809822, 31553716, 26194628, 11814423,
            12138116, 18463476, 19409305, 20030552, 19022636, 8996288, 13119910, 18290405,
            3786335, 10662724, 9110903, 17788635, 25423521, 13299684, 3941164, 30149110,
            1626034, 175845, 5537565, 22399972, 7918687, 1468866, 10186384, 16626187,
            1062352, 30247984, 1779198, 26381141, 28126970, 30715305, 16950924, 20410687,
            17416489, 31681908, 15586547, 27532752, 17196433, 17376620, 2167125, 24880079,
            31445715, 1085169, 3689316, 4939029, 2921480, 2699270, 2226729, 22634147,
            30361875, 28923733, 9761174, 31094247, 11490633, 1870011, 1308086, 11791503,
            7866036, 8818285, 14677981, 13823625, 25683102, 14762977, 17364919, 22069728,
            19058372, 16887273, 28404352, 15580332, 6751007, 26040181, 14775687, 27056084,
            9303383, 6393448, 23126303, 11033123, 22501679, 21838319, 6620230, 4241927,
        };

        public static final int[] t_tab = new int[]{
            1, 6766491, 31401819, 3725492, 28949306, 7949577, 29839180, 31413549,
            27777950,
        };


        private static int mulh64(long a, long b)
        {
            long al, bl, mask_low = (-1L) >>> 32;
            long ah, bh, albl, albh, ahbl, ahbh, t0, t1;

            al = a & mask_low;         // low part
            ah = a >> 32;              // high part
            bl = b & mask_low;
            bh = b >> 32;

            albl = (long)(al * bl);
            albh = al * bh;
            ahbl = ah * bl;
            ahbh = ah * bh;

            t0 = (ahbl & mask_low) + (albh & mask_low) + (albl >> 32);
            t0 = (ahbh & mask_low) + (ahbl >> 32) + (albh >> 32) + (t0 >> 32);
            t1 = (ahbh >> 32) + (t0 >> 32);

            return (int)(t0 + (t1 << 32));
        }


        private static long IFLESS64(long val, long gauge, long expr)
        {
            return ((((val) - (gauge)) >> (63)) & (expr));
        }

        private static long IFMORE64(long val, long gauge, long expr)
        {
            return ((((gauge) - (val)) >> (63)) & (expr));
        }

        private static int IFLESS32(int val, int gauge, int expr)
        {
            return ((((val) - (gauge)) >> (31)) & (expr));
        }


        private static int IFMORE32(int val, int gauge, int expr)
        {
            return ((((gauge) - (val)) >> (31)) & (expr));
        }


        private static int CENTER32(int v)
        {
            return v += IFLESS32((v), -(PARAM_Q >> 1), PARAM_Q) - IFMORE32((v), (PARAM_Q >> 1), PARAM_Q);
        }


        private static long barrett(long a)
        {
            long u = mulh64(a, RING_QREC);
            a -= u * PARAM_Q;
            long j = a + IFLESS64(a, 0, PARAM_Q) - IFMORE64(a, PARAM_Q - 1, PARAM_Q);
            return j;
        }


        static long MODQ(long value)
        {
            return barrett(value);
        }


        static void mu_dag(IntSlicer ai, IntSlicer Ai)
        { // The mu_dag component of the sextic NTT.
            // Input: Ai, the vector from (Z/qZ)^6 to apply mu_dag to.
            long u[] = new long[]{
                Ai.at(0 << PARAM_LGM), Ai.at(1 << PARAM_LGM), Ai.at(2 << PARAM_LGM),
                Ai.at(3 << PARAM_LGM), Ai.at(4 << PARAM_LGM), Ai.at(5 << PARAM_LGM),
            };
            long s0, s1, t0, t1;
            t0 = (u[2] - u[4]) * t_tab[3]; //% q;
            t1 = MODQ((u[3] - u[5]) * (long)t_tab[3]);
            s0 = u[0] + u[2] + u[4];
            s1 = u[1] + u[3] + u[5];
            ai.at(0 << PARAM_LGM, MODQ(s0 - s1 * t_tab[6]));
            ai.at(3 << PARAM_LGM, MODQ(s0 - s1));
            s0 = u[0] - u[2] - t0;
            s1 = u[1] - u[3] - t1;
            ai.at(1 << PARAM_LGM, MODQ(s0 - s1 * t_tab[5]));
            ai.at(4 << PARAM_LGM, MODQ(s0 - s1 * t_tab[8]));
            s0 = u[0] - u[4] + t0;
            s1 = u[1] - u[5] + t1;
            ai.at(2 << PARAM_LGM, MODQ(s0 - s1 * t_tab[4]));
            ai.at(5 << PARAM_LGM, MODQ(s0 - s1 * t_tab[7]));
        }


        static void NTT(IntSlicer A, IntSlicer a)
        {
            // The number-theoretic transform on (Z/qZ)[x, y]/<x^m + 1, y^6 + y^3 + 1>.
            // Input:  a, vector from (Z/qZ)^n, n = 6*m
            // Output: A, output vector NTT(a) in (Z/qZ)^n, n = 6*m
            int[] _Aa = new int[PARAM_N];

            // Apply the fudge preprocessing:
            for (int j = 0; j < PARAM_N; j++)
            {
                _Aa[j] = (int)MODQ(((long)a.at(j)) * (long)psi_phi_tab[j]);
            }

            IntSlicer Aa = new IntSlicer(_Aa, 0);

            int cc = 0;

            // Apply the binary NTT to each of the six m-entry blocks:
            IntSlicer Ao = A.copy();
            for (int o = 0; o < PARAM_N; o += PARAM_M)
            {
                // bit-reverse copy:
                IntSlicer Aao = Aa.from(o);
                for (int v = 0; v < PARAM_M; v++)
                {
                    Ao.at(rev_tab[v], Aao.at(v));
                }

                for (int s = 1; s <= PARAM_LGM; s++)
                {
                    int t = 1 << s, NumoProblems = 1 << (s - 1);
                    for (int jFirst = 0; jFirst < NumoProblems; jFirst++)
                    {
                        long W = twiddle[jFirst << (PARAM_LGM - s)];
                        for (int j = jFirst; j < jFirst + PARAM_M; j += t)
                        {
                            int temp = (int)MODQ(W * (long)Ao.at(j + NumoProblems));
                            Ao.at(j + NumoProblems, Ao.at(j) - temp);
                            Ao.at(j, Ao.at(j) + temp);
                        }
                    }
                }
                Ao.incBase(PARAM_M);
            }

            // Apply the mu transform to interlaced blocks:
            for (int i = 0; i < PARAM_M; i++)
            {
                mu(A.from(i), A.from(i));
            }
        }


        static void mu(IntSlicer Ai, IntSlicer ai)
        {
// The mu component of the sextic NTT
            // Input: ai, the vector from (Z/qZ)^6 to apply mu to.
            long u[] = new long[]{
                ai.at(0 << PARAM_LGM),
                ai.at(1 << PARAM_LGM),
                ai.at(2 << PARAM_LGM),
                ai.at(3 << PARAM_LGM),
                ai.at(4 << PARAM_LGM),
                ai.at(5 << PARAM_LGM),
            };
            long s0, s1, s2, s3;
            s0 = u[0] + u[3];
            s1 = u[1] + u[4];
            s2 = u[2] + u[5];
            s3 = (s1 - s2) * t_tab[3]; //% q;
            Ai.at(0 << PARAM_LGM, MODQ(s0 + s1 + s2));
            Ai.at(2 << PARAM_LGM, MODQ(s0 - s2 + s3));
            Ai.at(4 << PARAM_LGM, MODQ(s0 - s3 - s1));
            s0 = u[0] + u[3] * t_tab[3]; //% q;
            s1 = u[1] * t_tab[1] + u[4] * t_tab[4]; //% q;
            s2 = u[2] * t_tab[2] + u[5] * t_tab[5]; //% q;
            s3 = MODQ(s1 - s2) * t_tab[3]; //% q;
            Ai.at(1 << PARAM_LGM, MODQ(s0 + s1 + s2));
            Ai.at(3 << PARAM_LGM, MODQ(s0 - s2 + s3));
            Ai.at(5 << PARAM_LGM, MODQ(s0 - s3 - s1));
        }


        static void invNTT(IntSlicer a, IntSlicer A)
        {
            // The inverse number-theoretic transform on (Z/qZ)[x, y]/<x^m + 1, y^6 + y^3 + 1>.
            // Input:  A, vector from (Z/qZ)^n, n = 6*m
            // Output: a, output vector NTT^{-1}(A) in (Z/qZ)^n, n = 6*m
            IntSlicer aA = new IntSlicer(new int[PARAM_N], 0);

            // Apply the mu transform to interlaced blocks:
            for (int i = 0; i < PARAM_M; i++)
            {
                mu_dag(aA.from(i), A.from(i));
            }

            // Apply the inverse binary NTT to each of the six m-entry blocks:
            IntSlicer ao = a.copy();
            for (int o = 0; o < PARAM_N; o += PARAM_M)
            {
                // bit-reverse copy:
                IntSlicer aAo = aA.from(o);
                for (int v = 0; v < PARAM_M; v++)
                {
                    ao.at(rev_tab[v], aAo.at(v));
                }

                for (int s = 1; s <= PARAM_LGM; s++)
                {
                    int t = 1 << s, NumoProblems = 1 << (s - 1);
                    for (int jFirst = 0; jFirst < NumoProblems; jFirst++)
                    {
                        long W = twiddle[(-(jFirst << (PARAM_LGM - s))) & (PARAM_M - 1)];
                        for (int k = jFirst; k < jFirst + PARAM_M; k += t)
                        {
                            int temp = (int)MODQ(W * ao.at(k + NumoProblems));
                            ao.at(k + NumoProblems, ao.at(k) - temp);
                            ao.at(k, ao.at(k) + temp);
                        }
                    }
                }
                ao.incBase(PARAM_M);
            }


            // Apply the fudge postprocessing and centralize:
            for (int j = 0; j < PARAM_N; j++)
            {
                a.at(j, MODQ((long)a.at(j) * iph_ips_tab[j]));
                a.at(j, CENTER32(a.at(j)));
                aA.at(j, 0);
            }

        }

        static void ntt(int[] a)
        {
            NTT(new IntSlicer(a, 0), new IntSlicer(a, 0));
        }

        static void nttInv(int[] a)
        {
            invNTT(new IntSlicer(a, 0), new IntSlicer(a, 0));
        }

        public static void poly_pointwise(int[] result, int[] x, int[] y)
        { // Pointwise polynomial multiplication result = x.y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = (int)MODQ((long)x[i] * (long)y[i]);
            }
        }

        public static void poly_mul(int[] result, int[] x, int[] y)
        { // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)
            // The input x is assumed to be in NTT form
            int[] y_ntt = new int[PARAM_N];

            for (int i = 0; i < PARAM_N; i++)
            {
                y_ntt[i] = y[i];
            }

            ntt(y_ntt);
            poly_pointwise(result, x, y_ntt);

            nttInv(result);
        }


        public static void poly_add(int[] result, int[] x, int[] y)
        { // Polynomial addition result = x+y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] + y[i];
            }
        }


        static void poly_add_correct(int[] result, int[] x, int[] y)
        { // Polynomial addition result = x+y with correction

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] + y[i];
                result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;    // If result[i] < 0 then add q
                result[i] -= PARAM_Q;
                result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;    // If result[i] >= q then subtract q
            }
        }


        static void poly_sub_correct(int[] result, int[] x, int[] y)
        { // Polynomial subtraction result = x-y with correction

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] - y[i];
                result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;    // If result[i] < 0 then add q
            }
        }

        static void poly_sub_reduce(int[] result, int[] x, int[] y)
        { // Polynomial subtraction result = x-y with reduction

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = (int)MODQ((x[i] - y[i]));
            }
        }


        static void poly_uniform(int[] a, byte[] seed, int seedOffset)
        { // Generation of polynomial "a" (in NTT form, i.e. as the sequence of eigenvalues)
            int pos = 0, i = 0, nbytes = (PARAM_Q_LOG + 7) / 8;
            int nblocks = PARAM_GEN_A;
            int val1, val2, val3, val4, mask = (1 << PARAM_Q_LOG) - 1;
            byte[] buf = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A];
            short dmsp = 0;

            HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                buf, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A,
                dmsp++,
                seed, seedOffset, CRYPTO_RANDOMBYTES
            );


            while (i < PARAM_N)
            {
                if (pos > HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * nblocks - 4 * nbytes)
                {
                    nblocks = 1;

                    HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                        buf, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * nblocks,
                        dmsp++,
                        seed, seedOffset, CRYPTO_RANDOMBYTES
                    );

                    pos = 0;
                }
                val1 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                val2 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                val3 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                val4 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                if (val1 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = (int)MODQ(val1);
                }
                if (val2 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = (int)MODQ(val2);
                }
                if (val3 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = (int)MODQ(val3);
                }
                if (val4 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = (int)MODQ(val4);
                }
            }
        }

    }


}
