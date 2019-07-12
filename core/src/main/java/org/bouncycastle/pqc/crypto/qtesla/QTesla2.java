package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class QTesla2
{

    private static final int PARAM_LGM = 7;
    private static final int PARAM_M = (1 << PARAM_LGM);
    private static final int PARAM_N = (6 * PARAM_M);

    private static final double PARAM_SIGMA = 9.73;
    private static final int PARAM_Q = 8404993;
    private static final int PARAM_Q_LOG = 24;
    //    private static final long PARAM_QINV = 4034936831L;
//    private static final int PARAM_BARR_MULT = 511;
//    private static final int PARAM_BARR_DIV = 32;
    private static final int PARAM_B_BITS = 21;
    private static final int PARAM_B = ((1 << PARAM_B_BITS) - 1);
    private static final int PARAM_S_BITS = 8;
    private static final int PARAM_K = 1;
    private static final double PARAM_SIGMA_E = PARAM_SIGMA;
    private static final int PARAM_H = 39;
    private static final int PARAM_D = 22;
    private static final int PARAM_GEN_A = 28;
    private static final int PARAM_KEYGEN_BOUND_E = 859;
    private static final int PARAM_E = (2 * PARAM_KEYGEN_BOUND_E);
    private static final int PARAM_KEYGEN_BOUND_S = 859;
    private static final int PARAM_S = (2 * PARAM_KEYGEN_BOUND_S);
    //    private static final int PARAM_R2_INVN = 3118783;
//    private static final int PARAM_R = 15873;
    private static final long RING_QREC = 2194736399388L;


    static final String CRYPTO_ALGNAME = "qTesla-II";

    private static final int CRYPTO_RANDOMBYTES = 32;
    private static final int CRYPTO_SEEDBYTES = 32;
    private static final int CRYPTO_C_BYTES = 32;
    private static final int HM_BYTES = 64;
    private static final int RADIX32 = 32;

    // Contains signature (z,c). z is a polynomial bounded by B, c is the output of a hashed string
    static final int CRYPTO_BYTES = ((PARAM_N * (PARAM_B_BITS + 1) + 7) / 8 + CRYPTO_C_BYTES);
    // Contains polynomial s and e, and seeds seed_a and seed_y
    static final int CRYPTO_SECRETKEYBYTES = (2 * PARAM_S_BITS * PARAM_N / 8 + 2 * CRYPTO_SEEDBYTES);
    // Contains seed_a and polynomial t
    static final int CRYPTO_PUBLICKEYBYTES = ((PARAM_N * PARAM_Q_LOG + 7) / 8 + CRYPTO_SEEDBYTES);

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


        HashUtils.secureHashAlgorithmKECCAK128(
            randomnessInput, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES, HM_BYTES, message, 0, messageLength);

        HashUtils.secureHashAlgorithmKECCAK128(
            randomness, 0, CRYPTO_SEEDBYTES, randomnessInput, 0, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + HM_BYTES);


        QTesla2Polynomial.poly_uniform(A, seed, 0);





        /* Loop Due to Possible Rejection */
        while (true)
        {

            /* Sample Y Uniformly Random from -B to B */
            sampleY(Y, randomness, 0, ++nonce); //n, q, b, bBit);

            /* V = A * Y Modulo Q */
            QTesla2Polynomial.poly_mul(V, A, Y);

            hashFunction(C, 0, V, randomnessInput, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES); //, n, d, q);


//
//            /* Generate C = EncodeC (C') Where C' is the Hashing of V Together with Message */
            encodeC(positionList, signList, C, 0);


            int c_ntt[] = new int[PARAM_N];

            for (int i = 0; i < PARAM_H; i++)
            {
                c_ntt[positionList[i]] = signList[i];
            }


            QTesla2Polynomial.ntt(c_ntt);
            QTesla2Polynomial.poly_mul(Sc, c_ntt, secretPolynomial);
            QTesla2Polynomial.poly_add(Z, Y, Sc);


            if (testRejection(Z)) // PARAM_N, b, u))
            {
                continue;
            }


            //sparse_mul16(Ec, e, pos_list, sign_list);
            QTesla2Polynomial.poly_mul(EC, c_ntt, errorPolynomial);
            QTesla2Polynomial.poly_sub_correct(V, V, EC);

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


    static int verifying(

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

        QTesla2Polynomial.poly_uniform(a, seed, 0);
        encodeC(pos_list, sign_list, c, 0);

        int c_ntt[] = new int[PARAM_N];

        for (int i = 0; i < PARAM_H; i++)
        {
            c_ntt[pos_list[i]] = sign_list[i];
        }
        QTesla2Polynomial.ntt(c_ntt);

        QTesla2Polynomial.poly_mul(Tc, c_ntt, pk_t);
        QTesla2Polynomial.poly_mul(w, a, z);
        QTesla2Polynomial.poly_sub_reduce(w, w, Tc);

        HashUtils.secureHashAlgorithmKECCAK128(
            hm, 0, HM_BYTES, message, 0, message.length
        );
        hashFunction(c_sig, 0, w, hm, 0);

        if (!memoryEqual(c, 0, c_sig, 0, CRYPTO_C_BYTES))
        {
            return -3;
        }

        return 0;
    }


    static int generateKeyPair(

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
        HashUtils.secureHashAlgorithmKECCAK128(randomness_extended, 0, CRYPTO_SEEDBYTES * 4, randomness, 0, CRYPTO_RANDOMBYTES);


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
        QTesla2Polynomial.poly_uniform(a, randomness_extended, 2 * CRYPTO_SEEDBYTES);

        // Compute the public key t = as+e
        QTesla2Polynomial.poly_mul(t, a, s);


        QTesla2Polynomial.poly_add_correct(t, t, e);

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

    static final int RADIX = 32;


    private static final int CHUNK_SIZE = 256;
    private static final int CDT_ROWS = 110;
    private static final int CDT_COLS = 3;

    private static long[] cdt_v = new long[]{
        0x00000000L, 0x00000000L, 0x00000000L, // 0
        0x053F8783L, 0x78DE6135L, 0x16412B5AL, // 1
        0x0FB06F27L, 0x743C9E89L, 0x059C8691L, // 2
        0x19F752BDL, 0x21757914L, 0x6AF58172L, // 3
        0x23F9A5F8L, 0x65676668L, 0x2B290419L, // 4
        0x2D9EF9B8L, 0x42F1FAE2L, 0x2EBEC2C9L, // 5
        0x36D1AD18L, 0x3CB06DACL, 0x10AC35FBL, // 6
        0x3F7F7A90L, 0x47B798D7L, 0x39436659L, // 7
        0x4799DB5CL, 0x3C854609L, 0x7AEAA69BL, // 8
        0x4F163E3FL, 0x698277F0L, 0x79BDE505L, // 9
        0x55EE119AL, 0x54E78427L, 0x0129CB99L, // 10
        0x5C1EA378L, 0x0CBE4B6CL, 0x276EF670L, // 11
        0x61A8DC95L, 0x26DE8805L, 0x0516674AL, // 12
        0x6690DD2AL, 0x1349C414L, 0x13C83A7AL, // 13
        0x6ADD8365L, 0x3719A26AL, 0x2E5504BAL, // 14
        0x6E97E40CL, 0x5F3E4043L, 0x502A23FFL, // 15
        0x71CABD8BL, 0x6285BC0BL, 0x3F0BA07DL, // 16
        0x7481ED0CL, 0x6CF4A8B5L, 0x0C0BFFABL, // 17
        0x76C9EC15L, 0x08AE2654L, 0x31DEA83FL, // 18
        0x78AF5BB4L, 0x7A2DDE63L, 0x0640AD30L, // 19
        0x7A3EA0D3L, 0x08B85D3BL, 0x075BFA78L, // 20
        0x7B83938AL, 0x271778D6L, 0x1CC92382L, // 21
        0x7C894229L, 0x31EC0FC3L, 0x1B7B88ABL, // 22
        0x7D59C729L, 0x67895551L, 0x265F0274L, // 23
        0x7DFE3080L, 0x6A9B0377L, 0x28497C39L, // 24
        0x7E7E7602L, 0x7AF8BF62L, 0x5BAD45F0L, // 25
        0x7EE17C2FL, 0x5F684E99L, 0x44F8C845L, // 26
        0x7F2D209AL, 0x27D3B863L, 0x5C480555L, // 27
        0x7F664D36L, 0x6B552137L, 0x6FBD5185L, // 28
        0x7F911011L, 0x58924729L, 0x7B2CBF5FL, // 29
        0x7FB0B54CL, 0x0CDC3AF7L, 0x1CDEAE69L, // 30
        0x7FC7E19FL, 0x59A240F0L, 0x75EA2A32L, // 31
        0x7FD8AC13L, 0x00A48D2DL, 0x590FAC4AL, // 32
        0x7FE4B5ECL, 0x48833F0BL, 0x55424ABAL, // 33
        0x7FED404BL, 0x2DCDFFB1L, 0x56274DA1L, // 34
        0x7FF33F15L, 0x27329608L, 0x57D3BB69L, // 35
        0x7FF76927L, 0x471FE786L, 0x10735496L, // 36
        0x7FFA45DFL, 0x1CBE6D75L, 0x3FA568E4L, // 37
        0x7FFC382EL, 0x47872228L, 0x7C654861L, // 38
        0x7FFD8783L, 0x4AF80118L, 0x49798F45L, // 39
        0x7FFE66CDL, 0x08C3C495L, 0x3EE2B02BL, // 40
        0x7FFEF9EBL, 0x1560713CL, 0x4C1FFE98L, // 41
        0x7FFF59D4L, 0x7843E6AEL, 0x06B843BDL, // 42
        0x7FFF97B4L, 0x47028BB3L, 0x443F422FL, // 43
        0x7FFFBF33L, 0x2803668EL, 0x0BD7C463L, // 44
        0x7FFFD825L, 0x345CB793L, 0x4ADE694EL, // 45
        0x7FFFE7BCL, 0x49C4BFFDL, 0x2200BC21L, // 46
        0x7FFFF160L, 0x60FA34ACL, 0x3BB03441L, // 47
        0x7FFFF747L, 0x09016D1EL, 0x7DC8236AL, // 48
        0x7FFFFAD9L, 0x4524F17FL, 0x77168850L, // 49
        0x7FFFFCFDL, 0x35A49790L, 0x42095FCBL, // 50
        0x7FFFFE42L, 0x1BB35624L, 0x06686AF1L, // 51
        0x7FFFFF00L, 0x5EF55746L, 0x605D6E76L, // 52
        0x7FFFFF6FL, 0x2A2A36E9L, 0x5CE4A475L, // 53
        0x7FFFFFAEL, 0x6C01E934L, 0x55038F73L, // 54
        0x7FFFFFD2L, 0x783506C9L, 0x504830B3L, // 55
        0x7FFFFFE7L, 0x1E48C4EFL, 0x13A21122L, // 56
        0x7FFFFFF2L, 0x43E914CAL, 0x2A8DF3C6L, // 57
        0x7FFFFFF8L, 0x5FD62183L, 0x119C73F4L, // 58
        0x7FFFFFFCL, 0x1172FD73L, 0x357AA4EFL, // 59
        0x7FFFFFFDL, 0x7B31F2A4L, 0x17FB523AL, // 60
        0x7FFFFFFEL, 0x77E02C50L, 0x3ACAD7F4L, // 61
        0x7FFFFFFFL, 0x39AE890CL, 0x401B179CL, // 62
        0x7FFFFFFFL, 0x5C0C94C6L, 0x1A7C4A2CL, // 63
        0x7FFFFFFFL, 0x6DCF1992L, 0x7C32FAF6L, // 64
        0x7FFFFFFFL, 0x76E3E4C9L, 0x31014F68L, // 65
        0x7FFFFFFFL, 0x7B7C26D2L, 0x7C3A65FBL, // 66
        0x7FFFFFFFL, 0x7DC90A64L, 0x2C968D8FL, // 67
        0x7FFFFFFFL, 0x7EECC48DL, 0x0EADCA35L, // 68
        0x7FFFFFFFL, 0x7F7BC44DL, 0x414A347DL, // 69
        0x7FFFFFFFL, 0x7FC1202BL, 0x781F6149L, // 70
        0x7FFFFFFFL, 0x7FE269D1L, 0x26ADEA6FL, // 71
        0x7FFFFFFFL, 0x7FF238ACL, 0x3146B8BFL, // 72
        0x7FFFFFFFL, 0x7FF9A64CL, 0x1144E7B6L, // 73
        0x7FFFFFFFL, 0x7FFD1A7CL, 0x0A441C27L, // 74
        0x7FFFFFFFL, 0x7FFEB147L, 0x6A203C49L, // 75
        0x7FFFFFFFL, 0x7FFF6A78L, 0x740E44E2L, // 76
        0x7FFFFFFFL, 0x7FFFBDE4L, 0x6F60CC76L, // 77
        0x7FFFFFFFL, 0x7FFFE313L, 0x6A4CDD29L, // 78
        0x7FFFFFFFL, 0x7FFFF37AL, 0x0F8FDB23L, // 79
        0x7FFFFFFFL, 0x7FFFFAA2L, 0x26ABB2A7L, // 80
        0x7FFFFFFFL, 0x7FFFFDB9L, 0x3E07782CL, // 81
        0x7FFFFFFFL, 0x7FFFFF0BL, 0x461AA8B5L, // 82
        0x7FFFFFFFL, 0x7FFFFF9AL, 0x3D7C8A27L, // 83
        0x7FFFFFFFL, 0x7FFFFFD6L, 0x237A3820L, // 84
        0x7FFFFFFFL, 0x7FFFFFEFL, 0x03EDD61BL, // 85
        0x7FFFFFFFL, 0x7FFFFFF9L, 0x15C32760L, // 86
        0x7FFFFFFFL, 0x7FFFFFFDL, 0x23C8A19EL, // 87
        0x7FFFFFFFL, 0x7FFFFFFEL, 0x76BE7395L, // 88
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x4A75D8B4L, // 89
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x6B55365BL, // 90
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x781AEA35L, // 91
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7D03F9B0L, // 92
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7EE22EECL, // 93
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F9630C9L, // 94
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FD93CB0L, // 95
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF1F27AL, // 96
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFAF55DL, // 97
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFE35CCL, // 98
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF5F06L, // 99
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFC809L, // 100
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFECBFL, // 101
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF972L, // 102
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFDCAL, // 103
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF43L, // 104
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFC2L, // 105
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFEBL, // 106
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF9L, // 107
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFEL, // 108
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, // 109
    }; // cdt_v


    private static void kmxGauss(int[] z, int chunk, byte[] seed, int seedOffset, int nonce)
    {
        int[] sampk = new int[(CHUNK_SIZE + CDT_ROWS) * CDT_COLS];
        int[] sampg = new int[CHUNK_SIZE + CDT_ROWS];


        {
            // In the C Implementation they cast between uint_8 and int32 a lot, this is one of those situations.
            byte[] sampkBytes = new byte[sampk.length * 4];
            HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
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
//                            {
//                                diff = (diff + (a[ap_iPtr + 3] & ((neg >>> 1))) - (a[a_iPtr + 3] & ((neg >>> 1)))) >> (32 - 1);
//                            }
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
//                            {
//                                swapa = (a[a_iPtr + 3] ^ a[ap_iPtr + 3]) & diff;
//                                a[a_iPtr + 3] ^= swapa;
//                                a[ap_iPtr + 3] ^= swapa;
//                            }
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
//                                {
//                                    diff = (diff + (a[aq_iPtr + 3] & (neg >>> 1))) - (a[ap_iPtr_ + 3] & (neg >>> 1)) >> (32 - 1);
//                                }
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
//                                {
//                                    swapa = (a[ap_iPtr_ + 3] ^ a[aq_iPtr + 3]) & diff;
//                                    a[ap_iPtr_ + 3] ^= swapa;
//                                    a[aq_iPtr + 3] ^= swapa;
//                                }
//                                ;
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
        HashUtils.secureHashAlgorithmKECCAK128(output, outputOffset, CRYPTO_C_BYTES, T, 0, PARAM_N + HM_BYTES);

    }

    static void encodeC(int[] positionList, short[] signList, byte[] output, int outputOffset)
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


    static void encodePrivateKey(byte[] privateKey, final int[] secretPolynomial, final int[] errorPolynomial, final byte[] seed, int seedOffset)
    {
        byte[] sk = privateKey;
        int[] s = secretPolynomial;
        int[] e = errorPolynomial;

        int j = 0;

        for (int i = 0; i < PARAM_N; i++, j++)
        {
            sk[j] = (byte)s[i];
        }
        for (int i = 0; i < PARAM_N; i++, j++)
        {
            sk[j] = (byte)e[i];
        }

        System.arraycopy(seed, seedOffset, privateKey, 2 * PARAM_S_BITS * PARAM_N / 8, CRYPTO_SEEDBYTES * 2);

    }


    static void decodePrivateKey(byte[] seed, int[] secretPolynomial, int[] errorPolynomial, final byte[] privateKey)
    {

        int j = 0;
        int temporary = 0;


        for (int i = 0; i < PARAM_N; i++, j++)
        {
            secretPolynomial[i] = privateKey[j];
        }
        for (int i = 0; i < PARAM_N; i++, j++)
        {
            errorPolynomial[i] = privateKey[j];
        }
        System.arraycopy(privateKey, 2 * PARAM_S_BITS * PARAM_N / 8, seed, 0, CRYPTO_SEEDBYTES * 2);


    }


    static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {
        int maskq = ((1 << PARAM_Q_LOG) - 1);

        int j = 0;
        for (int i = 0; i < PARAM_N; i += 32)
        {
            publicKey[i + 0] = (at(publicKeyInput, j, 0)) & maskq;
            publicKey[i + 1] = ((at(publicKeyInput, j, 0) >>> 24) | (at(publicKeyInput, j, 1) << 8)) & maskq;
            publicKey[i + 2] = ((at(publicKeyInput, j, 1) >>> 16) | (at(publicKeyInput, j, 2) << 16)) & maskq;
            publicKey[i + 3] = ((at(publicKeyInput, j, 2) >>> 8)) & maskq;

            publicKey[i + 4] = (at(publicKeyInput, j, 3)) & maskq;
            publicKey[i + 5] = ((at(publicKeyInput, j, 3) >>> 24) | (at(publicKeyInput, j, 4) << 8)) & maskq;
            publicKey[i + 6] = ((at(publicKeyInput, j, 4) >>> 16) | (at(publicKeyInput, j, 5) << 16)) & maskq;
            publicKey[i + 7] = ((at(publicKeyInput, j, 5) >>> 8)) & maskq;

            publicKey[i + 8] = (at(publicKeyInput, j, 6)) & maskq;
            publicKey[i + 9] = ((at(publicKeyInput, j, 6) >>> 24) | (at(publicKeyInput, j, 7) << 8)) & maskq;
            publicKey[i + 10] = ((at(publicKeyInput, j, 7) >>> 16) | (at(publicKeyInput, j, 8) << 16)) & maskq;
            publicKey[i + 11] = ((at(publicKeyInput, j, 8) >>> 8)) & maskq;

            publicKey[i + 12] = (at(publicKeyInput, j, 9)) & maskq;
            publicKey[i + 13] = ((at(publicKeyInput, j, 9) >>> 24) | (at(publicKeyInput, j, 10) << 8)) & maskq;
            publicKey[i + 14] = ((at(publicKeyInput, j, 10) >>> 16) | (at(publicKeyInput, j, 11) << 16)) & maskq;
            publicKey[i + 15] = ((at(publicKeyInput, j, 11) >>> 8)) & maskq;

            publicKey[i + 16] = (at(publicKeyInput, j, 12)) & maskq;
            publicKey[i + 17] = ((at(publicKeyInput, j, 12) >>> 24) | (at(publicKeyInput, j, 13) << 8)) & maskq;
            publicKey[i + 18] = ((at(publicKeyInput, j, 13) >>> 16) | (at(publicKeyInput, j, 14) << 16)) & maskq;
            publicKey[i + 19] = ((at(publicKeyInput, j, 14) >>> 8)) & maskq;

            publicKey[i + 20] = (at(publicKeyInput, j, 15)) & maskq;
            publicKey[i + 21] = ((at(publicKeyInput, j, 15) >>> 24) | (at(publicKeyInput, j, 16) << 8)) & maskq;
            publicKey[i + 22] = ((at(publicKeyInput, j, 16) >>> 16) | (at(publicKeyInput, j, 17) << 16)) & maskq;
            publicKey[i + 23] = ((at(publicKeyInput, j, 17) >>> 8)) & maskq;

            publicKey[i + 24] = (at(publicKeyInput, j, 18)) & maskq;
            publicKey[i + 25] = ((at(publicKeyInput, j, 18) >>> 24) | (at(publicKeyInput, j, 19) << 8)) & maskq;
            publicKey[i + 26] = ((at(publicKeyInput, j, 19) >>> 16) | (at(publicKeyInput, j, 20) << 16)) & maskq;
            publicKey[i + 27] = ((at(publicKeyInput, j, 20) >>> 8)) & maskq;

            publicKey[i + 28] = (at(publicKeyInput, j, 21)) & maskq;
            publicKey[i + 29] = ((at(publicKeyInput, j, 21) >>> 24) | (at(publicKeyInput, j, 22) << 8)) & maskq;
            publicKey[i + 30] = ((at(publicKeyInput, j, 22) >>> 16) | (at(publicKeyInput, j, 23) << 16)) & maskq;
            publicKey[i + 31] = ((at(publicKeyInput, j, 23) >>> 8)) & maskq;
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


    static void encodePublicKey(byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset)
    {

        int[] t = T;
        int j = 0;
        for (int i = 0; i < (PARAM_N * PARAM_Q_LOG / 32); i += PARAM_Q_LOG)
        {
            at(publicKey, i, 0, (t[j + 0] | (t[j + 1] << 24)));
            at(publicKey, i, 1, ((t[j + 1] >> 8) | (t[j + 2] << 16)));
            at(publicKey, i, 2, ((t[j + 2] >> 16) | (t[j + 3] << 8)));
            at(publicKey, i, 3, (t[j + 4] | (t[j + 5] << 24)));
            at(publicKey, i, 4, ((t[j + 5] >> 8) | (t[j + 6] << 16)));
            at(publicKey, i, 5, ((t[j + 6] >> 16) | (t[j + 7] << 8)));
            at(publicKey, i, 6, (t[j + 8] | (t[j + 9] << 24)));
            at(publicKey, i, 7, ((t[j + 9] >> 8) | (t[j + 10] << 16)));
            at(publicKey, i, 8, ((t[j + 10] >> 16) | (t[j + 11] << 8)));
            at(publicKey, i, 9, (t[j + 12] | (t[j + 13] << 24)));
            at(publicKey, i, 10, ((t[j + 13] >> 8) | (t[j + 14] << 16)));
            at(publicKey, i, 11, ((t[j + 14] >> 16) | (t[j + 15] << 8)));
            at(publicKey, i, 12, (t[j + 16] | (t[j + 17] << 24)));
            at(publicKey, i, 13, ((t[j + 17] >> 8) | (t[j + 18] << 16)));
            at(publicKey, i, 14, ((t[j + 18] >> 16) | (t[j + 19] << 8)));
            at(publicKey, i, 15, (t[j + 20] | (t[j + 21] << 24)));
            at(publicKey, i, 16, ((t[j + 21] >> 8) | (t[j + 22] << 16)));
            at(publicKey, i, 17, ((t[j + 22] >> 16) | (t[j + 23] << 8)));
            at(publicKey, i, 18, (t[j + 24] | (t[j + 25] << 24)));
            at(publicKey, i, 19, ((t[j + 25] >> 8) | (t[j + 26] << 16)));
            at(publicKey, i, 20, ((t[j + 26] >> 16) | (t[j + 27] << 8)));
            at(publicKey, i, 21, (t[j + 28] | (t[j + 29] << 24)));
            at(publicKey, i, 22, ((t[j + 29] >> 8) | (t[j + 30] << 16)));
            at(publicKey, i, 23, ((t[j + 30] >> 16) | (t[j + 31] << 8)));
            j += 32;
        }
        System.arraycopy(seedA, seedAOffset, publicKey, PARAM_N * PARAM_Q_LOG / 8, CRYPTO_SEEDBYTES);


    }

    static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z)
    {

        int j = 0;

        for (int i = 0; i < (PARAM_N * (PARAM_B_BITS + 1) / 32); i += ((PARAM_B_BITS + 1) / 2))
        {
            at(signature, i, 0, ((Z[j] & ((1 << 22) - 1)) | (Z[j + 1] << 22)));
            at(signature, i, 1, (((Z[j + 1] >>> 10) & ((1 << 12) - 1)) | (Z[j + 2] << 12)));
            at(signature, i, 2, (((Z[j + 2] >>> 20) & ((1 << 2) - 1)) | ((Z[j + 3] & ((1 << 22) - 1)) << 2) | (Z[j + 4] << 24)));
            at(signature, i, 3, (((Z[j + 4] >>> 8) & ((1 << 14) - 1)) | (Z[j + 5] << 14)));
            at(signature, i, 4, (((Z[j + 5] >>> 18) & ((1 << 4) - 1)) | ((Z[j + 6] & ((1 << 22) - 1)) << 4) | (Z[j + 7] << 26)));
            at(signature, i, 5, (((Z[j + 7] >>> 6) & ((1 << 16) - 1)) | (Z[j + 8] << 16)));
            at(signature, i, 6, (((Z[j + 8] >>> 16) & ((1 << 6) - 1)) | ((Z[j + 9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28)));
            at(signature, i, 7, (((Z[j + 10] >>> 4) & ((1 << 18) - 1)) | (Z[j + 11] << 18)));
            at(signature, i, 8, (((Z[j + 11] >>> 14) & ((1 << 8) - 1)) | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30)));
            at(signature, i, 9, (((Z[j + 13] >>> 2) & ((1 << 20) - 1)) | (Z[j + 14] << 20)));
            at(signature, i, 10, (((Z[j + 14] >>> 12) & ((1 << 10) - 1)) | (Z[j + 15] << 10)));
            j += 16;
        }
        System.arraycopy(C, cOffset, signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, CRYPTO_C_BYTES);

    }


    static void decodeSignature(byte[] C, int[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;

        for (int i = 0; i < PARAM_N; i += 16)
        {
            Z[i] = (at(signature, j, 0) << 10) >> 10;
            Z[i + 1] = (at(signature, j, 0) >>> 22) | ((at(signature, j, 1) << 20) >> 10);
            Z[i + 2] = (at(signature, j, 1) >>> 12) | ((at(signature, j, 2) << 30) >> 10);
            Z[i + 3] = (at(signature, j, 2) << 8) >> 10;
            Z[i + 4] = (at(signature, j, 2) >>> 24) | ((at(signature, j, 3) << 18) >> 10);
            Z[i + 5] = (at(signature, j, 3) >>> 14) | ((at(signature, j, 4) << 28) >> 10);
            Z[i + 6] = (at(signature, j, 4) << 6) >> 10;
            Z[i + 7] = (at(signature, j, 4) >>> 26) | ((at(signature, j, 5) << 16) >> 10);
            Z[i + 8] = (at(signature, j, 5) >>> 16) | ((at(signature, j, 6) << 26) >> 10);
            Z[i + 9] = (at(signature, j, 6) << 4) >> 10;
            Z[i + 10] = (at(signature, j, 6) >>> 28) | ((at(signature, j, 7) << 14) >> 10);
            Z[i + 11] = (at(signature, j, 7) >>> 18) | ((at(signature, j, 8) << 24) >> 10);
            Z[i + 12] = (at(signature, j, 8) << 2) >> 10;
            Z[i + 13] = (at(signature, j, 8) >>> 30) | ((at(signature, j, 9) << 12) >> 10);
            Z[i + 14] = (at(signature, j, 9) >>> 20) | ((at(signature, j, 10) << 22) >> 10);
            Z[i + 15] = at(signature, j, 10) >> 10;

            j += 11;

        }

        System.arraycopy(signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, C, 0, CRYPTO_C_BYTES);


    }


    private static final int SHAKE_RATE = HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE;
    private static final int NBLOCKS_SHAKE = SHAKE_RATE / (((PARAM_B_BITS + 1) + 7) / 8);
    private static final int BPLUS1BYTES = ((PARAM_B_BITS + 1) + 7) / 8;

    static void sampleY(int[] Y, final byte[] seed, int seedOffset, int nonce) //   int n, int b, int bBit)
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

            if (position >= numberOfBlock * numberOfByte * 4)
            {
                numberOfBlock =
                    SHAKE_RATE /
                        ((PARAM_B_BITS + 1 + 7) / 8);

                HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
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


    private static class QTesla2Polynomial
    {

        static final int[] rev_tab = new int[]{
            0, 64, 32, 96, 16, 80, 48, 112,
            8, 72, 40, 104, 24, 88, 56, 120,
            4, 68, 36, 100, 20, 84, 52, 116,
            12, 76, 44, 108, 28, 92, 60, 124,
            2, 66, 34, 98, 18, 82, 50, 114,
            10, 74, 42, 106, 26, 90, 58, 122,
            6, 70, 38, 102, 22, 86, 54, 118,
            14, 78, 46, 110, 30, 94, 62, 126,
            1, 65, 33, 97, 17, 81, 49, 113,
            9, 73, 41, 105, 25, 89, 57, 121,
            5, 69, 37, 101, 21, 85, 53, 117,
            13, 77, 45, 109, 29, 93, 61, 125,
            3, 67, 35, 99, 19, 83, 51, 115,
            11, 75, 43, 107, 27, 91, 59, 123,
            7, 71, 39, 103, 23, 87, 55, 119,
            15, 79, 47, 111, 31, 95, 63, 127,
        };

        static final int[] twiddle = new int[]{1,
            1623961, 6270918, 1407594, 5433596, 8117671, 3463953, 5647814, 7134899,
            2159866, 90438, 7342229, 2379409, 6367187, 5639303, 3411320, 2082318,
            5577922, 6278159, 1923988, 973655, 5249316, 4360356, 1182483, 714467,
            7690095, 6807119, 5239962, 1651513, 1461658, 4704222, 6825782, 4819347,
            4671615, 5785355, 5665825, 6920830, 1368030, 2807084, 4101293, 4898555,
            5361631, 2786978, 6139232, 5121240, 3888098, 3004816, 400180, 2654220,
            395244, 5146046, 2733215, 8191273, 2836022, 5968848, 519776, 7720725,
            7983975, 4153273, 7046636, 5240745, 4059033, 3074540, 5796241, 8404992,
            6781032, 2134075, 6997399, 2971397, 287322, 4941040, 2757179, 1270094,
            6245127, 8314555, 1062764, 6025584, 2037806, 2765690, 4993673, 6322675,
            2827071, 2126834, 6481005, 7431338, 3155677, 4044637, 7222510, 7690526,
            714898, 1597874, 3165031, 6753480, 6943335, 3700771, 1579211, 3585646,
            3733378, 2619638, 2739168, 1484163, 7036963, 5597909, 4303700, 3506438,
            3043362, 5618015, 2265761, 3283753, 4516895, 5400177, 8004813, 5750773,
            8009749, 3258947, 5671778, 213720, 5568971, 2436145, 7885217, 684268,
            421018, 4251720, 1358357, 3164248, 4345960, 5330453, 2608752
        };

        static final int[] psi_phi_tab = new int[]{
            1,
            56156, 1623961, 979866, 6270918, 5679487, 1407594, 4294492, 5433596,
            2556097, 8117671, 2732328, 3463953, 4991669, 5647814, 4637122, 7134899,
            1371934, 2159866, 5386106, 90438, 2020556, 7342229, 3280109, 2379409,
            3918083, 6367187, 7350952, 5639303, 5778007, 3411320, 7890457, 2082318,
            4386992, 5577922, 4913701, 6278159, 460426, 1923988, 5690106, 973655,
            2090715, 5249316, 674800, 4360356, 5895460, 1182483, 4070648, 714467,
            4577263, 7690095, 4839473, 6807119, 1492924, 5239962, 4906135, 1651513,
            1671266, 1461658, 6110003, 4704222, 1360642, 6825782, 7313220, 4819347,
            2880525, 4671615, 2570424, 5785355, 4200951, 5665825, 7463678, 6920830,
            7658153, 1368030, 1456660, 2807084, 7370382, 4101293, 6996515, 4898555,
            4643676, 5361631, 4091190, 2786978, 4566908, 6139232, 7114311, 5121240,
            3112952, 3888098, 3528127, 3004816, 8212821, 400180, 5961791, 2654220,
            4637451, 395244, 6140544, 5146046, 889850, 2733215, 2844367, 8191273,
            669684, 2836022, 1844068, 5968848, 3912441, 519776, 6405360, 7720725,
            1874188, 7983975, 558501, 4153273, 1047831, 7046636, 3820776, 5240745,
            6851318, 4059033, 4051981, 3074540, 6907027, 5796241, 1950678, 125596,
            1179849, 7445618, 1342630, 3943070, 5903328, 5958255, 5806436, 2921574,
            6851177, 4546030, 2008291, 7798315, 5231854, 3462909, 5199756, 8041116,
            7066164, 7786054, 5912564, 3505505, 1797727, 786489, 6243062, 4726649,
            22304, 159467, 3711307, 1949464, 7471552, 3628545, 2327721, 1049340,
            7736110, 119969, 4579771, 5644462, 1312056, 1648098, 3213365, 2930223,
            5054827, 5441416, 4636381, 7548268, 8335825, 7313551, 6596997, 2492064,
            1212534, 2211011, 2977120, 7839950, 6698860, 7315452, 4084644, 5009494,
            6434347, 4946055, 7670895, 2483377, 874956, 6845051, 5139087, 5134917,
            6304201, 406196, 7596567, 5801730, 7611214, 4629348, 7637791, 998606,
            8010233, 4228974, 7591722, 2685686, 6593617, 5999623, 684783, 1831173,
            4666626, 8177902, 6257178, 7355403, 3439869, 5734438, 2603519, 6764722,
            7665004, 7868101, 7407732, 279643, 3105384, 7554133, 1491045, 582754,
            4495875, 1176766, 2416530, 4046695, 408679, 4147034, 3700253, 3170522,
            866713, 6225758, 7982413, 5297752, 5834077, 205865, 3689565, 8134690,
            282090, 6039228, 5825011, 3800142, 6406875, 342142, 7917147, 4797204,
            3357181, 1863246, 7089512, 7737434, 7230569, 3025927, 213131, 6588348,
            4288414, 317148, 7987914, 3227167, 4735979, 2848218, 5918211, 1228703,
            2458131, 3604397, 7881499, 3336450, 5987237, 2750986, 598476, 4856242,
            7127867, 1517613, 4851601, 7062654, 3993333, 4394708, 1817982, 3552214,
            2430515, 7724006, 1212178, 7434454, 4791521, 3612367, 1575197, 2616400,
            7280760, 5879068, 5222561, 2714767, 692618, 4753797, 3241659, 3264410,
            3310630, 1698113, 4588043, 7892279, 3538634, 4686398, 630265, 8140810,
            7757090, 1573829, 1439929, 4620264, 1816267, 8104590, 7795076, 8252416,
            4978848, 96143, 3000802, 1332455, 4095294, 6316391, 4143403, 1517649,
            6873217, 6690299, 5648537, 3212945, 4559682, 3795640, 5742353, 1613630,
            776747, 5495855, 2295413, 2239780, 4770428, 4217872, 6117292, 2180649,
            4182227, 4825006, 1277595, 8009565, 336738, 7029871, 3724652, 3306907,
            2754150, 1771207, 7618123, 5981474, 6918685, 4873435, 6043780, 892340,
            8081767, 3705624, 2204650, 7183503, 7560426, 1871047, 8102832, 1527751,
            2621605, 5397985, 3173115, 3594340, 6255138, 2062072, 2126671, 7196132,
            2330145, 2691596, 2275857, 5107127, 652666, 5342416, 892754, 6115372,
            3626038, 4429510, 6200718, 5470004, 4670446, 4164004, 6903364, 6999551,
            7288311, 1258381, 4867285, 5289093, 7068867, 8285848, 8072801, 4510508,
            7623193, 4922632, 3507815, 5443192, 3509521, 385412, 339297, 7848194,
            7374309, 6096087, 4901675, 3345543, 3909172, 1855658, 1227434, 6841104,
            2021173, 8370509, 5069879, 1797235, 6777709, 5728585, 1717178, 7768072,
            4714532, 384485, 7117636, 6930094, 6777771, 805264, 1542844, 1279820,
            6881770, 7907966, 1933541, 4228822, 7461003, 7993404, 538866, 2584296,
            3117038, 6406703, 7493296, 5960624, 4360112, 598389, 8375663, 323148,
            319201, 5606280, 436879, 7607550, 593596, 8179731, 8106586, 2212550,
            5351274, 2428015, 1813894, 921297, 3622417, 2808466, 928044, 4282264,
            7967454, 5759448, 3431248, 698163, 5154076, 6357901, 6995902, 4094899,
            944757, 1458276, 1100257, 928549, 7426065, 4378445, 4697191, 1562477,
            2736485, 1564641, 6588167, 2529171, 554962, 7137021, 2865064, 2157978,
            223494, 1874515, 1132008, 2079189, 5179721, 819725, 6735432, 1829399,
            5905798, 1778694, 7808445, 2552610, 5616538, 4945603, 7503362, 8092389,
            3440153, 4872756, 1533828, 7681897, 6747200, 7083753, 3724764, 1191386,
            8132929, 2251290, 3941527, 3304550, 4874346, 6771938, 1042043, 3769554,
            3325719, 131704, 7980977, 302673, 2009142, 5157113, 398820, 5234568,
            4580419, 8585, 3014659, 6226791, 7156610, 1850865, 1031502, 6219549,
            3914522, 8115503, 7061015, 4408572, 7105410, 1171271, 4824051, 6483566,
            3645522, 5923924, 2658197, 1035052, 3853517, 3150874, 6972701, 3993458,
            3009215, 3093275, 8365562, 4630916, 3235476, 656575, 6326402, 3186588,
            3734758, 7684912, 7957680, 3215249, 7868211, 5179899, 2410500, 1625735,
            8145687, 4265133, 4128220, 6210387, 2117823, 6222431, 6061247, 6790004,
            6957179, 6459298, 2460580, 6650553, 995306, 7605279, 7543208, 1551234,
            1749052, 7420907, 495559, 8084374, 7219435, 8159498, 6576293, 8132267,
            7100983, 4718449, 1817719, 5593172, 3983415, 2169038, 7744365, 1413134,
            4413991, 430033, 1388259, 2762329, 7201509, 1701209, 1942166, 1084728,
            3001297, 3914696, 1076661, 3860467, 6805396, 5596052, 6017828, 6000610,
            5680797, 7732010, 5220173, 3094127, 5780516, 1421843, 5987001, 6308156,
            3973358, 542677, 6469987, 5957561, 454144, 2161702, 7628606, 6315312,
            2386030, 5907267, 221928, 6389142, 4721961, 5722752, 1953957, 7630670,
            4551394, 649327, 2747378, 8112453, 3885075, 1868399, 2286625, 4458480,
            2471396, 469360, 7727105, 7139762, 5498786, 7193782, 4843433, 2250068,
            2558839, 2402556, 987100, 658765, 3233147, 4349139, 6368083, 7236770,
            6644570, 1213678, 7618524, 3285051, 2537592, 2765030, 7588991, 613524,
            987437, 2773351, 4183459, 6769254, 1609213, 4885485, 1919147, 2798686,
            6451902, 7380454, 6569994, 7415329, 6647125, 1807377, 4772337, 2154767,
            4816424, 6836397, 6654657, 4524719, 7181774, 2921625, 1310140, 3318111,
            1551499, 8225399, 710936, 8010259, 5689030, 7789743, 2947223, 1537625,
            2376411, 3662255, 4223056, 3055241, 7396480, 7191799, 2750994, 1047724,
            1037944, 6561802, 1254999, 8262532, 1513420, 4729297, 5838511, 5456772,
            1253638, 7479153, 1815658, 7525558, 2187008, 8268525, 1856608, 4145676,
            3085342, 8344643, 6602572, 4577023, 2617648, 1718511, 6979083, 966351,
            3771948, 3283295, 4787572, 382141, 1562867, 7827339, 4534956, 2106229,
            2334228, 5041733, 1369143, 5123337, 3202182, 5312150, 7488837, 7710810,
            8221979, 1972255, 1359019, 8139517, 2387326, 3040506, 3627134, 7141535,
            4203458, 3564036, 2312300, 781943, 3107676, 1783797, 197758, 2302495,
            4901901, 7631806, 1104666, 4775556, 6416078, 4441237, 747683
        };

        static final long[] iph_ips_tab = new long[]{
            8384325,
            6266476, 343759, 4032924, 2845640, 7398049, 1858911, 4123353, 572869,
            2889133, 6559137, 5309140, 8057848, 3043279, 5972724, 5509840, 3152195,
            7340730, 1149314, 6297928, 4068203, 4959162, 6886507, 6410434, 3861358,
            2856114, 129667, 1295116, 1697306, 5774085, 7654789, 4702089, 6434642,
            1099008, 407128, 3750793, 7448804, 6014561, 7476384, 6675514, 1711471,
            1632206, 3872648, 783154, 1844275, 2485340, 2761796, 7285494, 5194055,
            4472448, 1169319, 7367037, 5550426, 7968947, 47588, 4283021, 3543566,
            2460375, 2908624, 1677578, 2286722, 5967472, 4784229, 2125281, 7096746,
            2641841, 5859864, 7047271, 6306265, 4927172, 2002702, 5609451, 794111,
            2162628, 1199811, 1023929, 6762658, 2811264, 465830, 4675469, 7436248,
            6577927, 6243993, 183759, 1502862, 2883013, 1213444, 828607, 1948298,
            448752, 962101, 1632492, 708278, 7246842, 1607908, 5691165, 3784264,
            6291090, 4080476, 1708132, 1076473, 822468, 45515, 5236882, 11169,
            7024267, 5445350, 4846184, 3264138, 4311516, 1192665, 5090523, 6895340,
            6307310, 476968, 4930810, 7655223, 7012130, 3958955, 4031791, 2450655,
            1834576, 2472019, 7910071, 2341164, 4242351, 2888899, 743174, 2611252,
            8103899, 4935885, 641134, 159562, 8022733, 408299, 5664951, 2879944,
            3489210, 4527048, 2221815, 5809866, 5507143, 2605143, 6515727, 3936645,
            2604217, 5770060, 465284, 2311546, 3501473, 3972812, 3944233, 2052226,
            7221721, 3480756, 4962594, 2534039, 8329753, 1024954, 7706042, 3994290,
            6172254, 5144344, 6222265, 6540637, 1812198, 7615654, 1934200, 8375093,
            3025773, 5055233, 1024297, 3337559, 4662798, 5392773, 7918804, 3991001,
            537544, 6456869, 4737989, 7496118, 6863802, 2241314, 2132869, 6544755,
            4093502, 470343, 1293326, 5338831, 879120, 7488416, 2858274, 5971673,
            4854126, 1381561, 4712155, 4973542, 3598508, 375442, 2615379, 1234094,
            4459356, 5076961, 3072412, 3028223, 8335150, 4672017, 372318, 2913526,
            4336056, 6394673, 3032922, 3541598, 312878, 4335411, 3833033, 1386482,
            3927723, 8217823, 3910333, 7956495, 7865267, 5401062, 1550401, 1889340,
            3003057, 5533585, 4219508, 7358560, 421608, 7114826, 1734229, 3275308,
            980112, 841774, 3029680, 7084938, 6566845, 6015593, 3170015, 904825,
            1093671, 5794280, 7914770, 5952605, 8288205, 6851992, 1662681, 5476087,
            8076560, 4841142, 4740804, 4797977, 4536800, 8114111, 4445559, 1937246,
            534963, 6565980, 3948470, 7542652, 7938150, 4592983, 5875764, 5691241,
            6822610, 2836410, 255990, 3382896, 4110658, 3320701, 454913, 1974933,
            3806948, 994490, 1455131, 182177, 2843027, 2688912, 1639258, 6664933,
            7577574, 424306, 5711200, 5167984, 1985943, 1599283, 3492929, 3464525,
            4808581, 4235061, 2083363, 3440253, 6339428, 7823779, 3452329, 742286,
            794174, 5344809, 5856320, 2940864, 6381477, 8091244, 5301534, 1697078,
            5064040, 1208843, 7770554, 1410350, 401446, 1317422, 2522599, 424665,
            3032217, 350736, 1836185, 7298499, 2895539, 335467, 7848368, 5526038,
            438638, 3600822, 8392784, 4482533, 4670302, 597874, 360122, 7252224,
            895169, 1251126, 5448989, 143034, 7275569, 569333, 8392281, 2289386,
            3646954, 3570346, 335030, 2985368, 175469, 1416950, 2375922, 5654958,
            4826431, 6518760, 4645343, 5850620, 1999725, 4927694, 752939, 5769129,
            1068014, 2606411, 4123965, 266939, 2496687, 7170092, 6409092, 7718411,
            6793011, 7057615, 476233, 1425337, 6560907, 7061203, 2802738, 6870304,
            2067395, 2962499, 4932800, 507776, 4142936, 1138780, 4532095, 7801745,
            1557179, 1247845, 1018841, 5515589, 965035, 2143473, 6243016, 8385545,
            5052335, 5933845, 7667963, 533718, 6117113, 379528, 78435, 3063642,
            6313528, 7971056, 4514256, 870574, 2476492, 6910111, 5158576, 5864848,
            1040027, 5802062, 7155932, 797581, 7734326, 1391790, 4680275, 4044975,
            3990483, 2389588, 8327206, 2050957, 3159168, 4541710, 3572158, 4208547,
            6437926, 8082115, 2860829, 6150232, 5056037, 4412876, 7930910, 7113463,
            4530555, 2858371, 1665753, 5753280, 3799382, 656530, 6966056, 4906978,
            8197036, 6967687, 438514, 1740097, 4297270, 3644595, 7688577, 7148931,
            7785627, 7911363, 3563088, 4347742, 5112581, 3999183, 1171855, 2583513,
            6616007, 7753887, 2847652, 7765644, 5952303, 638458, 673237, 3146571,
            1032944, 4645844, 3540130, 6210562, 7364283, 6927111, 1329961, 1500787,
            7738230, 868536, 2396567, 2229111, 3316327, 1652590, 5274179, 7598204,
            1043650, 7094781, 3047303, 6707914, 5291631, 4587398, 7541466, 1664190,
            3650535, 2741611, 4328719, 4816080, 788559, 6695900, 7616639, 5259767,
            6067955, 7648508, 2430813, 2194687, 5966722, 5323947, 3924650, 1486315,
            5578759, 2238148, 309562, 939049, 1949198, 1482089, 3845854, 5003012,
            7269968, 8230904, 4650163, 364834, 2314837, 5234827, 7877791, 7089864,
            4434016, 5493648, 2566677, 1518171, 2893640, 6476069, 4369197, 1776238,
            5924956, 7744146, 712877, 4206251, 5333345, 2742539, 1173030, 5099952,
            4077162, 2815407, 4410142, 3914007, 2219559, 2323102, 3657731, 2001033,
            153749, 573397, 6745288, 5561341, 6165846, 6864377, 6870526, 6076515,
            2160926, 1281532, 7169322, 3937405, 7772698, 4843232, 4245389, 2249200,
            223351, 3740163, 8038213, 3052708, 3154546, 2017937, 7085369, 6323927,
            4118643, 1608900, 3766979, 2928404, 4589601, 5149255, 8134627, 507384,
            3954349, 3917142, 5678933, 2702433, 1390054, 3845104, 5542730, 664344,
            2620473, 7587081, 5148111, 3982121, 8272604, 4899817, 7903828, 1589061,
            6680049, 5844370, 6497375, 5914114, 1627641, 7830131, 1705355, 5293787,
            1422130, 665468, 3761574, 6481772, 7863295, 2651284, 947173, 6457924,
            5995984, 2891774, 7079248, 2928912, 5434351, 2406377, 4246992, 1969762,
            4771286, 1151663, 4876491, 4786754, 1989229, 4681034, 2759141, 454903,
            4671727, 2934407, 2824816, 6985552, 7082015, 1408392, 3962148, 3616750,
            2847728, 2398997, 2497623, 5218965, 2348001, 6180756, 3531177, 5055242,
            278181, 1601348, 1334506, 2936892, 5070947, 1079676, 6115626, 7080284,
            7629817, 1693677, 7780441, 4515899, 6613946, 2109598, 5405300, 5090149,
            5214521, 5613250, 3372215, 3324729, 1792384, 3786739, 2829022, 5707052,
            2572069, 6513631, 7731135, 6310468, 1095713, 6476486, 6220792, 5381725,
            202303, 3219902, 440393, 993083, 6031359, 2650054, 4858108, 8400290,
            4191271, 2329124, 6855029, 2973660, 2347512, 1893096, 5410385, 3784259,
            7639487, 7846702, 2623295, 8044180, 4272387, 3530694, 5873500, 999915,
            913168, 7058558, 1680346, 7220517, 7104021, 7492568, 6056470, 3474000,
            4714138, 3075848, 7683029, 3879491, 7827477, 1329079, 7380211, 1382055,
            7651418, 7733101, 3954328, 2856415, 1325099, 4865119, 7120443, 4886775,
            6732493, 1657141, 3411209, 3773447, 1837593, 771593, 3036414, 8223345,
            7467443, 7327037, 715414, 5877042, 602685, 4025445, 898554, 4530594,
            2426866, 2547165, 5339003, 1562224, 2324138, 8358636, 6665352, 5527813,
            842304, 2984479, 2899653, 2014490, 7078035, 7298293, 1295543, 852107,
            1847120, 101810, 3052417, 7667313, 7725468, 8236899, 1680816, 6546094,
            6088483, 5517176, 6681466, 6976341, 4902039, 2068707, 7195828, 6783273,
            7475799, 4743096, 5300277, 7846361, 3810046, 984013, 6170554
        };

        static final int[] t_tab = new int[]{
            1, 125596, 6588348, 6999551, 3769554, 4458480, 1405441, 4509843, 5763158
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

        static void poly_pointwise(int[] result, int[] x, int[] y)
        { // Pointwise polynomial multiplication result = x.y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = (int)MODQ((long)x[i] * (long)y[i]);
            }
        }

        static void poly_mul(int[] result, int[] x, int[] y)
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


        static void poly_add(int[] result, int[] x, int[] y)
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


        static int lE24BitToInt(byte[] bs, int off)
        {
            int n = bs[off] & 0xff;
            n |= (bs[++off] & 0xff) << 8;
            n |= (bs[++off] & 0xff) << 16;
            return n;
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
                val1 = lE24BitToInt(buf, pos) & mask;
                pos += nbytes;
                val2 = lE24BitToInt(buf, pos) & mask;
                pos += nbytes;
                val3 = lE24BitToInt(buf, pos) & mask;
                pos += nbytes;
                val4 = lE24BitToInt(buf, pos) & mask;
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
