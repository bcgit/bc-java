package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class QTesla1p
{
    private static final int PARAM_N = 1024;
//    private static final int PARAM_N_LOG = 10;
//    private static final double PARAM_SIGMA = 8.5;
    private static final int PARAM_Q = 343576577;
    private static final int PARAM_Q_LOG = 29;
    private static final long PARAM_QINV = 2205847551L;
    private static final int PARAM_BARR_MULT = 3;
    private static final int PARAM_BARR_DIV = 30;
    private static final int PARAM_B = 524287;
    private static final int PARAM_B_BITS = 19;
    private static final int PARAM_S_BITS = 8;
    private static final int PARAM_K = 4;
//    private static final double PARAM_SIGMA_E = PARAM_SIGMA;
    private static final int PARAM_H = 25;
    private static final int PARAM_D = 22;
    private static final int PARAM_GEN_A = 108;
    private static final int PARAM_KEYGEN_BOUND_E = 554;
    private static final int PARAM_E = PARAM_KEYGEN_BOUND_E;
    private static final int PARAM_KEYGEN_BOUND_S = 554;
    private static final int PARAM_S = PARAM_KEYGEN_BOUND_S;
    private static final int PARAM_R2_INVN = 13632409;
//    private static final int PARAM_R = 172048372;

    private static final int CRYPTO_RANDOMBYTES = 32;
    private static final int CRYPTO_SEEDBYTES = 32;
    private static final int CRYPTO_C_BYTES = 32;
    private static final int HM_BYTES = 40;

//    private static final int RADIX = 32;
    private static final int RADIX32 = 32;


    // Contains signature (z,c). z is a polynomial bounded by B, c is the output of a hashed string
    static final int CRYPTO_BYTES = (PARAM_N * (PARAM_B_BITS + 1) + 7) / 8 + CRYPTO_C_BYTES;
    // Contains polynomial s and e, and seeds seed_a and seed_y
    static final int CRYPTO_SECRETKEYBYTES = (PARAM_K + 1) * PARAM_S_BITS * PARAM_N / 8 + 2 * CRYPTO_SEEDBYTES + HM_BYTES;
    // Contains seed_a and polynomials t
    static final int CRYPTO_PUBLICKEYBYTES = (PARAM_K * PARAM_Q_LOG * PARAM_N + 7) / 8 + CRYPTO_SEEDBYTES;


    static int generateKeyPair(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {
        /* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
        int nonce = 0;

        byte[] randomness = new byte[CRYPTO_RANDOMBYTES];

        /* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
        byte[] randomnessExtended = new byte[(PARAM_K + 3) * CRYPTO_SEEDBYTES];

        int[] secretPolynomial = new int[PARAM_N];
        int[] errorPolynomial = new int[PARAM_N * PARAM_K];
        int[] A = new int[PARAM_N * PARAM_K];
        int[] T = new int[PARAM_N * PARAM_K];

        int[] s_ntt = new int[PARAM_N];

        /* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
        // this.rng.randomByte (randomness, (short) 0, Polynomial.RANDOM);
        secureRandom.nextBytes(randomness);

        HashUtils.secureHashAlgorithmKECCAK128(
            randomnessExtended, 0, (PARAM_K + 3) * CRYPTO_SEEDBYTES,
            randomness, 0, CRYPTO_RANDOMBYTES);

        /*
         * Sample the Error Polynomial Fulfilling the Criteria
         * Choose All Error Polynomial in R with Entries from D_SIGMA
         * Repeat Step at Iteration if the h Largest Entries of Error Polynomial Summation to L_E
         */
        for (int k = 0; k < PARAM_K; k++)
        {
            do
            {
                Gaussian.sample_gauss_poly(++nonce, randomnessExtended, k * CRYPTO_SEEDBYTES, errorPolynomial, k * PARAM_N);
            }
            while (checkPolynomial(errorPolynomial, k * PARAM_N, PARAM_KEYGEN_BOUND_E));
        }

        /*
         * Sample the Secret Polynomial Fulfilling the Criteria
         * Choose Secret Polynomial in R with Entries from D_SIGMA
         * Repeat Step if the h Largest Entries of Secret Polynomial Summation to L_S
         */
        do
        {
            Gaussian.sample_gauss_poly(++nonce, randomnessExtended, PARAM_K * CRYPTO_SEEDBYTES, secretPolynomial, 0);
        }
        while (checkPolynomial(secretPolynomial, 0, PARAM_KEYGEN_BOUND_S));

        QTesla1PPolynomial.poly_uniform(A, randomnessExtended, (PARAM_K + 1) * CRYPTO_SEEDBYTES);
        QTesla1PPolynomial.poly_ntt(s_ntt, secretPolynomial);

        for (int k = 0; k < PARAM_K; k++)
        {
            QTesla1PPolynomial.poly_mul(T, k * PARAM_N, A, k * PARAM_N, s_ntt);
            QTesla1PPolynomial.poly_add_correct(T, k * PARAM_N, T, k * PARAM_N, errorPolynomial, k * PARAM_N);
        }

        /* Pack Public and Private Keys */
        encodePublicKey(publicKey, T, randomnessExtended, (PARAM_K + 1) * CRYPTO_SEEDBYTES);
        encodePrivateKey(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, (PARAM_K + 1) * CRYPTO_SEEDBYTES, publicKey);

        return 0;
    }

    static int generateSignature(byte[] signature, byte[] message, int messageOffset, int messageLength,
        byte[] privateKey, SecureRandom secureRandom)
    {
        byte[] c = new byte[CRYPTO_C_BYTES];
        byte[] randomness = new byte[CRYPTO_SEEDBYTES];
        byte[] randomness_input = new byte[CRYPTO_SEEDBYTES + CRYPTO_RANDOMBYTES + 2 * HM_BYTES];
        int[] pos_list = new int[PARAM_H];
        short[] sign_list = new short[PARAM_H];
        int[] y = new int[PARAM_N];

        int[] y_ntt = new int[PARAM_N];
        int[] Sc = new int[PARAM_N];
        int[] z = new int[PARAM_N];

        int[] v = new int[PARAM_N * PARAM_K];
        int[] Ec = new int[PARAM_N * PARAM_K];
        int[] a = new int[PARAM_N * PARAM_K];

        int k;
        int nonce = 0;  // Initialize domain separator for sampling y
        boolean rsp = false;

        System.arraycopy(privateKey, CRYPTO_SECRETKEYBYTES - HM_BYTES - CRYPTO_SEEDBYTES, randomness_input, 0, CRYPTO_SEEDBYTES);

        {
            byte[] tmp = new byte[CRYPTO_RANDOMBYTES];
            secureRandom.nextBytes(tmp);
            System.arraycopy(tmp, 0, randomness_input, CRYPTO_SEEDBYTES, CRYPTO_RANDOMBYTES);
        }

        HashUtils.secureHashAlgorithmKECCAK128(
            randomness_input, CRYPTO_SEEDBYTES + CRYPTO_RANDOMBYTES, HM_BYTES,
            message, 0, messageLength);

        HashUtils.secureHashAlgorithmKECCAK128(
            randomness, 0, CRYPTO_SEEDBYTES,
            randomness_input, 0, randomness_input.length - HM_BYTES);

        System.arraycopy(privateKey, CRYPTO_SECRETKEYBYTES - HM_BYTES, randomness_input, randomness_input.length - HM_BYTES, HM_BYTES);

        QTesla1PPolynomial.poly_uniform(a, privateKey, CRYPTO_SECRETKEYBYTES - HM_BYTES - 2 * CRYPTO_SEEDBYTES);

        while (true)
        {
            sample_y(y, randomness, 0, ++nonce);

            QTesla1PPolynomial.poly_ntt(y_ntt, y);
            for (k = 0; k < PARAM_K; k++)
            {
                QTesla1PPolynomial.poly_mul(v, k * PARAM_N, a, k * PARAM_N, y_ntt);
            }

            hashFunction(c, 0, v, randomness_input, CRYPTO_SEEDBYTES + CRYPTO_RANDOMBYTES);
            encodeC(pos_list, sign_list, c, 0);

            QTesla1PPolynomial.sparse_mul8(Sc, 0, privateKey, 0, pos_list, sign_list);

            QTesla1PPolynomial.poly_add(z, y, Sc);

            if (testRejection(z))
            {
                continue;
            }

            for (k = 0; k < PARAM_K; k++)
            {
                QTesla1PPolynomial.sparse_mul8(Ec, k * PARAM_N, privateKey, (PARAM_N * (k + 1)), pos_list, sign_list);
                QTesla1PPolynomial.poly_sub(v, k * PARAM_N, v, k * PARAM_N, Ec, k * PARAM_N);
                rsp = test_correctness(v, k * PARAM_N);
                if (rsp)
                {
                    break;
                } // TODO replace with contine outer
            }
            if (rsp)
            {
                continue;
            }

            encodeSignature(signature, 0, c, 0, z);
            return 0;
        }
    }

    static int verifying(byte[] message, final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey)
    {
        byte c[] = new byte[CRYPTO_C_BYTES];
        byte c_sig[] = new byte[CRYPTO_C_BYTES];
        byte seed[] = new byte[CRYPTO_SEEDBYTES];
        byte hm[] = new byte[2 * HM_BYTES];
        int pos_list[] = new int[PARAM_H];
        short sign_list[] = new short[PARAM_H];
        int pk_t[] = new int[PARAM_N * PARAM_K];
        int[] w = new int[PARAM_N * PARAM_K];
        int[] a = new int[PARAM_N * PARAM_K];
        int[] Tc = new int[PARAM_N * PARAM_K];

        int[] z = new int[PARAM_N];
        int[] z_ntt = new int[PARAM_N];

        int k = 0;

        if (signatureLength != CRYPTO_BYTES)
        {
            return -1;
        }

        decodeSignature(c, z, signature, signatureOffset);
        if (testZ(z))
        {
            return -2;
        }
        decodePublicKey(pk_t, seed, 0, publicKey);

        // Get H(m) and hash_pk
        HashUtils.secureHashAlgorithmKECCAK128(
            hm, 0, HM_BYTES,
            message, 0, message.length);
        HashUtils.secureHashAlgorithmKECCAK128(
            hm, HM_BYTES, HM_BYTES,
            publicKey, 0, CRYPTO_PUBLICKEYBYTES - CRYPTO_SEEDBYTES);

        QTesla1PPolynomial.poly_uniform(a, seed, 0);
        encodeC(pos_list, sign_list, c, 0);
        QTesla1PPolynomial.poly_ntt(z_ntt, z);

        for (k = 0; k < PARAM_K; k++)
        {      // Compute w = az - tc
            QTesla1PPolynomial.sparse_mul32(Tc, k * PARAM_N, pk_t, (k * PARAM_N), pos_list, sign_list);
            QTesla1PPolynomial.poly_mul(w, k * PARAM_N, a, k * PARAM_N, z_ntt);
            QTesla1PPolynomial.poly_sub_reduce(w, k * PARAM_N, w, k * PARAM_N, Tc, k * PARAM_N);
        }
        hashFunction(c_sig, 0, w, hm, 0);

        if (!memoryEqual(c, 0, c_sig, 0, CRYPTO_C_BYTES))
        {
            return -3;
        }

        return 0;
    }

    static void encodePrivateKey(byte[] privateKey, int[] secretPolynomial, int[] errorPolynomial,
        byte[] seed, int seedOffset, byte[] publicKey)
    {
        int i, k = 0;
        int skPtr = 0;

        for (i = 0; i < PARAM_N; i++)
        {
            privateKey[skPtr + i] = (byte)secretPolynomial[i];
        }
        skPtr += PARAM_N;

        for (k = 0; k < PARAM_K; k++)
        {
            for (i = 0; i < PARAM_N; i++)
            {
                privateKey[skPtr + (k * PARAM_N + i)] = (byte)errorPolynomial[k * PARAM_N + i];
            }
        }
        skPtr += PARAM_K * PARAM_N;

        System.arraycopy(seed, seedOffset, privateKey, skPtr, CRYPTO_SEEDBYTES * 2);
        skPtr += CRYPTO_SEEDBYTES * 2;

        /* Hash of the public key */
        HashUtils.secureHashAlgorithmKECCAK128(
            privateKey, skPtr, HM_BYTES,
            publicKey, 0, CRYPTO_PUBLICKEYBYTES - CRYPTO_SEEDBYTES);
        skPtr += HM_BYTES;

//        assert CRYPTO_SECRETKEYBYTES == skPtr;
    }

    static void encodePublicKey(byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset)
    {
        int j = 0;

        for (int i = 0; i < (PARAM_N * PARAM_K * PARAM_Q_LOG / 32); i += PARAM_Q_LOG)
        {
            at(publicKey, i, 0, T[j] | (T[j + 1] << 29));
            at(publicKey, i, 1, (T[j + 1] >> 3) | (T[j + 2] << 26));
            at(publicKey, i, 2, (T[j + 2] >> 6) | (T[j + 3] << 23));
            at(publicKey, i, 3, (T[j + 3] >> 9) | (T[j + 4] << 20));
            at(publicKey, i, 4, (T[j + 4] >> 12) | (T[j + 5] << 17));
            at(publicKey, i, 5, (T[j + 5] >> 15) | (T[j + 6] << 14));
            at(publicKey, i, 6, (T[j + 6] >> 18) | (T[j + 7] << 11));
            at(publicKey, i, 7, (T[j + 7] >> 21) | (T[j + 8] << 8));
            at(publicKey, i, 8, (T[j + 8] >> 24) | (T[j + 9] << 5));
            at(publicKey, i, 9, (T[j + 9] >> 27) | (T[j + 10] << 2) | (T[j + 11] << 31));
            at(publicKey, i, 10, (T[j + 11] >> 1) | (T[j + 12] << 28));
            at(publicKey, i, 11, (T[j + 12] >> 4) | (T[j + 13] << 25));
            at(publicKey, i, 12, (T[j + 13] >> 7) | (T[j + 14] << 22));
            at(publicKey, i, 13, (T[j + 14] >> 10) | (T[j + 15] << 19));
            at(publicKey, i, 14, (T[j + 15] >> 13) | (T[j + 16] << 16));
            at(publicKey, i, 15, (T[j + 16] >> 16) | (T[j + 17] << 13));
            at(publicKey, i, 16, (T[j + 17] >> 19) | (T[j + 18] << 10));
            at(publicKey, i, 17, (T[j + 18] >> 22) | (T[j + 19] << 7));
            at(publicKey, i, 18, (T[j + 19] >> 25) | (T[j + 20] << 4));
            at(publicKey, i, 19, (T[j + 20] >> 28) | (T[j + 21] << 1) | (T[j + 22] << 30));
            at(publicKey, i, 20, (T[j + 22] >> 2) | (T[j + 23] << 27));
            at(publicKey, i, 21, (T[j + 23] >> 5) | (T[j + 24] << 24));
            at(publicKey, i, 22, (T[j + 24] >> 8) | (T[j + 25] << 21));
            at(publicKey, i, 23, (T[j + 25] >> 11) | (T[j + 26] << 18));
            at(publicKey, i, 24, (T[j + 26] >> 14) | (T[j + 27] << 15));
            at(publicKey, i, 25, (T[j + 27] >> 17) | (T[j + 28] << 12));
            at(publicKey, i, 26, (T[j + 28] >> 20) | (T[j + 29] << 9));
            at(publicKey, i, 27, (T[j + 29] >> 23) | (T[j + 30] << 6));
            at(publicKey, i, 28, (T[j + 30] >> 26) | (T[j + 31] << 3));
            j += 32;
        }

        System.arraycopy(seedA, seedAOffset, publicKey, PARAM_N * PARAM_K * PARAM_Q_LOG / 8, CRYPTO_SEEDBYTES);
    }

    static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;
        byte[] pt = publicKeyInput;
        int mask29 = (1 << PARAM_Q_LOG) - 1;


        for (int i = 0; i < PARAM_N * PARAM_K; i += 32)
        {
            publicKey[i] = at(pt, j, 0) & mask29;
            publicKey[i + 1] = ((at(pt, j, 0) >>> 29) | (at(pt, j, 1) << 3)) & mask29;
            publicKey[i + 2] = ((at(pt, j, 1) >>> 26) | (at(pt, j, 2) << 6)) & mask29;
            publicKey[i + 3] = ((at(pt, j, 2) >>> 23) | (at(pt, j, 3) << 9)) & mask29;
            publicKey[i + 4] = ((at(pt, j, 3) >>> 20) | (at(pt, j, 4) << 12)) & mask29;
            publicKey[i + 5] = ((at(pt, j, 4) >>> 17) | (at(pt, j, 5) << 15)) & mask29;
            publicKey[i + 6] = ((at(pt, j, 5) >>> 14) | (at(pt, j, 6) << 18)) & mask29;
            publicKey[i + 7] = ((at(pt, j, 6) >>> 11) | (at(pt, j, 7) << 21)) & mask29;
            publicKey[i + 8] = ((at(pt, j, 7) >>> 8) | (at(pt, j, 8) << 24)) & mask29;
            publicKey[i + 9] = ((at(pt, j, 8) >>> 5) | (at(pt, j, 9) << 27)) & mask29;
            publicKey[i + 10] = (at(pt, j, 9) >>> 2) & mask29;
            publicKey[i + 11] = ((at(pt, j, 9) >>> 31) | (at(pt, j, 10) << 1)) & mask29;
            publicKey[i + 12] = ((at(pt, j, 10) >>> 28) | (at(pt, j, 11) << 4)) & mask29;
            publicKey[i + 13] = ((at(pt, j, 11) >>> 25) | (at(pt, j, 12) << 7)) & mask29;
            publicKey[i + 14] = ((at(pt, j, 12) >>> 22) | (at(pt, j, 13) << 10)) & mask29;
            publicKey[i + 15] = ((at(pt, j, 13) >>> 19) | (at(pt, j, 14) << 13)) & mask29;
            publicKey[i + 16] = ((at(pt, j, 14) >>> 16) | (at(pt, j, 15) << 16)) & mask29;
            publicKey[i + 17] = ((at(pt, j, 15) >>> 13) | (at(pt, j, 16) << 19)) & mask29;
            publicKey[i + 18] = ((at(pt, j, 16) >>> 10) | (at(pt, j, 17) << 22)) & mask29;
            publicKey[i + 19] = ((at(pt, j, 17) >>> 7) | (at(pt, j, 18) << 25)) & mask29;
            publicKey[i + 20] = ((at(pt, j, 18) >>> 4) | (at(pt, j, 19) << 28)) & mask29;
            publicKey[i + 21] = (at(pt, j, 19) >>> 1) & mask29;
            publicKey[i + 22] = ((at(pt, j, 19) >>> 30) | (at(pt, j, 20) << 2)) & mask29;
            publicKey[i + 23] = ((at(pt, j, 20) >>> 27) | (at(pt, j, 21) << 5)) & mask29;
            publicKey[i + 24] = ((at(pt, j, 21) >>> 24) | (at(pt, j, 22) << 8)) & mask29;
            publicKey[i + 25] = ((at(pt, j, 22) >>> 21) | (at(pt, j, 23) << 11)) & mask29;
            publicKey[i + 26] = ((at(pt, j, 23) >>> 18) | (at(pt, j, 24) << 14)) & mask29;
            publicKey[i + 27] = ((at(pt, j, 24) >>> 15) | (at(pt, j, 25) << 17)) & mask29;
            publicKey[i + 28] = ((at(pt, j, 25) >>> 12) | (at(pt, j, 26) << 20)) & mask29;
            publicKey[i + 29] = ((at(pt, j, 26) >>> 9) | (at(pt, j, 27) << 23)) & mask29;
            publicKey[i + 30] = ((at(pt, j, 27) >>> 6) | (at(pt, j, 28) << 26)) & mask29;
            publicKey[i + 31] = at(pt, j, 28) >>> 3;
            j += 29;
        }


        System.arraycopy(publicKeyInput, PARAM_N * PARAM_K * PARAM_Q_LOG / 8, seedA, seedAOffset, CRYPTO_SEEDBYTES);

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

    private static final int maskb1 = ((1 << (PARAM_B_BITS + 1)) - 1);

    static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z)
    {
        int j = 0;

        for (int i = 0; i < (PARAM_N * (PARAM_B_BITS + 1) / 32); i += 10)
        {
            at(signature, i, 0, (Z[j] & ((1 << 20) - 1)) | (Z[j + 1] << 20));
            at(signature, i, 1, ((Z[j + 1] >>> 12) & ((1 << 8) - 1)) | ((Z[j + 2] & maskb1) << 8) | (Z[j + 3] << 28));
            at(signature, i, 2, ((Z[j + 3] >>> 4) & ((1 << 16) - 1)) | (Z[j + 4] << 16));
            at(signature, i, 3, ((Z[j + 4] >>> 16) & ((1 << 4) - 1)) | ((Z[j + 5] & maskb1) << 4) | (Z[j + 6] << 24));
            at(signature, i, 4, ((Z[j + 6] >>> 8) & ((1 << 12) - 1)) | (Z[j + 7] << 12));
            at(signature, i, 5, (Z[j + 8] & ((1 << 20) - 1)) | (Z[j + 9] << 20));
            at(signature, i, 6, ((Z[j + 9] >>> 12) & ((1 << 8) - 1)) | ((Z[j + 10] & maskb1) << 8) | (Z[j + 11] << 28));
            at(signature, i, 7, ((Z[j + 11] >>> 4) & ((1 << 16) - 1)) | (Z[j + 12] << 16));
            at(signature, i, 8, ((Z[j + 12] >>> 16) & ((1 << 4) - 1)) | ((Z[j + 13] & maskb1) << 4) | (Z[j + 14] << 24));
            at(signature, i, 9, ((Z[j + 14] >>> 8) & ((1 << 12) - 1)) | (Z[j + 15] << 12));
            j += 16;
        }

        System.arraycopy(C, cOffset, signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, CRYPTO_C_BYTES);
    }

    static void decodeSignature(byte[] C, int[] Z, final byte[] signature, int signatureOffset)
    {
        int j = 0;
        for (int i = 0; i < PARAM_N; i += 16)
        {
            int s0 = at(signature, j, 0);
            int s1 = at(signature, j, 1);
            int s2 = at(signature, j, 2);
            int s3 = at(signature, j, 3);
            int s4 = at(signature, j, 4);
            int s5 = at(signature, j, 5);
            int s6 = at(signature, j, 6);
            int s7 = at(signature, j, 7);
            int s8 = at(signature, j, 8);
            int s9 = at(signature, j, 9);

            Z[i] = (s0 << 12) >> 12;
            Z[i + 1] = (s0 >>> 20) | ((s1 << 24) >> 12);
            Z[i + 2] = ((s1 << 4) >> 12);
            Z[i + 3] = (s1 >>> 28) | ((s2 << 16) >> 12);
            Z[i + 4] = (s2 >>> 16) | ((s3 << 28) >> 12);
            Z[i + 5] = (s3 << 8) >> 12;
            Z[i + 6] = (s3 >>> 24) | ((s4 << 20) >> 12);
            Z[i + 7] = s4 >> 12;
            Z[i + 8] = (s5 << 12) >> 12;
            Z[i + 9] = (s5 >>> 20) | ((s6 << 24) >> 12);
            Z[i + 10] = (s6 << 4) >> 12;
            Z[i + 11] = (s6 >>> 28) | ((s7 << 16) >> 12);
            Z[i + 12] = (s7 >>> 16) | ((s8 << 28) >> 12);
            Z[i + 13] = (s8 << 8) >> 12;
            Z[i + 14] = (s8 >>> 24) | ((s9 << 20) >> 12);
            Z[i + 15] = (s9 >> 12);
            j += 10;
        }
        System.arraycopy(signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, C, 0, CRYPTO_C_BYTES);
    }

    static void encodeC(int[] positionList, short[] signList, byte[] output, int outputOffset)
    {
        int count = 0;
        int position;
        short domainSeparator = 0;
        short[] C = new short[PARAM_N];
        byte[] randomness = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE];

        // Enc: the XOF is instantiated with cSHAKE128 (see Algorithm 14).
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
                // Enc: the XOF is instantiated with cSHAKE128 (see Algorithm 14).
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

    private static void hashFunction(byte[] output, int outputOffset, int[] v, byte[] message, int messageOffset)
    {
        int mask;
        int cL;

        byte[] T = new byte[PARAM_K * PARAM_N + 2 * HM_BYTES];

        for (int k = 0; k < PARAM_K; k++)
        {
            int index = k * PARAM_N;
            for (int i = 0; i < PARAM_N; i++)
            {
                int temp = v[index];
                // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
                mask = (PARAM_Q / 2 - temp) >> (RADIX32 - 1);
                temp = ((temp - PARAM_Q) & mask) | (temp & ~mask);

                cL = temp & ((1 << PARAM_D) - 1);
                // If cL > 2^(d-1) then cL -= 2^d
                mask = ((1 << (PARAM_D - 1)) - cL) >> (RADIX32 - 1);
                cL = ((cL - (1 << PARAM_D)) & mask) | (cL & ~mask);
                T[index++] = (byte)((temp - cL) >> PARAM_D);
            }
        }
        System.arraycopy(message, messageOffset, T, PARAM_N * PARAM_K, 2 * HM_BYTES);

        HashUtils.secureHashAlgorithmKECCAK128(
            output, outputOffset, CRYPTO_C_BYTES,
            T, 0, T.length);
    }

    static int littleEndianToInt24(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        return n;
    }

    private static int NBLOCKS_SHAKE = HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE / (((PARAM_B_BITS + 1) + 7) / 8);
    private static int BPLUS1BYTES = ((PARAM_B_BITS + 1) + 7) / 8;

    static void sample_y(int[] y, byte[] seed, int seedOffset, int nonce)
    { // Sample polynomial y, such that each coefficient is in the range [-B,B]
        int i = 0, pos = 0, nblocks = PARAM_N;
        byte buf[] = new byte[PARAM_N * BPLUS1BYTES+1];
        int nbytes = BPLUS1BYTES;
        short dmsp = (short)(nonce << 8);

        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
            buf, 0, PARAM_N * nbytes, dmsp++, seed, seedOffset, CRYPTO_RANDOMBYTES
        );

        while (i < PARAM_N)
        {
            if (pos >= nblocks * nbytes)
            {
                nblocks = NBLOCKS_SHAKE;
                HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                    buf, 0, PARAM_N * nbytes, dmsp++, seed, seedOffset, CRYPTO_RANDOMBYTES
                );
                pos = 0;
            }
            y[i] = littleEndianToInt24(buf, pos) & ((1 << (PARAM_B_BITS + 1)) - 1);
            y[i] -= PARAM_B;
            if (y[i] != (1 << PARAM_B_BITS))
            {
                i++;
            }
            pos += nbytes;
        }
    }

    private static void at(byte[] bs, int base, int index, int value)
    {
        Pack.intToLittleEndian(value, bs, (base + index) << 2);
    }

    private static int at(byte[] bs, int base, int index)
    {
        return Pack.littleEndianToInt(bs, (base + index) << 2);
    }

    static boolean test_correctness(int[] v, int vpos)
    { // Check bounds for w = v - ec during signature verification. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
        // This function leaks the position of the coefficient that fails the test (but this is independent of the secret data).
        // It does not leak the sign of the coefficients.
        int mask, left, val;
        int t0, t1;

        for (int i = 0; i < PARAM_N; i++)
        {
            // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
            int a = v[vpos + i];
            mask = (PARAM_Q / 2 - a) >> (RADIX32 - 1);
            val =  ((a - PARAM_Q) & mask) | (a & ~mask);
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

    private static boolean testRejection(int[] Z)
    {
        int valid = 0;

        for (int i = 0; i < PARAM_N; i++)
        {
            valid |= (PARAM_B - PARAM_S) - absolute(Z[i]);
        }

        return (valid >>> 31) != 0;
    }

    private static int absolute(int value)
    {
        int sign = value >> (RADIX32 - 1);
        return (sign ^ value) - sign;
    }

    private static boolean checkPolynomial(int[] polynomial, int polyOffset, int bound)
    {
        int i, j, sum = 0, limit = PARAM_N;
        int temp, mask;
        int[] list = new int[PARAM_N];

        for (j = 0; j < PARAM_N; j++)
        {
            list[j] = absolute(polynomial[polyOffset + j]);
        }

        for (j = 0; j < PARAM_H; j++)
        {
            for (i = 0; i < limit - 1; i++)
            {
                int a = list[i], b = list[i + 1];
                // If list[i+1] > list[i] then exchange contents
                mask = (b - a) >> (RADIX32 - 1);
                temp = (b & mask) | (a & ~mask);
                list[i + 1] = (a & mask) | (b & ~mask);
                list[i] = temp;
            }
            sum += list[limit - 1];
            limit -= 1;
        }

        return sum > bound;
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

    // End of outer.

    static class Gaussian
    {
        private static final int CDT_ROWS = 78;
        private static final int CDT_COLS = 2;
        private static final int CHUNK_SIZE = 512;

        private static final int[] cdt_v = new int[]{
            0x00000000, 0x00000000, // 0
            0x0601F22A, 0x280663D4, // 1
            0x11F09FFA, 0x162FE23D, // 2
            0x1DA089E9, 0x437226E8, // 3
            0x28EAB25D, 0x04C51FE2, // 4
            0x33AC2F26, 0x14FDBA70, // 5
            0x3DC767DC, 0x4565C960, // 6
            0x4724FC62, 0x3342C78A, // 7
            0x4FB448F4, 0x5229D06D, // 8
            0x576B8599, 0x7423407F, // 9
            0x5E4786DA, 0x3210BAF7, // 10
            0x644B2C92, 0x431B3947, // 11
            0x697E90CE, 0x77C362C4, // 12
            0x6DEE0B96, 0x2798C9CE, // 13
            0x71A92144, 0x5765FCE4, // 14
            0x74C16FD5, 0x1E2A0990, // 15
            0x7749AC92, 0x0DF36EEB, // 16
            0x7954BFA4, 0x28079289, // 17
            0x7AF5067A, 0x2EDC2050, // 18
            0x7C3BC17C, 0x123D5E7B, // 19
            0x7D38AD76, 0x2A9381D9, // 20
            0x7DF9C5DF, 0x0E868CA7, // 21
            0x7E8B2ABA, 0x18E5C811, // 22
            0x7EF7237C, 0x00908272, // 23
            0x7F4637C5, 0x6DBA5126, // 24
            0x7F7F5707, 0x4A52EDEB, // 25
            0x7FA808CC, 0x23290599, // 26
            0x7FC4A083, 0x69BDF2D5, // 27
            0x7FD870CA, 0x42275558, // 28
            0x7FE5FB5D, 0x3EF82C1B, // 29
            0x7FEF1BFA, 0x6C03A362, // 30
            0x7FF52D4E, 0x316C2C8C, // 31
            0x7FF927BA, 0x12AE54AF, // 32
            0x7FFBBA43, 0x749CC0E2, // 33
            0x7FFD5E3D, 0x4524AD91, // 34
            0x7FFE6664, 0x535785B5, // 35
            0x7FFF0A41, 0x0B291681, // 36
            0x7FFF6E81, 0x132C3D6F, // 37
            0x7FFFAAFE, 0x4DBC6BED, // 38
            0x7FFFCEFD, 0x7A1E2D14, // 39
            0x7FFFE41E, 0x4C6EC115, // 40
            0x7FFFF059, 0x319503C8, // 41
            0x7FFFF754, 0x5DDD0D40, // 42
            0x7FFFFB43, 0x0B9E9823, // 43
            0x7FFFFD71, 0x76B81AE1, // 44
            0x7FFFFEA3, 0x7E66A1EC, // 45
            0x7FFFFF49, 0x26F6E191, // 46
            0x7FFFFFA1, 0x2FA31694, // 47
            0x7FFFFFCF, 0x5247BEC9, // 48
            0x7FFFFFE7, 0x4F4127C7, // 49
            0x7FFFFFF3, 0x6FAA69FD, // 50
            0x7FFFFFFA, 0x0630D073, // 51
            0x7FFFFFFD, 0x0F2957BB, // 52
            0x7FFFFFFE, 0x4FD29432, // 53
            0x7FFFFFFF, 0x2CFAD60D, // 54
            0x7FFFFFFF, 0x5967A930, // 55
            0x7FFFFFFF, 0x6E4C9DFF, // 56
            0x7FFFFFFF, 0x77FDCCC8, // 57
            0x7FFFFFFF, 0x7C6CE89E, // 58
            0x7FFFFFFF, 0x7E6D116F, // 59
            0x7FFFFFFF, 0x7F50FA31, // 60
            0x7FFFFFFF, 0x7FB50089, // 61
            0x7FFFFFFF, 0x7FE04C2D, // 62
            0x7FFFFFFF, 0x7FF2C7C1, // 63
            0x7FFFFFFF, 0x7FFA8FE3, // 64
            0x7FFFFFFF, 0x7FFDCB1B, // 65
            0x7FFFFFFF, 0x7FFF1DE2, // 66
            0x7FFFFFFF, 0x7FFFA6B7, // 67
            0x7FFFFFFF, 0x7FFFDD39, // 68
            0x7FFFFFFF, 0x7FFFF2A3, // 69
            0x7FFFFFFF, 0x7FFFFAEF, // 70
            0x7FFFFFFF, 0x7FFFFE1B, // 71
            0x7FFFFFFF, 0x7FFFFF4D, // 72
            0x7FFFFFFF, 0x7FFFFFBF, // 73
            0x7FFFFFFF, 0x7FFFFFE9, // 74
            0x7FFFFFFF, 0x7FFFFFF8, // 75
            0x7FFFFFFF, 0x7FFFFFFD, // 76
            0x7FFFFFFF, 0x7FFFFFFF, // 77
        };

        static void sample_gauss_poly(int nonce, byte[] seed, int seedOffset, int[] poly, int polyOffset)
        {
            int dmsp = nonce << 8;

            byte samp[] = new byte[CHUNK_SIZE*CDT_COLS * 4]; // This is int32_t in C, we will treat it as byte[] in java
            int c[] = new int[CDT_COLS];
            int borrow, sign;
            int mask = (-1) >>> 1;

            for (int chunk = 0; chunk < PARAM_N; chunk += CHUNK_SIZE)
            {
                HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                    samp, 0, CHUNK_SIZE * CDT_COLS * 4, (short)dmsp++, seed, seedOffset, CRYPTO_SEEDBYTES);

                for (int i = 0; i < CHUNK_SIZE; i++) {
                    poly[ polyOffset+ chunk+i] = 0;
                    for (int j = 1; j < CDT_ROWS; j++) {
                        borrow = 0;
                        for (int k = CDT_COLS-1; k >= 0; k--) {
                            c[k] = (at(samp, i*CDT_COLS, k) & mask) - (cdt_v[j*CDT_COLS+k] + borrow);
                            borrow = c[k] >> (RADIX32-1);
                        }
                        poly[polyOffset+chunk+i] += ~borrow & 1;
                    }

//                    sign =  at(samp,i*CDT_COLS, 0) >> (RADIX32-1);
                    sign = (int)samp[((i*CDT_COLS) << 2) + 3] >> (RADIX32 - 1);

                    poly[polyOffset+chunk+i] = (sign & -poly[polyOffset+chunk+i]) | (~sign & poly[polyOffset+chunk+i]);
                }
            }
        }
    }

    static class QTesla1PPolynomial
    {
        private static final int[] zeta = new int[]{
            184007114, 341297933, 172127038, 306069179, 260374244, 269720605, 20436325, 2157599, 36206659, 61987110, 112759694, 92762708, 278504038, 139026960, 183642748, 298230187,
            37043356, 230730845, 107820937, 97015745, 156688276, 38891102, 170244636, 259345227, 170077366, 141586883, 100118513, 328793523, 289946488, 263574185, 132014089, 14516260,
            87424978, 192691578, 190961717, 262687761, 333967048, 12957952, 326574509, 273585413, 151922543, 195893203, 261889302, 120488377, 169571794, 44896463, 128576039, 68257019,
            20594664, 44164717, 36060712, 256009818, 172063915, 211967562, 135533785, 104908181, 203788155, 52968398, 123297488, 44711423, 329131026, 245797804, 220629853, 200431766,
            92905498, 215466666, 227373088, 120513729, 274875394, 236766448, 84216704, 97363940, 224003799, 167341181, 333540791, 225846253, 290150331, 137934911, 101127339, 95054535,
            7072757, 58600117, 264117725, 207480694, 268253444, 292044590, 166300682, 256585624, 133577520, 119707476, 58169614, 188489502, 184778640, 156039906, 286669262, 112658784,
            89254003, 266568758, 290599527, 80715937, 180664712, 225980378, 103512701, 304604206, 327443646, 92082345, 296093912, 144843084, 309484036, 329737605, 141656867, 264967053,
            227847682, 328674715, 208663554, 309005608, 315790590, 182996330, 333212133, 203436199, 13052895, 23858345, 173478900, 97132319, 57066271, 70747422, 202106993, 309870606,
            56390934, 336126437, 189147643, 219236223, 293351741, 305570320, 18378834, 336914091, 59506067, 277923611, 217306643, 129369847, 308113789, 56954705, 190254906, 199465001,
            119331054, 143640880, 17590914, 309468163, 172483421, 153376031, 58864560, 70957183, 237697179, 116097341, 62196815, 80692520, 310642530, 328595292, 12121494, 71200620,
            200016287, 235006678, 21821056, 102505389, 183332133, 59734849, 283127491, 313646880, 30359439, 163176989, 50717815, 100183661, 322975554, 92821217, 283119421, 34453836,
            303758926, 89460722, 147514506, 175603941, 76494101, 220775631, 304963431, 38821441, 217317485, 301302769, 328727631, 101476595, 270750726, 253708871, 176201368, 324059659,
            114780906, 304156831, 273708648, 144095014, 263545324, 179240984, 187811389, 244886526, 202581571, 209325648, 117231636, 182195945, 217965216, 252295904, 332003328, 46153749,
            334740528, 62618402, 301165510, 283016648, 212224416, 234984074, 107363471, 125430881, 172821269, 270409387, 156316970, 311644197, 50537885, 248376507, 154072039, 331539029,
            48454192, 267029920, 225963915, 16753350, 76840946, 226444843, 108106635, 154887261, 326283837, 101291223, 204194230, 54014060, 104099734, 104245071, 260949411, 333985274,
            291682234, 328313139, 29607387, 106291750, 162553334, 275058303, 64179189, 263147140, 15599810, 325103190, 137254480, 66787068, 4755224, 308520011, 181897417, 325162685,
            221099032, 131741505, 147534370, 131533267, 144073688, 166398146, 155829711, 252509898, 251605008, 323547097, 216038649, 232629333, 95137254, 287931575, 235583527, 32386598,
            76722491, 60825791, 138354268, 400761, 51907675, 197369064, 319840588, 98618414, 84343982, 108113946, 314679670, 134518178, 64988900, 4333172, 295712261, 200707216,
            147647414, 318013383, 77682006, 92518996, 42154619, 87464521, 285037574, 332936592, 62635246, 5534097, 308862707, 91097989, 269726589, 273280832, 251670430, 95492698,
            21676891, 182964692, 177187742, 294825274, 85128609, 273594538, 93115857, 116308166, 312212122, 18665807, 32192823, 313249299, 98777368, 273984239, 312125377, 205655336,
            264861277, 178920022, 341054719, 232663249, 173564046, 176591124, 157537342, 305058098, 277279130, 170028356, 228573747, 31628995, 175280663, 37304323, 122111670, 210658936,
            175704183, 314649282, 325535066, 266783938, 301319742, 327923297, 279787306, 304633001, 304153402, 292839078, 147442886, 94150133, 40461238, 221384781, 269671052, 265445273,
            208370149, 160863546, 287765159, 339146643, 129600429, 96192870, 113146118, 95879915, 216708053, 285201955, 67756451, 79028039, 309141895, 138447809, 212246614, 12641916,
            243544995, 33459809, 76979779, 71155723, 152521243, 200750888, 36425947, 339074467, 319204591, 188312744, 266105966, 280016981, 183723313, 238915015, 23277613, 160934729,
            200611286, 163282810, 297928823, 226921588, 86839172, 145317111, 202226936, 51887320, 318474782, 282270658, 221219795, 207597867, 132089009, 334627662, 163952597, 67529059,
            173759630, 234865017, 255217646, 277806158, 61964704, 216678166, 96126463, 39218331, 70028373, 4899005, 238135514, 242700690, 284680271, 81041980, 332906491, 463527,
            299280916, 204600651, 149654879, 222229829, 26825157, 81825189, 127990873, 200962599, 16149163, 108812393, 217708971, 152638110, 28735779, 5272794, 19720409, 231726324,
            49854178, 118319174, 185669526, 223407181, 243138094, 259020958, 308825615, 164156486, 341391280, 192526841, 97036052, 279986894, 20263748, 32228956, 43816679, 343421811,
            124320208, 3484106, 31711063, 147679160, 195369505, 54243678, 279088595, 149119313, 301997352, 244557309, 19700779, 138872683, 230523717, 113507709, 135291486, 313025300,
            254384479, 219815764, 253574481, 220646316, 124744817, 123915741, 325760383, 123516396, 138140410, 154060994, 314730104, 57286356, 222353426, 76630003, 145380041, 52039855,
            229881219, 332902036, 152308429, 95071889, 124799350, 270141530, 47897266, 119620601, 133269057, 138561303, 341820265, 66049665, 273409631, 304306012, 212490958, 210388603,
            277413768, 280793261, 223131872, 162407285, 44911970, 316685837, 298709373, 252812339, 230786851, 230319350, 56863422, 341141914, 177295413, 248222411, 215148650, 97970603,
            291678055, 161911155, 339645428, 206445182, 31895080, 279676698, 78257775, 268845232, 92545841, 336725589, 47384597, 62216335, 82290365, 89893410, 266117967, 791867,
            28042243, 110563426, 183316855, 281174508, 166338432, 86326996, 261473803, 164647535, 84749290, 157518777, 214336587, 72257047, 13358702, 229010735, 204196474, 179927635,
            21786785, 330554989, 164559635, 144505300, 280425045, 324057501, 268227440, 323362437, 26891539, 228523003, 166709094, 61174973, 13532911, 42168701, 133044957, 158219357,
            220115616, 15174468, 281706353, 283813987, 263212325, 289818392, 247170937, 276072317, 197581495, 33713097, 181695825, 96829354, 32991226, 228583784, 4040287, 65188717,
            258204083, 96366799, 176298395, 341574369, 306098123, 218746932, 29191888, 311810435, 305844323, 31614267, 28130094, 72716426, 38568041, 197579396, 14876445, 228525674,
            294569685, 2451649, 165929882, 112195415, 204786047, 138216235, 3438132, 126150615, 59754608, 158965324, 268160978, 266231264, 244422459, 306155336, 218178824, 301806695,
            208837335, 212153467, 209725081, 269355286, 295716530, 13980580, 264284060, 301901789, 275319045, 107139083, 4006959, 143908623, 139848274, 25357089, 21607040, 340818603,
            91260932, 198869267, 45119941, 224113252, 269556513, 42857483, 268925602, 188501450, 235382337, 324688793, 113056679, 177232352, 98280013, 117743899, 87369665, 330110286,
            310895756, 268425063, 27568325, 266303142, 181405304, 65876631, 246283438, 127636847, 16153922, 210256884, 9257227, 147272724, 235571791, 340876897, 31558760, 224463520,
            229909008, 40943950, 263351999, 14865952, 27279162, 51980445, 99553161, 108121152, 145230283, 217402431, 84060866, 190168688, 46894008, 205718237, 296935065, 331646198,
            59709076, 265829428, 214503586, 310273189, 86051634, 247210969, 275872780, 55395653, 302717617, 155583500, 207999042, 293597246, 305796948, 139332832, 198434142, 104197059,
            320317582, 101819543, 70813687, 43594385, 241913829, 210308279, 298735610, 151599086, 92093482, 24654121, 52528801, 134711941, 324580593, 293101038, 121757877, 323940193,
            276114751, 33522997, 218880483, 46953248, 33126382, 294367143, 161595040, 208968904, 129221110, 323693686, 234366848, 50155901, 123936119, 72127416, 34243899, 171824126,
            26019236, 93997235, 28452989, 24219933, 188331672, 181161011, 146526219, 186502916, 258266311, 207146754, 206589869, 189836867, 107762500, 129011227, 222324073, 331319091,
            36618753, 141615400, 273319528, 246222615, 156139193, 290104141, 154851520, 310226922, 60187406, 73704819, 225899604, 87931539, 142487643, 152682959, 45891249, 212048348,
            148547910, 207745063, 4405848, 179269204, 216233362, 230307487, 303352796, 41616117, 47140231, 13452075, 94626849, 48892822, 78453712, 214721933, 300785835, 1512599,
            173577933, 163255132, 239883248, 205714288, 306118903, 106953300, 150085654, 77068348, 246390345, 199698311, 280165539, 256497526, 194381508, 78125966, 168327358, 180735395,
            145983352, 243342736, 198463602, 83165996, 286431792, 22885329, 271516106, 66137359, 243561376, 324886778, 149497212, 24531379, 32857894, 62778029, 56960216, 224996784,
            129315394, 81068505, 277744916, 215817366, 117205172, 195090165, 287841567, 57750901, 162987791, 259309908, 135370005, 194853269, 236792732, 219249166, 42349628, 27805769,
            186263338, 310699018, 6491000, 228545163, 315890485, 22219119, 144392189, 15505150, 87848372, 155973124, 20446561, 177725890, 226669021, 205315635, 269580641, 133696452,
            189388357, 314652032, 317225560, 304194584, 157633737, 298144493, 185785271, 337434647, 559796, 4438732, 249110619, 184824722, 221490126, 205632858, 172362641, 176702767,
            276712118, 296075254, 111221225, 259809961, 15438443, 198021462, 134378223, 162261445, 170746654, 256890644, 125206341, 307078324, 279553989, 170124925, 296845387, 188226544,
            295437875, 315053523, 172025817, 279046062, 189967278, 158662482, 192989875, 326540363, 135446089, 98631439, 257379933, 325004289, 26554274, 62190249, 228828648, 274361329,
            18518762, 184854759, 210189061, 186836398, 230859454, 206912014, 201250021, 276332768, 119984643, 91358832, 325377399, 69085488, 307352479, 308876137, 208756649, 32865966,
            152976045, 207821125, 66426662, 67585526, 118828370, 3107192, 322037257, 146029104, 106553806, 266958791, 89567376, 153815988, 90786397, 271042585, 203781777, 169087756,
            315867500, 306916544, 7528726, 327732739, 227901532, 2263402, 14357894, 269740764, 322090105, 59838559, 298337502, 292797139, 337635349, 66476915, 75612762, 328089387,
            155232910, 87069405, 36163560, 273715413, 321325749, 218096743, 308178877, 21861281, 180676741, 135208372, 119891712, 122406065, 267537516, 341350322, 87789083, 196340943,
            217070591, 83564209, 159382818, 253921239, 184673854, 213569600, 194031064, 35973794, 18071215, 250854127, 115090766, 147707843, 330337973, 266187164, 27853295, 296801215,
            254949704, 43331190, 73930201, 35703461, 119780800, 216998106, 12687572, 250863345, 243908221, 330555990, 296216993, 202100577, 111307303, 151049872, 103451600, 237710099,
            78658022, 121490075, 134292528, 88277916, 177315676, 186629690, 77848818, 211822377, 145696683, 289190386, 274721999, 328391282, 218772820, 91324151, 321725584, 277577004,
            65732866, 275538085, 144429136, 204062923, 177280727, 214204692, 264758257, 169151951, 335535576, 334002493, 281131703, 305997258, 310527888, 136973519, 216764406, 235954329,
            254049694, 285174861, 264316834, 11792643, 149333889, 214699018, 261331547, 317320791, 24527858, 118790777, 264146824, 174296812, 332779737, 94199786, 288227027, 172048372,
        };

        private static final int[] zetainv = new int[]{
            55349550, 249376791, 10796840, 169279765, 79429753, 224785800, 319048719, 26255786, 82245030, 128877559, 194242688, 331783934, 79259743, 58401716, 89526883, 107622248,
            126812171, 206603058, 33048689, 37579319, 62444874, 9574084, 8041001, 174424626, 78818320, 129371885, 166295850, 139513654, 199147441, 68038492, 277843711, 65999573,
            21850993, 252252426, 124803757, 15185295, 68854578, 54386191, 197879894, 131754200, 265727759, 156946887, 166260901, 255298661, 209284049, 222086502, 264918555, 105866478,
            240124977, 192526705, 232269274, 141476000, 47359584, 13020587, 99668356, 92713232, 330889005, 126578471, 223795777, 307873116, 269646376, 300245387, 88626873, 46775362,
            315723282, 77389413, 13238604, 195868734, 228485811, 92722450, 325505362, 307602783, 149545513, 130006977, 158902723, 89655338, 184193759, 260012368, 126505986, 147235634,
            255787494, 2226255, 76039061, 221170512, 223684865, 208368205, 162899836, 321715296, 35397700, 125479834, 22250828, 69861164, 307413017, 256507172, 188343667, 15487190,
            267963815, 277099662, 5941228, 50779438, 45239075, 283738018, 21486472, 73835813, 329218683, 341313175, 115675045, 15843838, 336047851, 36660033, 27709077, 174488821,
            139794800, 72533992, 252790180, 189760589, 254009201, 76617786, 237022771, 197547473, 21539320, 340469385, 224748207, 275991051, 277149915, 135755452, 190600532, 310710611,
            134819928, 34700440, 36224098, 274491089, 18199178, 252217745, 223591934, 67243809, 142326556, 136664563, 112717123, 156740179, 133387516, 158721818, 325057815, 69215248,
            114747929, 281386328, 317022303, 18572288, 86196644, 244945138, 208130488, 17036214, 150586702, 184914095, 153609299, 64530515, 171550760, 28523054, 48138702, 155350033,
            46731190, 173451652, 64022588, 36498253, 218370236, 86685933, 172829923, 181315132, 209198354, 145555115, 328138134, 83766616, 232355352, 47501323, 66864459, 166873810,
            171213936, 137943719, 122086451, 158751855, 94465958, 339137845, 343016781, 6141930, 157791306, 45432084, 185942840, 39381993, 26351017, 28924545, 154188220, 209880125,
            73995936, 138260942, 116907556, 165850687, 323130016, 187603453, 255728205, 328071427, 199184388, 321357458, 27686092, 115031414, 337085577, 32877559, 157313239, 315770808,
            301226949, 124327411, 106783845, 148723308, 208206572, 84266669, 180588786, 285825676, 55735010, 148486412, 226371405, 127759211, 65831661, 262508072, 214261183, 118579793,
            286616361, 280798548, 310718683, 319045198, 194079365, 18689799, 100015201, 277439218, 72060471, 320691248, 57144785, 260410581, 145112975, 100233841, 197593225, 162841182,
            175249219, 265450611, 149195069, 87079051, 63411038, 143878266, 97186232, 266508229, 193490923, 236623277, 37457674, 137862289, 103693329, 180321445, 169998644, 342063978,
            42790742, 128854644, 265122865, 294683755, 248949728, 330124502, 296436346, 301960460, 40223781, 113269090, 127343215, 164307373, 339170729, 135831514, 195028667, 131528229,
            297685328, 190893618, 201088934, 255645038, 117676973, 269871758, 283389171, 33349655, 188725057, 53472436, 187437384, 97353962, 70257049, 201961177, 306957824, 12257486,
            121252504, 214565350, 235814077, 153739710, 136986708, 136429823, 85310266, 157073661, 197050358, 162415566, 155244905, 319356644, 315123588, 249579342, 317557341, 171752451,
            309332678, 271449161, 219640458, 293420676, 109209729, 19882891, 214355467, 134607673, 181981537, 49209434, 310450195, 296623329, 124696094, 310053580, 67461826, 19636384,
            221818700, 50475539, 18995984, 208864636, 291047776, 318922456, 251483095, 191977491, 44840967, 133268298, 101662748, 299982192, 272762890, 241757034, 23258995, 239379518,
            145142435, 204243745, 37779629, 49979331, 135577535, 187993077, 40858960, 288180924, 67703797, 96365608, 257524943, 33303388, 129072991, 77747149, 283867501, 11930379,
            46641512, 137858340, 296682569, 153407889, 259515711, 126174146, 198346294, 235455425, 244023416, 291596132, 316297415, 328710625, 80224578, 302632627, 113667569, 119113057,
            312017817, 2699680, 108004786, 196303853, 334319350, 133319693, 327422655, 215939730, 97293139, 277699946, 162171273, 77273435, 316008252, 75151514, 32680821, 13466291,
            256206912, 225832678, 245296564, 166344225, 230519898, 18887784, 108194240, 155075127, 74650975, 300719094, 74020064, 119463325, 298456636, 144707310, 252315645, 2757974,
            321969537, 318219488, 203728303, 199667954, 339569618, 236437494, 68257532, 41674788, 79292517, 329595997, 47860047, 74221291, 133851496, 131423110, 134739242, 41769882,
            125397753, 37421241, 99154118, 77345313, 75415599, 184611253, 283821969, 217425962, 340138445, 205360342, 138790530, 231381162, 177646695, 341124928, 49006892, 115050903,
            328700132, 145997181, 305008536, 270860151, 315446483, 311962310, 37732254, 31766142, 314384689, 124829645, 37478454, 2002208, 167278182, 247209778, 85372494, 278387860,
            339536290, 114992793, 310585351, 246747223, 161880752, 309863480, 145995082, 67504260, 96405640, 53758185, 80364252, 59762590, 61870224, 328402109, 123460961, 185357220,
            210531620, 301407876, 330043666, 282401604, 176867483, 115053574, 316685038, 20214140, 75349137, 19519076, 63151532, 199071277, 179016942, 13021588, 321789792, 163648942,
            139380103, 114565842, 330217875, 271319530, 129239990, 186057800, 258827287, 178929042, 82102774, 257249581, 177238145, 62402069, 160259722, 233013151, 315534334, 342784710,
            77458610, 253683167, 261286212, 281360242, 296191980, 6850988, 251030736, 74731345, 265318802, 63899879, 311681497, 137131395, 3931149, 181665422, 51898522, 245605974,
            128427927, 95354166, 166281164, 2434663, 286713155, 113257227, 112789726, 90764238, 44867204, 26890740, 298664607, 181169292, 120444705, 62783316, 66162809, 133187974,
            131085619, 39270565, 70166946, 277526912, 1756312, 205015274, 210307520, 223955976, 295679311, 73435047, 218777227, 248504688, 191268148, 10674541, 113695358, 291536722,
            198196536, 266946574, 121223151, 286290221, 28846473, 189515583, 205436167, 220060181, 17816194, 219660836, 218831760, 122930261, 90002096, 123760813, 89192098, 30551277,
            208285091, 230068868, 113052860, 204703894, 323875798, 99019268, 41579225, 194457264, 64487982, 289332899, 148207072, 195897417, 311865514, 340092471, 219256369, 154766,
            299759898, 311347621, 323312829, 63589683, 246540525, 151049736, 2185297, 179420091, 34750962, 84555619, 100438483, 120169396, 157907051, 225257403, 293722399, 111850253,
            323856168, 338303783, 314840798, 190938467, 125867606, 234764184, 327427414, 142613978, 215585704, 261751388, 316751420, 121346748, 193921698, 138975926, 44295661, 343113050,
            10670086, 262534597, 58896306, 100875887, 105441063, 338677572, 273548204, 304358246, 247450114, 126898411, 281611873, 65770419, 88358931, 108711560, 169816947, 276047518,
            179623980, 8948915, 211487568, 135978710, 122356782, 61305919, 25101795, 291689257, 141349641, 198259466, 256737405, 116654989, 45647754, 180293767, 142965291, 182641848,
            320298964, 104661562, 159853264, 63559596, 77470611, 155263833, 24371986, 4502110, 307150630, 142825689, 191055334, 272420854, 266596798, 310116768, 100031582, 330934661,
            131329963, 205128768, 34434682, 264548538, 275820126, 58374622, 126868524, 247696662, 230430459, 247383707, 213976148, 4429934, 55811418, 182713031, 135206428, 78131304,
            73905525, 122191796, 303115339, 249426444, 196133691, 50737499, 39423175, 38943576, 63789271, 15653280, 42256835, 76792639, 18041511, 28927295, 167872394, 132917641,
            221464907, 306272254, 168295914, 311947582, 115002830, 173548221, 66297447, 38518479, 186039235, 166985453, 170012531, 110913328, 2521858, 164656555, 78715300, 137921241,
            31451200, 69592338, 244799209, 30327278, 311383754, 324910770, 31364455, 227268411, 250460720, 69982039, 258447968, 48751303, 166388835, 160611885, 321899686, 248083879,
            91906147, 70295745, 73849988, 252478588, 34713870, 338042480, 280941331, 10639985, 58539003, 256112056, 301421958, 251057581, 265894571, 25563194, 195929163, 142869361,
            47864316, 339243405, 278587677, 209058399, 28896907, 235462631, 259232595, 244958163, 23735989, 146207513, 291668902, 343175816, 205222309, 282750786, 266854086, 311189979,
            107993050, 55645002, 248439323, 110947244, 127537928, 20029480, 91971569, 91066679, 187746866, 177178431, 199502889, 212043310, 196042207, 211835072, 122477545, 18413892,
            161679160, 35056566, 338821353, 276789509, 206322097, 18473387, 327976767, 80429437, 279397388, 68518274, 181023243, 237284827, 313969190, 15263438, 51894343, 9591303,
            82627166, 239331506, 239476843, 289562517, 139382347, 242285354, 17292740, 188689316, 235469942, 117131734, 266735631, 326823227, 117612662, 76546657, 295122385, 12037548,
            189504538, 95200070, 293038692, 31932380, 187259607, 73167190, 170755308, 218145696, 236213106, 108592503, 131352161, 60559929, 42411067, 280958175, 8836049, 297422828,
            11573249, 91280673, 125611361, 161380632, 226344941, 134250929, 140995006, 98690051, 155765188, 164335593, 80031253, 199481563, 69867929, 39419746, 228795671, 19516918,
            167375209, 89867706, 72825851, 242099982, 14848946, 42273808, 126259092, 304755136, 38613146, 122800946, 267082476, 167972636, 196062071, 254115855, 39817651, 309122741,
            60457156, 250755360, 20601023, 243392916, 292858762, 180399588, 313217138, 29929697, 60449086, 283841728, 160244444, 241071188, 321755521, 108569899, 143560290, 272375957,
            331455083, 14981285, 32934047, 262884057, 281379762, 227479236, 105879398, 272619394, 284712017, 190200546, 171093156, 34108414, 325985663, 199935697, 224245523, 144111576,
            153321671, 286621872, 35462788, 214206730, 126269934, 65652966, 284070510, 6662486, 325197743, 38006257, 50224836, 124340354, 154428934, 7450140, 287185643, 33705971,
            141469584, 272829155, 286510306, 246444258, 170097677, 319718232, 330523682, 140140378, 10364444, 160580247, 27785987, 34570969, 134913023, 14901862, 115728895, 78609524,
            201919710, 13838972, 34092541, 198733493, 47482665, 251494232, 16132931, 38972371, 240063876, 117596199, 162911865, 262860640, 52977050, 77007819, 254322574, 230917793,
            56907315, 187536671, 158797937, 155087075, 285406963, 223869101, 209999057, 86990953, 177275895, 51531987, 75323133, 136095883, 79458852, 284976460, 336503820, 248522042,
            242449238, 205641666, 53426246, 117730324, 10035786, 176235396, 119572778, 246212637, 259359873, 106810129, 68701183, 223062848, 116203489, 128109911, 250671079, 143144811,
            122946724, 97778773, 14445551, 298865154, 220279089, 290608179, 139788422, 238668396, 208042792, 131609015, 171512662, 87566759, 307515865, 299411860, 322981913, 275319558,
            215000538, 298680114, 174004783, 223088200, 81687275, 147683374, 191654034, 69991164, 17002068, 330618625, 9609529, 80888816, 152614860, 150884999, 256151599, 329060317,
            211562488, 80002392, 53630089, 14783054, 243458064, 201989694, 173499211, 84231350, 173331941, 304685475, 186888301, 246560832, 235755640, 112845732, 306533221, 45346390,
            159933829, 204549617, 65072539, 250813869, 230816883, 281589467, 307369918, 341418978, 323140252, 73855972, 83202333, 37507398, 171449539, 2278644, 159569463, 171528205,
        };

        static void poly_uniform(int[] a, byte[] seed, int seedOffset)
        {
            int pos = 0, i = 0, nbytes = (PARAM_Q_LOG + 7) / 8;
            int nblocks = PARAM_GEN_A;
            int val1, val2, val3, val4, mask = (1 << PARAM_Q_LOG) - 1;
            byte[] buf = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A];
            short dmsp = 0;

            // GenA: the XOF is instantiated with cSHAKE128 (see Algorithm 10).
            HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                buf, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A,
                dmsp++,
                seed, seedOffset, CRYPTO_RANDOMBYTES
            );

            while (i < PARAM_K * PARAM_N)
            {
                if (pos > HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * nblocks - 4 * nbytes)
                {
                    nblocks = 1;

                    // GenA: the XOF is instantiated with cSHAKE128 (see Algorithm 10).
                    HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                        buf, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A,
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

                if (val1 < PARAM_Q && i < PARAM_K * PARAM_N)
                {
                    a[i++] = reduce((long)val1 * PARAM_R2_INVN);
                }
                if (val2 < PARAM_Q && i < PARAM_K * PARAM_N)
                {
                    a[i++] = reduce((long)val2 * PARAM_R2_INVN);
                }
                if (val3 < PARAM_Q && i < PARAM_K * PARAM_N)
                {
                    a[i++] = reduce((long)val3 * PARAM_R2_INVN);
                }
                if (val4 < PARAM_Q && i < PARAM_K * PARAM_N)
                {
                    a[i++] = reduce((long)val4 * PARAM_R2_INVN);
                }
            }
        }

        static int reduce(long a)
        { // Montgomery reduction
            long u;

            u = (a * (long)PARAM_QINV) & 0xFFFFFFFFL;
            u *= PARAM_Q;
            a += u;
            return (int)(a >> 32);
        }

        static void ntt(int[] a, int[] w)
        { // Forward NTT transform
            int NumoProblems = PARAM_N >> 1, jTwiddle = 0;

            for (; NumoProblems > 0; NumoProblems >>= 1)
            {
                int jFirst, j = 0;
                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems)
                {
                    int W = w[jTwiddle++];
                    for (j = jFirst; j < jFirst + NumoProblems; j++)
                    {
                        int a_j = a[j], a_n = a[j + NumoProblems];
                        int temp = reduce((long)W * a_n);
                        a[j] = correct(a_j + temp - PARAM_Q);
                        a[j + NumoProblems] = correct(a_j - temp);
                    }
                }
            }
        }

        private static int barr_reduce(int a)
        { // Barrett reduction
            int u = (int)(((long)a * PARAM_BARR_MULT) >> PARAM_BARR_DIV);
            return a - u * PARAM_Q;
        }

        private static int barr_reduce64(long a)
        { // Barrett reduction
            long u = (a * PARAM_BARR_MULT) >> PARAM_BARR_DIV;
            return (int)(a - u * PARAM_Q);
        }

        private static int correct(int x)
        {
            return x + ((x >> (RADIX32 - 1)) & PARAM_Q);
        }

        static void nttinv(int[] a, int aPos, int[] w)
        { // Inverse NTT transform
            int NumoProblems = 1, jTwiddle = 0;
            for (NumoProblems = 1; NumoProblems < PARAM_N; NumoProblems *= 2)
            {
                int jFirst, j = 0;
                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems)
                {
                    int W = w[jTwiddle++];
                    for (j = jFirst; j < jFirst + NumoProblems; j++)
                    {
                        int temp = a[aPos + j];
                        a[aPos + j] = barr_reduce(temp + a[aPos + j + NumoProblems]);
                        a[aPos + j + NumoProblems] = reduce((long)W * (temp - a[aPos + j + NumoProblems]));
                    }
                }
            }
        }

        static void poly_ntt(int[] x_ntt, int[] x)
        { // Call to NTT function. Avoids input destruction

            for (int i = 0; i < PARAM_N; i++)
            {
                x_ntt[i] = x[i];
            }
            ntt(x_ntt, zeta);
        }

        static void poly_pointwise(int[] result, int rpos, int[] x, int xpos, int[] y)
        { // Pointwise polynomial multiplication result = x.y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i + rpos] = reduce((long)x[i + xpos] * y[i]);
            }
        }

        static void poly_mul(int[] result, int rpos, int[] x, int xpos, int[] y)
        { // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)

            poly_pointwise(result, rpos, x, xpos, y);
            nttinv(result, rpos, zetainv);
        }

        static void poly_add(int[] result, int[] x, int[] y)
        { // Polynomial addition result = x+y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] + y[i];
            }
        }

        static void poly_add_correct(int[] result, int rpos, int[] x, int xpos, int[] y, int ypos)
        { // Polynomial addition result = x+y with correction

            for (int i = 0; i < PARAM_N; i++)
            {
                int ri = correct(x[xpos + i] + y[ypos + i]);
                result[rpos + i] = correct(ri - PARAM_Q);
            }
        }

        static void poly_sub(int[] result, int rpos, int[] x, int xpos, int[] y, int ypos)
        { // Polynomial subtraction result = x-y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[rpos + i] = x[xpos + i] - y[ypos + i];
            }
        }

        static void poly_sub_reduce(int[] result, int rpos, int[] x, int xpos, int[] y, int ypos)
        { // Polynomial subtraction result = x-y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[rpos + i] = barr_reduce(x[xpos + i] - y[ypos + i]);
            }
        }

        static void sparse_mul8(int[] prod, int ppos, byte[] s, int spos, int[] pos_list, short[] sign_list)
        {
            // TODO Review multiplications involving elements of s (an unsigned char* in reference implementation)
            int i, j, pos;

            for (i = 0; i < PARAM_N; i++)
            {
                prod[ppos + i] = 0;
            }

            for (i = 0; i < PARAM_H; i++)
            {
                pos = pos_list[i];
                for (j = 0; j < pos; j++)
                {
                    prod[ppos + j] = prod[ppos + j] - sign_list[i] * s[spos + j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    prod[ppos + j] = prod[ppos + j] + sign_list[i] * s[spos + j - pos];
                }
            }
        }

        static void sparse_mul32(int[] prod, int ppos, int[] pk, int pkPos, int[] pos_list, short[] sign_list)
        {
            int i, j, pos;
            long[] temp = new long[PARAM_N];

            for (i = 0; i < PARAM_H; i++)
            {
                pos = pos_list[i];
                for (j = 0; j < pos; j++)
                {
                    temp[j] = temp[j] - sign_list[i] * pk[pkPos + j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    temp[j] = temp[j] + sign_list[i] * pk[pkPos + j - pos];
                }
            }

            for (i = 0; i < PARAM_N; i++)
            {
                prod[ppos + i] = barr_reduce64(temp[i]);
            }
        }
    }
}
