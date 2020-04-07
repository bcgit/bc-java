package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class QTesla3p
{
    private static final int PARAM_N = 2048;
//    private static final double PARAM_SIGMA = 8.5;
    private static final int PARAM_Q = 856145921;
    private static final int PARAM_Q_LOG = 30;
    private static final long PARAM_QINV = 587710463;
    private static final long PARAM_BARR_MULT = 5;
    private static final int PARAM_BARR_DIV = 32;
    private static final int PARAM_B = 2097151;
    private static final int PARAM_B_BITS = 21;
//    private static final int PARAM_S_BITS = 8;
    private static final int PARAM_K = 5;
//    private static final double PARAM_SIGMA_E = PARAM_SIGMA;
    private static final int PARAM_H = 40;
    private static final int PARAM_D = 24;
    private static final int PARAM_GEN_A = 180;
    private static final int PARAM_KEYGEN_BOUND_E = 901;
    private static final int PARAM_E = PARAM_KEYGEN_BOUND_E;
    private static final int PARAM_KEYGEN_BOUND_S = 901;
    private static final int PARAM_S = PARAM_KEYGEN_BOUND_S;
    private static final int PARAM_R2_INVN = 513161157;
//    private static final int PARAM_R = 14237691;

    private static final int CRYPTO_RANDOMBYTES = 32;
    private static final int CRYPTO_SEEDBYTES = 32;
    private static final int CRYPTO_C_BYTES = 32;
    private static final int HM_BYTES = 40;

//    private static final int RADIX = 32;
    private static final int RADIX32 = 32;


    static final int CRYPTO_BYTES = ((PARAM_N * (PARAM_B_BITS + 1) + 7) / 8 + CRYPTO_C_BYTES);
    // Contains polynomial s and e, and seeds seed_a and seed_y
    static final int CRYPTO_SECRETKEYBYTES = (1 * PARAM_N + 1 * PARAM_N * PARAM_K + 2 * CRYPTO_SEEDBYTES + HM_BYTES);

    // Contains seed_a and polynomials t
    static final int CRYPTO_PUBLICKEYBYTES = ((PARAM_Q_LOG * PARAM_N * PARAM_K + 7) / 8 + CRYPTO_SEEDBYTES);

    static int generateKeyPair(byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {
        /* Initialize Domain Separator for Error Polynomial and Secret Polynomial */
        int nonce = 0;

        byte[] randomness = new byte[CRYPTO_RANDOMBYTES];

        /* Extend Random Bytes to Seed Generation of Error Polynomial and Secret Polynomial */
        byte[] randomnessExtended = new byte[(PARAM_K + 3) * CRYPTO_SEEDBYTES];

        long[] secretPolynomial = new long[PARAM_N];
        long[] errorPolynomial = new long[PARAM_N * PARAM_K];
        long[] A = new long[PARAM_N * PARAM_K];
        long[] T = new long[PARAM_N * PARAM_K];

        long[] s_ntt = new long[PARAM_N];

        /* Get randomnessExtended <- seedErrorPolynomial, seedSecretPolynomial, seedA, seedY */
        secureRandom.nextBytes(randomness);

        HashUtils.secureHashAlgorithmKECCAK256(
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

        QTesla3PPolynomial.poly_uniform(A, randomnessExtended, (PARAM_K + 1) * CRYPTO_SEEDBYTES);
        QTesla3PPolynomial.poly_ntt(s_ntt, secretPolynomial);

        for (int k = 0; k < PARAM_K; k++)
        {
            QTesla3PPolynomial.poly_mul(T, k * PARAM_N, A, k * PARAM_N, s_ntt);
            QTesla3PPolynomial.poly_add_correct(T, k * PARAM_N, T, k * PARAM_N, errorPolynomial, k * PARAM_N);
        }

        /* Pack Public and Private Keys */
        encodePublicKey(publicKey, T, randomnessExtended, (PARAM_K + 1) * CRYPTO_SEEDBYTES);
        encodePrivateKey(privateKey, secretPolynomial, errorPolynomial, randomnessExtended, (PARAM_K + 1) * CRYPTO_SEEDBYTES, publicKey);

        return 0;
    }

    static int generateSignature(
        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom)
    {
        byte[] c = new byte[CRYPTO_C_BYTES];
        byte[] randomness = new byte[CRYPTO_SEEDBYTES];
        byte[] randomness_input = new byte[CRYPTO_SEEDBYTES + CRYPTO_RANDOMBYTES + 2 * HM_BYTES];
        int[] pos_list = new int[PARAM_H];
        short[] sign_list = new short[PARAM_H];
        long[] y = new long[PARAM_N];

        long[] y_ntt = new long[PARAM_N];
        long[] Sc = new long[PARAM_N];
        long[] z = new long[PARAM_N];

        long[] v = new long[PARAM_N * PARAM_K];
        long[] Ec = new long[PARAM_N * PARAM_K];
        long[] a = new long[PARAM_N * PARAM_K];

        int k;
        int nonce = 0;  // Initialize domain separator for sampling y
        boolean rsp = false;

        System.arraycopy(privateKey, CRYPTO_SECRETKEYBYTES - HM_BYTES - CRYPTO_SEEDBYTES, randomness_input, 0, CRYPTO_SEEDBYTES);

        {
            byte[] tmp = new byte[CRYPTO_RANDOMBYTES];
            secureRandom.nextBytes(tmp);
            System.arraycopy(tmp, 0, randomness_input, CRYPTO_SEEDBYTES, CRYPTO_RANDOMBYTES);
        }

        HashUtils.secureHashAlgorithmKECCAK256(
            randomness_input, CRYPTO_SEEDBYTES + CRYPTO_RANDOMBYTES, HM_BYTES,
            message, 0, messageLength);

        HashUtils.secureHashAlgorithmKECCAK256(
            randomness, 0, CRYPTO_SEEDBYTES,
            randomness_input, 0, randomness_input.length - HM_BYTES);

        System.arraycopy(privateKey, CRYPTO_SECRETKEYBYTES - HM_BYTES, randomness_input, randomness_input.length - HM_BYTES, HM_BYTES);

        QTesla3PPolynomial.poly_uniform(a, privateKey, CRYPTO_SECRETKEYBYTES - HM_BYTES - 2 * CRYPTO_SEEDBYTES);

        while (true)
        {
            sample_y(y, randomness, 0, ++nonce);

            QTesla3PPolynomial.poly_ntt(y_ntt, y);
            for (k = 0; k < PARAM_K; k++)
            {
                QTesla3PPolynomial.poly_mul(v, k * PARAM_N, a, k * PARAM_N, y_ntt);
            }

            hashFunction(c, 0, v, randomness_input, CRYPTO_SEEDBYTES + CRYPTO_RANDOMBYTES);
            encodeC(pos_list, sign_list, c, 0);

            QTesla3PPolynomial.sparse_mul8(Sc, privateKey, pos_list, sign_list);

            QTesla3PPolynomial.poly_add(z, y, Sc);

            if (testRejection(z))
            {
                continue;
            }

            for (k = 0; k < PARAM_K; k++)
            {
                QTesla3PPolynomial.sparse_mul8(Ec, k * PARAM_N, privateKey, (PARAM_N * (k + 1)), pos_list, sign_list);
                QTesla3PPolynomial.poly_sub(v, k * PARAM_N, v, k * PARAM_N, Ec, k * PARAM_N);
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

        // return 0;
    }

    static int verifying(
        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey)
    {
        byte[] c = new byte[CRYPTO_C_BYTES];
        byte[] c_sig = new byte[CRYPTO_C_BYTES];
        byte[] seed = new byte[CRYPTO_SEEDBYTES];
        byte[] hm = new byte[2 * HM_BYTES];
        int[] pos_list = new int[PARAM_H];
        short[] sign_list = new short[PARAM_H];
        int[] pk_t = new int[PARAM_N * PARAM_K];
        long[] w = new long[PARAM_N * PARAM_K];
        long[] a = new long[PARAM_N * PARAM_K];
        long[] Tc = new long[PARAM_N * PARAM_K];

        long[] z = new long[PARAM_N];
        long[] z_ntt = new long[PARAM_N];

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

        // Get H(m) and hash_pk^M
        HashUtils.secureHashAlgorithmKECCAK256(
            hm, 0, HM_BYTES,
            message, 0, message.length);
        HashUtils.secureHashAlgorithmKECCAK256(
            hm, HM_BYTES, HM_BYTES,
            publicKey, 0, CRYPTO_PUBLICKEYBYTES - CRYPTO_SEEDBYTES);

        QTesla3PPolynomial.poly_uniform(a, seed, 0);
        encodeC(pos_list, sign_list, c, 0);
        QTesla3PPolynomial.poly_ntt(z_ntt, z);

        for (k = 0; k < PARAM_K; k++)
        {      // Compute w = az - tc
            QTesla3PPolynomial.sparse_mul32(Tc, k * PARAM_N, pk_t, (k * PARAM_N), pos_list, sign_list);
            QTesla3PPolynomial.poly_mul(w, k * PARAM_N, a, k * PARAM_N, z_ntt);
            QTesla3PPolynomial.poly_sub(w, k * PARAM_N, w, k * PARAM_N, Tc, k * PARAM_N);
        }

        hashFunction(c_sig, 0, w, hm, 0);

        if (!memoryEqual(c, 0, c_sig, 0, CRYPTO_C_BYTES))
        {
            return -3;
        }

        return 0;
    }

    static void encodePrivateKey(byte[] privateKey, final long[] secretPolynomial, final long[] errorPolynomial,
        final byte[] seed, int seedOffset, byte[] publicKey)
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
        HashUtils.secureHashAlgorithmKECCAK256(
            privateKey, skPtr, HM_BYTES,
            publicKey, 0, CRYPTO_PUBLICKEYBYTES - CRYPTO_SEEDBYTES);
        skPtr += HM_BYTES;

//        assert CRYPTO_SECRETKEYBYTES == skPtr;
    }

    static void encodePublicKey(byte[] publicKey, final long[] T, final byte[] seedA, int seedAOffset)
    {
        int j = 0;

        for (int i = 0; i < (PARAM_N * PARAM_K * PARAM_Q_LOG / 32); i += 15)
        {
            at(publicKey, i, 0, (int)(T[j] | (T[j + 1] << 30)));
            at(publicKey, i, 1, (int)((T[j + 1] >> 2) | (T[j + 2] << 28)));
            at(publicKey, i, 2, (int)((T[j + 2] >> 4) | (T[j + 3] << 26)));
            at(publicKey, i, 3, (int)((T[j + 3] >> 6) | (T[j + 4] << 24)));
            at(publicKey, i, 4, (int)((T[j + 4] >> 8) | (T[j + 5] << 22)));
            at(publicKey, i, 5, (int)((T[j + 5] >> 10) | (T[j + 6] << 20)));
            at(publicKey, i, 6, (int)((T[j + 6] >> 12) | (T[j + 7] << 18)));
            at(publicKey, i, 7, (int)((T[j + 7] >> 14) | (T[j + 8] << 16)));
            at(publicKey, i, 8, (int)((T[j + 8] >> 16) | (T[j + 9] << 14)));
            at(publicKey, i, 9, (int)((T[j + 9] >> 18) | (T[j + 10] << 12)));
            at(publicKey, i, 10, (int)((T[j + 10] >> 20) | (T[j + 11] << 10)));
            at(publicKey, i, 11, (int)((T[j + 11] >> 22) | (T[j + 12] << 8)));
            at(publicKey, i, 12, (int)((T[j + 12] >> 24) | (T[j + 13] << 6)));
            at(publicKey, i, 13, (int)((T[j + 13] >> 26) | (T[j + 14] << 4)));
            at(publicKey, i, 14, (int)((T[j + 14] >> 28) | (T[j + 15] << 2)));
            j += 16;
        }

        System.arraycopy(seedA, seedAOffset, publicKey, PARAM_N * PARAM_K * PARAM_Q_LOG / 8, CRYPTO_SEEDBYTES);

    }


    static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;
        byte[] pt = publicKeyInput;
        int maskq = (1 << PARAM_Q_LOG) - 1;


        for (int i = 0; i < PARAM_N * PARAM_K; i += 16)
        {
            publicKey[i] = at(pt, j, 0) & maskq;
            publicKey[i + 1] = ((at(pt, j, 0) >>> 30) | (at(pt, j, 1) << 2)) & maskq;
            publicKey[i + 2] = ((at(pt, j, 1) >>> 28) | (at(pt, j, 2) << 4)) & maskq;
            publicKey[i + 3] = ((at(pt, j, 2) >>> 26) | (at(pt, j, 3) << 6)) & maskq;
            publicKey[i + 4] = ((at(pt, j, 3) >>> 24) | (at(pt, j, 4) << 8)) & maskq;
            publicKey[i + 5] = ((at(pt, j, 4) >>> 22) | (at(pt, j, 5) << 10)) & maskq;
            publicKey[i + 6] = ((at(pt, j, 5) >>> 20) | (at(pt, j, 6) << 12)) & maskq;
            publicKey[i + 7] = ((at(pt, j, 6) >>> 18) | (at(pt, j, 7) << 14)) & maskq;
            publicKey[i + 8] = ((at(pt, j, 7) >>> 16) | (at(pt, j, 8) << 16)) & maskq;
            publicKey[i + 9] = ((at(pt, j, 8) >>> 14) | (at(pt, j, 9) << 18)) & maskq;
            publicKey[i + 10] = ((at(pt, j, 9) >>> 12) | (at(pt, j, 10) << 20)) & maskq;
            publicKey[i + 11] = ((at(pt, j, 10) >>> 10) | (at(pt, j, 11) << 22)) & maskq;
            publicKey[i + 12] = ((at(pt, j, 11) >>> 8) | (at(pt, j, 12) << 24)) & maskq;
            publicKey[i + 13] = ((at(pt, j, 12) >>> 6) | (at(pt, j, 13) << 26)) & maskq;
            publicKey[i + 14] = ((at(pt, j, 13) >>> 4) | (at(pt, j, 14) << 28)) & maskq;
            publicKey[i + 15] = (at(pt, j, 14) >>> 2) & maskq;
            j += 15;
        }


        System.arraycopy(publicKeyInput, PARAM_N * PARAM_K * PARAM_Q_LOG / 8, seedA, seedAOffset, CRYPTO_SEEDBYTES);

    }

    private static boolean testZ(long[] Z)
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

    static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z)
    {
        int j = 0;

        for (int i = 0; i < (PARAM_N * (PARAM_B_BITS + 1) / 32); i += 11)
        {
            at(signature, i, 0, (int)((Z[j + 0] & ((1 << 22) - 1)) | (Z[j + 1] << 22)));
            at(signature, i, 1, (int)(((Z[j + 1] >>> 10) & ((1 << 12) - 1)) | (Z[j + 2] << 12)));
            at(signature, i, 2, (int)(((Z[j + 2] >>> 20) & ((1 << 2) - 1)) | ((Z[j + 3] & maskb1) << 2) | (Z[j + 4] << 24)));
            at(signature, i, 3, (int)(((Z[j + 4] >>> 8) & ((1 << 14) - 1)) | (Z[j + 5] << 14)));
            at(signature, i, 4, (int)(((Z[j + 5] >>> 18) & ((1 << 4) - 1)) | ((Z[j + 6] & maskb1) << 4) | (Z[j + 7] << 26)));
            at(signature, i, 5, (int)(((Z[j + 7] >>> 6) & ((1 << 16) - 1)) | (Z[j + 8] << 16)));
            at(signature, i, 6, (int)(((Z[j + 8] >>> 16) & ((1 << 6) - 1)) | ((Z[j + 9] & maskb1) << 6) | (Z[j + 10] << 28)));
            at(signature, i, 7, (int)(((Z[j + 10] >>> 4) & ((1 << 18) - 1)) | (Z[j + 11] << 18)));
            at(signature, i, 8, (int)(((Z[j + 11] >>> 14) & ((1 << 8) - 1)) | ((Z[j + 12] & maskb1) << 8) | (Z[j + 13] << 30)));
            at(signature, i, 9, (int)(((Z[j + 13] >>> 2) & ((1 << 20) - 1)) | (Z[j + 14] << 20)));
            at(signature, i, 10, (int)(((Z[j + 14] >>> 12) & ((1 << 10) - 1)) | (Z[j + 15] << 10)));
            j += 16;
        }

        System.arraycopy(C, cOffset, signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, CRYPTO_C_BYTES);
    }

    static void decodeSignature(byte[] C, long[] Z, final byte[] signature, int signatureOffset)
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
            int s10 = at(signature, j, 10);

            Z[i] = (s0 << 10) >> 10;
            Z[i + 1] = (s0 >>> 22) | ((s1 << 20) >> 10);
            Z[i + 2] = (s1 >>> 12) | ((s2 << 30) >> 10);
            Z[i + 3] = ((s2 << 8) >> 10);
            Z[i + 4] = (s2 >>> 24) | ((s3 << 18) >> 10);
            Z[i + 5] = (s3 >>> 14) | ((s4 << 28) >> 10);
            Z[i + 6] = ((s4 << 6) >> 10);
            Z[i + 7] = (s4 >>> 26) | ((s5 << 16) >> 10);
            Z[i + 8] = (s5 >>> 16) | ((s6 << 26) >> 10);
            Z[i + 9] = ((s6 << 4) >> 10);
            Z[i + 10] = (s6 >>> 28) | ((s7 << 14) >> 10);
            Z[i + 11] = (s7 >>> 18) | ((s8 << 24) >> 10);
            Z[i + 12] = ((s8 << 2) >> 10);
            Z[i + 13] = (s8 >>> 30) | ((s9 << 12) >> 10);
            Z[i + 14] = (s9 >>> 20) | ((s10 << 22) >> 10);
            Z[i + 15] = (s10 >> 10);
            j += 11;
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

    private static void hashFunction(byte[] output, int outputOff, long[] v, byte[] hm, int hmOff)
    {
        int mask, cL;

        byte[] T = new byte[PARAM_K * PARAM_N + 2 * HM_BYTES];

        for (int k = 0; k < PARAM_K; k++)
        {
            int index = k * PARAM_N;
            for (int i = 0; i < PARAM_N; i++)
            {
                int temp = (int)v[index];
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
        System.arraycopy(hm, hmOff, T, PARAM_K * PARAM_N, 2 * HM_BYTES);

        HashUtils.secureHashAlgorithmKECCAK256(
            output, outputOff, CRYPTO_C_BYTES,
            T, 0, T.length);
    }

    static int lE24BitToInt(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        return n;
    }


    private static int NBLOCKS_SHAKE = HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE / (((PARAM_B_BITS + 1) + 7) / 8);
    private static int BPLUS1BYTES = ((PARAM_B_BITS + 1) + 7) / 8;


    static void sample_y(long[] y, byte[] seed, int seedOffset, int nonce)
    { // Sample polynomial y, such that each coefficient is in the range [-B,B]
        int i = 0, pos = 0, nblocks = PARAM_N;
        byte buf[] = new byte[PARAM_N * BPLUS1BYTES + 1];
        int nbytes = BPLUS1BYTES;
        short dmsp = (short)(nonce << 8);

        HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
            buf, 0, PARAM_N * nbytes, dmsp++, seed, seedOffset, CRYPTO_RANDOMBYTES
        );


        while (i < PARAM_N)
        {
            if (pos >= nblocks * nbytes)
            {
                nblocks = NBLOCKS_SHAKE;
                HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
                    buf, 0, PARAM_N * nbytes, dmsp++, seed, seedOffset, CRYPTO_RANDOMBYTES
                );
                pos = 0;
            }
            y[i] = lE24BitToInt(buf, pos) & ((1 << (PARAM_B_BITS + 1)) - 1);
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
        Pack.intToLittleEndian(value, bs, (base * 4) + (index * 4));
    }

    private static int at(byte[] bs, int base, int index)
    {
        int off = (base * 4) + (index * 4);

        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }


    static boolean test_correctness(long[] v, int vpos)
    { // Check bounds for w = v - ec during signature verification. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
        // This function leaks the position of the coefficient that fails the test (but this is independent of the secret data).
        // It does not leak the sign of the coefficients.
        int mask, left, val;
        int t0, t1;

        for (int i = 0; i < PARAM_N; i++)
        {
            // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
            mask = (int)(PARAM_Q / 2 - v[vpos + i]) >> (RADIX32 - 1);
            val = (int)(((v[vpos + i] - PARAM_Q) & mask) | (v[vpos + i] & ~mask));
            // If (Abs(val) < PARAM_Q/2 - PARAM_E) then t0 = 0, else t0 = 1
            t0 = (int)(~(absolute(val) - (PARAM_Q / 2 - PARAM_E))) >>> (RADIX32 - 1);

            left = val;
            val = (val + (1 << (PARAM_D - 1)) - 1) >> PARAM_D;
            val = left - (val << PARAM_D);
            // If (Abs(val) < (1<<(PARAM_D-1))-PARAM_E) then t1 = 0, else t1 = 1
            t1 = (int)(~(absolute(val) - ((1 << (PARAM_D - 1)) - PARAM_E))) >>> (RADIX32 - 1);

            if ((t0 | t1) == 1)  // Returns 1 if any of the two tests failed
            {
                return true;
            }
        }
        return false;
    }


    private static boolean testRejection(long[] Z) //, int n, int b, int u)
    {

        int valid = 0;

        for (int i = 0; i < PARAM_N; i++)
        {
            valid |= (PARAM_B - PARAM_S) - absolute(Z[i]);

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


    private static boolean checkPolynomial(long[] polynomial, int polyOffset, int bound)
    {

        int i, j, sum = 0, limit = PARAM_N;
        long temp, mask;
        long[] list = new long[PARAM_N];

        for (j = 0; j < PARAM_N; j++)
        {
            list[j] = absolute((int)polynomial[polyOffset + j]);
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
            sum += (int)list[limit - 1];
            limit -= 1;
        }

        return (sum > bound);
    }


    // End of outer.

    static class Gaussian
    {

        private static final int CDT_ROWS = 111;
        private static final int CDT_COLS = 4;
        private static final int CHUNK_SIZE = 512;

        private static final long[] cdt_v = new long[]{
            0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, // 0
            0x0601F22AL, 0x280663D4L, 0x2E1B038CL, 0x1E75FCA7L, // 1
            0x11F09FFAL, 0x162FE23DL, 0x403739B4L, 0x3F2AA531L, // 2
            0x1DA089E9L, 0x437226E8L, 0x115E99C8L, 0x68C472A6L, // 3
            0x28EAB25DL, 0x04C51FE2L, 0x13F63FD0L, 0x1E56BF40L, // 4
            0x33AC2F26L, 0x14FDBA70L, 0x6618880FL, 0x792CE93EL, // 5
            0x3DC767DCL, 0x4565C95FL, 0x7EAC4790L, 0x163F4D99L, // 6
            0x4724FC62L, 0x3342C78AL, 0x390873B2L, 0x13A12ACEL, // 7
            0x4FB448F4L, 0x5229D06DL, 0x09A6C84BL, 0x1D13CB0DL, // 8
            0x576B8599L, 0x7423407FL, 0x1287EE2FL, 0x7B908556L, // 9
            0x5E4786DAL, 0x3210BAF6L, 0x6881795CL, 0x13DF4F59L, // 10
            0x644B2C92L, 0x431B3946L, 0x63F188D9L, 0x22AFB6DEL, // 11
            0x697E90CEL, 0x77C362C3L, 0x600A627EL, 0x66AEDF96L, // 12
            0x6DEE0B96L, 0x2798C9CEL, 0x147A98F9L, 0x27427F24L, // 13
            0x71A92144L, 0x5765FCE4L, 0x0FF04C94L, 0x74183C18L, // 14
            0x74C16FD5L, 0x1E2A0990L, 0x13EB545FL, 0x1CD9A2ADL, // 15
            0x7749AC92L, 0x0DF36EEBL, 0x414629E5L, 0x66610A51L, // 16
            0x7954BFA4L, 0x28079289L, 0x29D5B127L, 0x29B69601L, // 17
            0x7AF5067AL, 0x2EDC2050L, 0x2B486556L, 0x43BF4664L, // 18
            0x7C3BC17CL, 0x123D5E7AL, 0x63D4DD26L, 0x3B1E3755L, // 19
            0x7D38AD76L, 0x2A9381D9L, 0x1D20D034L, 0x77C09C55L, // 20
            0x7DF9C5DFL, 0x0E868CA7L, 0x23627687L, 0x78864423L, // 21
            0x7E8B2ABAL, 0x18E5C810L, 0x7C85B42CL, 0x7AC98BCCL, // 22
            0x7EF7237CL, 0x00908272L, 0x3D4B170EL, 0x3CD572E3L, // 23
            0x7F4637C5L, 0x6DBA5125L, 0x5B0285ECL, 0x46661EB9L, // 24
            0x7F7F5707L, 0x4A52EDEBL, 0x50ECECB1L, 0x7384DC42L, // 25
            0x7FA808CCL, 0x23290598L, 0x704F7A4DL, 0x08532154L, // 26
            0x7FC4A083L, 0x69BDF2D4L, 0x73B67B27L, 0x3AE237ADL, // 27
            0x7FD870CAL, 0x42275557L, 0x6F2AE034L, 0x4E4B0395L, // 28
            0x7FE5FB5DL, 0x3EF82C1BL, 0x256E2EB0L, 0x09E42B11L, // 29
            0x7FEF1BFAL, 0x6C03A362L, 0x07334BD4L, 0x22B6B15FL, // 30
            0x7FF52D4EL, 0x316C2C8CL, 0x1C77A4C3L, 0x1C3A974EL, // 31
            0x7FF927BAL, 0x12AE54AEL, 0x6CC24956L, 0x3BA9A3E4L, // 32
            0x7FFBBA43L, 0x749CC0E2L, 0x044B3068L, 0x620F14DAL, // 33
            0x7FFD5E3DL, 0x4524AD91L, 0x31F84A1FL, 0x4D23AF51L, // 34
            0x7FFE6664L, 0x535785B4L, 0x683C9E5EL, 0x2BD857DFL, // 35
            0x7FFF0A41L, 0x0B291681L, 0x1CB4CE6FL, 0x32B314B9L, // 36
            0x7FFF6E81L, 0x132C3D6FL, 0x4C8771CCL, 0x67421A75L, // 37
            0x7FFFAAFEL, 0x4DBC6BEDL, 0x4E8644D2L, 0x5158A208L, // 38
            0x7FFFCEFDL, 0x7A1E2D14L, 0x2CF905AAL, 0x79BFABD9L, // 39
            0x7FFFE41EL, 0x4C6EC115L, 0x2D648F1AL, 0x4B01BA3EL, // 40
            0x7FFFF059L, 0x319503C8L, 0x2CBEB96AL, 0x52FF656EL, // 41
            0x7FFFF754L, 0x5DDD0D40L, 0x09D07206L, 0x6BF97EB5L, // 42
            0x7FFFFB43L, 0x0B9E9822L, 0x5B584BE0L, 0x4974ED83L, // 43
            0x7FFFFD71L, 0x76B81AE1L, 0x3C93755CL, 0x375F857BL, // 44
            0x7FFFFEA3L, 0x7E66A1ECL, 0x3E342087L, 0x44ED1696L, // 45
            0x7FFFFF49L, 0x26F6E190L, 0x7E3625F9L, 0x2F4F5849L, // 46
            0x7FFFFFA1L, 0x2FA31694L, 0x0D53F684L, 0x59931C0DL, // 47
            0x7FFFFFCFL, 0x5247BEC8L, 0x5CC20735L, 0x397CE966L, // 48
            0x7FFFFFE7L, 0x4F4127C6L, 0x64926788L, 0x01CFEF66L, // 49
            0x7FFFFFF3L, 0x6FAA69FDL, 0x26A67DC3L, 0x1FFA2528L, // 50
            0x7FFFFFFAL, 0x0630D072L, 0x7AA0C1B7L, 0x7E90AAE6L, // 51
            0x7FFFFFFDL, 0x0F2957BBL, 0x3ADCE1E6L, 0x5A311C28L, // 52
            0x7FFFFFFEL, 0x4FD29431L, 0x6429F9EDL, 0x04653965L, // 53
            0x7FFFFFFFL, 0x2CFAD60DL, 0x52ED82D1L, 0x26455881L, // 54
            0x7FFFFFFFL, 0x5967A92FL, 0x5C85AB2DL, 0x188033BEL, // 55
            0x7FFFFFFFL, 0x6E4C9DFEL, 0x76798EAFL, 0x0DC0BA65L, // 56
            0x7FFFFFFFL, 0x77FDCCC8L, 0x194FF9ACL, 0x2C3FA855L, // 57
            0x7FFFFFFFL, 0x7C6CE89EL, 0x01FA1A72L, 0x6C3DC40BL, // 58
            0x7FFFFFFFL, 0x7E6D116EL, 0x5F82B352L, 0x57B67FCEL, // 59
            0x7FFFFFFFL, 0x7F50FA31L, 0x31856599L, 0x579DC24BL, // 60
            0x7FFFFFFFL, 0x7FB50089L, 0x43E64BB5L, 0x7F498E42L, // 61
            0x7FFFFFFFL, 0x7FE04C2CL, 0x56CBFAEFL, 0x7FC9C15FL, // 62
            0x7FFFFFFFL, 0x7FF2C7C0L, 0x5D509634L, 0x41DCA82BL, // 63
            0x7FFFFFFFL, 0x7FFA8FE3L, 0x24F6020DL, 0x7B594401L, // 64
            0x7FFFFFFFL, 0x7FFDCB1BL, 0x2D294BB3L, 0x1D1631BFL, // 65
            0x7FFFFFFFL, 0x7FFF1DE1L, 0x5D75B704L, 0x323B12FEL, // 66
            0x7FFFFFFFL, 0x7FFFA6B6L, 0x7E983E86L, 0x23392636L, // 67
            0x7FFFFFFFL, 0x7FFFDD39L, 0x029CCA2CL, 0x035F7017L, // 68
            0x7FFFFFFFL, 0x7FFFF2A3L, 0x205DBF7BL, 0x173D7F90L, // 69
            0x7FFFFFFFL, 0x7FFFFAEFL, 0x3F79145BL, 0x642F005DL, // 70
            0x7FFFFFFFL, 0x7FFFFE1BL, 0x23B2C7E4L, 0x6CA216CFL, // 71
            0x7FFFFFFFL, 0x7FFFFF4DL, 0x1E959E3FL, 0x4A29BB03L, // 72
            0x7FFFFFFFL, 0x7FFFFFBEL, 0x7C23D3D9L, 0x71DC92E4L, // 73
            0x7FFFFFFFL, 0x7FFFFFE8L, 0x55110485L, 0x0E1813E2L, // 74
            0x7FFFFFFFL, 0x7FFFFFF7L, 0x5EBC7B7BL, 0x2DFEE922L, // 75
            0x7FFFFFFFL, 0x7FFFFFFDL, 0x0EDB0975L, 0x0C9F1639L, // 76
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x00DDA1A1L, 0x6DE86AA0L, // 77
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x54CF6D87L, 0x023F1F47L, // 78
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7186FF6AL, 0x5B71BF8CL, // 79
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7B375EBCL, 0x767A89DCL, // 80
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E70BA89L, 0x44EBCEAAL, // 81
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F7F98B5L, 0x44C8E44AL, // 82
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FD744C2L, 0x448EE5A4L, // 83
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF34165L, 0x008855D0L, // 84
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC1110L, 0x754A60B6L, // 85
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFECD77L, 0x44BE6D4AL, // 86
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFA3F4L, 0x7400A73EL, // 87
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFE4BDL, 0x1143830BL, // 88
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF809L, 0x1A385059L, // 89
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFDB4L, 0x41CA0794L, // 90
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF59L, 0x02FFB605L, // 91
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFD1L, 0x18360E8DL, // 92
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF3L, 0x072A0E9AL, // 93
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFCL, 0x3C1BFEB0L, // 94
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x066EBCDDL, // 95
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x5FBE171AL, // 96
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x778EB81FL, // 97
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7DD211FEL, // 98
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F71F071L, // 99
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FDC528FL, // 100
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF7298CL, // 101
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFDD739L, // 102
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF7ACAL, // 103
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFE056L, // 104
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF893L, // 105
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFE48L, // 106
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF9CL, // 107
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFE9L, // 108
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFBL, // 109
            0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, // 110
        };


        static void sample_gauss_poly(int nonce, byte[] seed, int seedOffset, long[] poly, int polyOffset)
        {
            int dmsp = nonce << 8;

            byte samp[] = new byte[CHUNK_SIZE * CDT_COLS * 4]; // This is int32_t in C, we will treat it as byte[] in java
            int c[] = new int[CDT_COLS];
            int borrow, sign;
            int mask = (-1) >>> 1;

            for (int chunk = 0; chunk < PARAM_N; chunk += CHUNK_SIZE)
            {

                HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
                    samp, 0, CHUNK_SIZE * CDT_COLS * 4, (short)dmsp++, seed, seedOffset, CRYPTO_SEEDBYTES);

                for (int i = 0; i < CHUNK_SIZE; i++)
                {
                    poly[polyOffset + chunk + i] = 0;
                    for (int j = 1; j < CDT_ROWS; j++)
                    {
                        borrow = 0;
                        for (int k = CDT_COLS - 1; k >= 0; k--)
                        {
                            c[k] = (int)((at(samp, 0, i * CDT_COLS + k) & mask) - (cdt_v[j * CDT_COLS + k] + borrow));
                            borrow = c[k] >> (RADIX32 - 1);
                        }
                        poly[polyOffset + chunk + i] += ~borrow & 1;
                    }
                    sign = at(samp, 0, i * CDT_COLS) >> (RADIX32 - 1);
                    poly[polyOffset + chunk + i] = (sign & -poly[polyOffset + chunk + i]) | (~sign & poly[polyOffset + chunk + i]);
                }

            }

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


    static class QTesla3PPolynomial
    {


        private static final long[] zeta = new long[]{
            147314272, 762289503, 284789571, 461457674, 723990704, 123382358, 685457283, 458774590, 644795450, 723622678, 441493948, 676062368, 648739792, 214990524, 261899220, 138474554,
            205277234, 788000393, 541334956, 769530525, 786231394, 812002793, 251385069, 152717354, 674883688, 458756880, 323745289, 823881240, 686340396, 716163820, 107735873, 144028791,
            586327243, 71257244, 739303131, 487030542, 313626215, 396596783, 664640087, 728258996, 854656117, 567834989, 2315110, 210792230, 795895843, 433034260, 432732757, 480454055,
            750130006, 47628047, 2271301, 98590211, 729637734, 683553815, 476917424, 121851414, 296210757, 820475433, 403416438, 605633242, 804828963, 435181077, 781182803, 276684653,
            329135201, 697859430, 248472020, 396579594, 109340098, 97605675, 755271019, 565755143, 534799496, 378374148, 85686225, 298978496, 650100484, 712463562, 818417023, 283716467,
            269132585, 153024538, 223768950, 331863760, 761523727, 586019306, 805044248, 810909760, 77905343, 401203343, 162625701, 616243024, 659789238, 385270982, 720521140, 545633566,
            688663167, 740046782, 257189758, 115795491, 101106443, 409863172, 622399622, 405606434, 498832246, 730567206, 350755879, 41236295, 561547732, 525723591, 18655497, 3396399,
            289694332, 221478904, 738940554, 769726362, 32128402, 693016435, 275431006, 65292213, 601823865, 469363520, 480544944, 607230206, 473150754, 267072604, 463615065, 412972775,
            197544577, 770873783, 189036815, 407973558, 110878446, 442760341, 667560342, 756992079, 663708407, 585601880, 763637579, 660019224, 424935088, 249313490, 844593983, 664952705,
            274981537, 40233161, 655530034, 742724096, 8926394, 67709207, 616610795, 539664358, 306118645, 741629065, 283521858, 621397947, 369041534, 162477412, 258256937, 269480966,
            75469364, 815614830, 724060729, 510819743, 489239410, 265607303, 103024793, 434961090, 474838542, 234701483, 505818866, 450427360, 188113529, 650423376, 599263141, 720479782,
            755079140, 469798456, 745591660, 432033717, 530128582, 94480771, 722477467, 169342233, 35413255, 89769525, 424389771, 240236288, 360665614, 66702784, 76128663, 565345206,
            605031892, 393503210, 249841967, 485930917, 45880284, 746120091, 684031522, 537926896, 408749937, 608644803, 692593939, 515424474, 748771159, 155377700, 347101257, 393516280,
            708186062, 809233270, 562547654, 768251664, 651110951, 574473323, 588028067, 352359235, 646902518, 410726541, 134129459, 460099853, 829152883, 819102028, 7270760, 562515302,
            419641762, 347973450, 161011009, 401974733, 619807719, 559105457, 276126568, 165473862, 380215069, 356617900, 347744328, 615885981, 824819772, 811367929, 6451967, 515345658,
            648239021, 56427040, 709160497, 71545092, 390921213, 17177139, 194174898, 825533429, 497469884, 88988508, 64227614, 641021859, 159258883, 529265733, 823190295, 567280997,
            414094239, 238392498, 695610059, 416342151, 90807038, 206865379, 568337348, 168011486, 844375038, 777332780, 147582038, 199025846, 396231915, 151630666, 466807217, 12672521,
            570774644, 764098787, 283719496, 779154504, 383628791, 851035387, 395488461, 291115871, 52707730, 776449280, 479801706, 73403989, 402014636, 255214342, 56904698, 446531030,
            639487570, 848061696, 202732901, 739018922, 653983847, 453022791, 391722680, 584290855, 270911670, 390838431, 653070075, 535876472, 83207555, 131151682, 505677504, 778583044,
            472363568, 734419459, 768500943, 321131696, 371745445, 751887879, 51797676, 157604159, 838805925, 358099697, 763440819, 776721566, 719570904, 304610785, 656838485, 239522278,
            796234199, 659506535, 825373307, 674901303, 250484891, 54612517, 410236408, 111976920, 728940855, 720463104, 559960962, 514189554, 637176165, 436151981, 485801800, 802811374,
            549456481, 808832355, 112672706, 199163132, 807410080, 645955491, 365378122, 222316474, 381896744, 693909930, 402130292, 199856804, 277639257, 6848838, 648262319, 601521139,
            108516632, 392382841, 563420106, 475932203, 249861415, 99274558, 152886431, 744977783, 269184267, 562674804, 760959275, 733098096, 771348891, 674288361, 631521272, 513632066,
            476339117, 621937967, 206834230, 507101607, 420341698, 528715580, 853092790, 580174958, 278044321, 432350205, 603769437, 144426940, 733518338, 365468467, 848983278, 385382826,
            846062026, 593903051, 216589699, 219997638, 350708517, 733669279, 624754239, 499821820, 772548008, 199677439, 287505007, 144199205, 215073292, 825467700, 101591831, 571728784,
            841898341, 420897808, 61323616, 823475752, 72494861, 89946011, 236594097, 379582577, 539401967, 221244669, 479250487, 100726882, 263096036, 647161225, 491060387, 419890898,
            816149055, 546441322, 690509770, 215789647, 5870948, 821456387, 294091098, 783700004, 278643020, 520754327, 813718894, 123610053, 157045201, 265331664, 807174256, 258134244,
            703519669, 300265991, 41892125, 662173055, 439638698, 494124024, 700655120, 535348417, 37146186, 379568907, 644973451, 554904963, 594757858, 477812802, 266085643, 46337543,
            454847754, 496027901, 701947604, 5722633, 790588605, 233501932, 728956461, 462020148, 214013660, 155806979, 159935426, 423504958, 638889309, 602641304, 277759403, 71654804,
            710920410, 108337831, 641924564, 252946326, 463082282, 23277660, 142056200, 263317553, 9044238, 367816044, 349695658, 291597086, 230031083, 385106216, 281069679, 644033142,
            134221740, 212497862, 686686078, 787489098, 781698667, 748299513, 774414792, 380836293, 114027649, 766161763, 10536612, 707355910, 100516219, 637517297, 21478533, 769067854,
            668364559, 410803198, 64949715, 643421522, 525590993, 585289785, 423839840, 554109325, 450599860, 295350132, 435789550, 306634115, 611298620, 777817576, 553655202, 804525538,
            794474290, 138542076, 780958763, 62228371, 738032107, 684994110, 661486955, 67099069, 68865906, 32413094, 358393763, 205008770, 849715545, 289798348, 384767209, 787328590,
            823677120, 47455925, 706001331, 612392717, 487804928, 731804935, 520572665, 442307581, 351275150, 726042356, 667657829, 254929787, 459520026, 625393223, 319307882, 77267096,
            815224795, 335964550, 408353208, 604252110, 574953308, 563501897, 515015302, 313600371, 178773384, 417549087, 510834475, 167049599, 488791556, 664276219, 82933775, 822541833,
            17111190, 409659978, 96304098, 500484311, 269766378, 327037310, 584926256, 538611363, 404132255, 170931824, 744460626, 154011192, 322194096, 215888234, 258344560, 702851111,
            192046250, 738511820, 530780560, 57197515, 335425579, 410968369, 830078545, 448351649, 208921555, 356653676, 718038774, 424362596, 158929491, 420096666, 387056270, 797383293,
            381201911, 466480709, 373815662, 84912008, 4969808, 524614597, 93448903, 559481007, 400813998, 665223025, 601707338, 466022707, 192709574, 615503265, 822863744, 639854175,
            158713505, 12757666, 389196370, 823105438, 682974863, 468401586, 93508626, 402414043, 806357152, 180544963, 27876186, 321527031, 329857607, 669501423, 829809824, 333202822,
            106923493, 368991112, 282317903, 790323774, 517381333, 548329656, 236147848, 700119793, 404187488, 343578810, 798813301, 497964535, 656188346, 678161787, 736817175, 518031339,
            716647183, 674797219, 308643560, 714308544, 516103468, 605229646, 564549717, 47650358, 706404486, 494887760, 152496104, 54954356, 271435602, 76951527, 136123931, 601823638,
            329273401, 252710411, 754980731, 351648254, 49239731, 837833233, 88830509, 598216539, 155534490, 669603727, 418388693, 79322074, 636251444, 703683994, 796989459, 126497707,
            644863316, 730359063, 265213001, 64483814, 552208981, 8135537, 782474322, 780853310, 733976806, 395661138, 128188419, 266691358, 407092046, 447349747, 526245954, 119272088,
            359659635, 812410956, 669835517, 565139408, 248981831, 139910745, 685462294, 406991131, 709944045, 589819925, 714299787, 72923680, 648836181, 145321778, 392775383, 243093077,
            412955839, 174619485, 310936394, 699727061, 421087619, 745421519, 539546394, 29471558, 116471631, 852650639, 443777703, 773131303, 81618669, 756719012, 702785073, 847088653,
            851830586, 300908692, 430974543, 463215976, 668971423, 414271988, 108350516, 345933325, 716417649, 174980945, 679092437, 384030489, 814050910, 506580116, 249434097, 178438885,
            146797119, 10369463, 296359082, 215645133, 149545847, 483689845, 322009569, 308978588, 38531178, 328571637, 815396967, 709744233, 765487128, 645413104, 564779557, 213794315,
            280607549, 124792697, 423470554, 631348430, 21223627, 220718413, 598791979, 47797633, 734556299, 590321944, 168292920, 484802055, 340999812, 769601438, 42675060, 116026587,
            227462622, 543574607, 444066479, 467277895, 278798674, 597413704, 350168725, 301936652, 82885511, 656047519, 765110538, 52228202, 533005731, 621989298, 148235931, 317833915,
            118463894, 522391939, 451332724, 548031654, 73854149, 527786213, 583308898, 840663438, 275278054, 362931963, 587861579, 830807449, 431695707, 178004048, 75513216, 60681147,
            638603143, 470791469, 490903319, 527370962, 102981857, 224220555, 756514239, 293859807, 797926303, 620196520, 466126507, 646136763, 265504163, 213257337, 92270416, 398713724,
            91810366, 724247342, 855386762, 631553083, 376095634, 833728623, 636218061, 510719408, 378530670, 737821436, 127781731, 3443282, 770116208, 769633348, 430675947, 40370755,
            52361322, 844601468, 442556599, 128290354, 494328514, 405616679, 651440882, 421541290, 171560170, 386143493, 284277254, 450756213, 248305939, 526718005, 300780198, 714218239,
            68021827, 527353904, 236472015, 309320156, 683815803, 527980097, 598849444, 779607597, 339852811, 845420163, 96001931, 326760873, 609319751, 520803868, 140143851, 766988701,
            844896794, 532008178, 388459130, 574799295, 760406065, 773758517, 453271555, 134636434, 155747417, 105505251, 796987277, 399016325, 71156680, 709579308, 274279004, 96962867,
            476741915, 585319990, 709143538, 721328791, 293159344, 640577897, 138404614, 572892015, 394460832, 465897068, 325895331, 413861636, 447337182, 376950267, 721061932, 181671909,
            272138750, 247768905, 634973622, 280653872, 165108426, 134241779, 15142090, 153256717, 783424845, 773227607, 172477802, 504458250, 349868083, 461422806, 487725644, 586146740,
            561546455, 815406759, 468110471, 126476456, 285774551, 522013234, 801943660, 79684345, 654558548, 188038414, 249923934, 551812615, 562560206, 407120348, 384535446, 176837117,
            433155458, 82591339, 459412819, 435604627, 312211805, 98158590, 752137480, 446017293, 666480139, 60261988, 275386848, 642778031, 8582401, 677484160, 819506256, 333441964,
            25465219, 190315429, 91529631, 754681170, 563660271, 167135649, 20270015, 115773732, 658954441, 132923202, 844102455, 453432758, 250487209, 423813160, 632223296, 537494486,
            158265753, 327949044, 494109748, 659672289, 67984726, 422358258, 345141182, 164372996, 338500924, 41400311, 207638305, 832074651, 50853458, 228267776, 621895888, 635834787,
            484972544, 181125024, 558134871, 282159878, 788157855, 145576343, 194837894, 501440949, 63641414, 252098681, 835930645, 662856247, 456140980, 206147937, 565198503, 449503819,
            684013129, 494002381, 793836418, 649296754, 444313288, 136544068, 540002286, 355912945, 613175147, 134541429, 843111781, 672612536, 541098995, 734996181, 211869705, 620777828,
            756152791, 242128346, 795442420, 73925532, 735232214, 738668090, 530800757, 266183732, 97165934, 803231879, 10057267, 175942047, 181460965, 320684297, 637472526, 213840116,
            182671953, 152704513, 388004388, 597349323, 473851493, 445333546, 679315863, 267078568, 46538491, 530171754, 698082287, 75308587, 266467406, 96440883, 759196579, 470119952,
            381731475, 428392158, 10628712, 173921356, 116809433, 323843928, 812172630, 403459283, 655501128, 261944441, 774418023, 790520709, 589149480, 264133112, 806274256, 752372117,
            66236193, 713859568, 90804933, 551864345, 843839891, 600244073, 719230074, 803646506, 254956426, 138935723, 738829647, 109576220, 105819621, 249706947, 110623114, 10002331,
            795710911, 547062229, 721440199, 820747461, 397666160, 685179945, 463869301, 470338753, 641244231, 652990696, 698429485, 41147155, 638072709, 515832968, 241130026, 314161759,
            526815813, 529167244, 53391331, 782008115, 822962086, 337706389, 648197286, 209496506, 760818531, 781900302, 717270807, 709143641, 740503641, 734328409, 514061476, 844010670,
            67993787, 712083588, 319801387, 338260400, 48758556, 304195768, 478833380, 841413917, 710197685, 196321647, 777595184, 775983866, 147506314, 620961439, 399972264, 398715644,
            684489092, 659918078, 664075287, 723890579, 643103903, 508525962, 375409248, 501237729, 740609783, 639854810, 510797913, 521151016, 421045341, 193698327, 800266392, 93518128,
            443879633, 699245445, 194001794, 123905867, 75572337, 242620749, 463111940, 755239011, 31718790, 162155292, 386689240, 381413538, 745322913, 367897558, 343088005, 31706107,
            10842029, 404961623, 537521191, 281624684, 372852160, 55286017, 534907560, 264398082, 667644310, 486871690, 716964533, 734731419, 143593638, 293949413, 760014789, 594443755,
            147804127, 537704286, 460110740, 596458323, 577775570, 333025386, 260094086, 711487611, 359384182, 323339045, 716675075, 248179763, 525311626, 76326208, 559009987, 548139736,
            541721430, 31450329, 653923741, 676193285, 295171241, 558845563, 387079118, 403184480, 807941436, 501042343, 284608894, 705710380, 82388415, 763336555, 126077422, 438548854,
            606252517, 144569238, 126964439, 809559381, 263253751, 547929033, 236704198, 377978058, 59501955, 749500335, 254242336, 605755194, 408388953, 116242711, 116340056, 691021496,
            48100285, 371076069, 638156108, 211570763, 185945242, 653505761, 667569173, 335131755, 736662207, 572078378, 755939949, 840393623, 322934679, 520522390, 252068808, 491370519,
            200565770, 552637112, 182345569, 394747039, 822229467, 817698102, 644484388, 156591766, 729600982, 695826242, 509682463, 785132583, 746139100, 188369785, 628995003, 406654440,
            650660075, 676485042, 540766742, 493428142, 753346328, 82608613, 670846442, 145894970, 770907988, 621807160, 14676199, 793865193, 36579515, 619741404, 303691972, 794920577,
            134684826, 190038753, 538889970, 836657477, 643017556, 316870164, 464572481, 305395359, 446406992, 587814221, 423552502, 122802120, 146043780, 173756097, 130720237, 445515559,
            109884833, 133119099, 804139234, 834841519, 458514524, 74213698, 490363622, 119287122, 165016718, 351506713, 433750226, 439149867, 348281119, 319795826, 320785867, 446561207,
            705678831, 714536161, 172299381, 552925586, 635421942, 851853231, 208071525, 142303096, 93164236, 207534795, 655906672, 558127940, 98870558, 388322132, 87475979, 835970665,
            61996500, 298060757, 256194194, 563529863, 249184704, 451295997, 73892211, 559049908, 44006160, 832886345, 720732161, 255948582, 827295342, 629663637, 323103159, 155698755,
            598913314, 586685341, 761273875, 135225209, 324099714, 391112815, 493469140, 796490769, 667498514, 148390126, 721802249, 781884558, 309264043, 603401759, 503111668, 563611748,
            363342598, 383209405, 108340736, 758017880, 145907493, 312330194, 608895549, 45540348, 143092704, 772401556, 806068040, 853177536, 662120004, 463347842, 495085709, 560431884,
            274002454, 76985308, 519320299, 253092838, 727478114, 593752634, 490277266, 206283832, 701277908, 504787112, 816832531, 730997507, 27807749, 58254704, 584933136, 515463756,
            241104222, 251881934, 566567573, 592887586, 528932268, 88111104, 523103099, 448331392, 351083975, 157811347, 758866581, 802151021, 843579185, 481417280, 507414106, 462708367,
            461501222, 790988186, 462220673, 727683888, 159759683, 59757110, 310746434, 326369241, 305829588, 457718309, 529317279, 503631310, 661769334, 343160359, 472216278, 740498212,
            11312284, 760170115, 513391009, 538224236, 710934956, 491998229, 539829044, 610387964, 86624968, 72542777, 493966272, 132327984, 371526334, 182549152, 51622114, 173997077,
            550633787, 205437301, 435219235, 406409162, 414751325, 33371226, 40899348, 77245052, 763383124, 817701136, 598256078, 357440859, 468418959, 353612800, 721601331, 262567156,
            521577430, 232027892, 75986872, 443113391, 107360999, 482079354, 563502258, 782475535, 402866161, 515580626, 742688144, 677398836, 425899303, 42066550, 537192943, 430672016,
            115368023, 64053241, 92008456, 74327791, 572607165, 681138002, 378104858, 695786430, 844827190, 436817825, 751393351, 142965259, 81300919, 688342617, 433082724, 221191094,
            712003270, 301076404, 747091407, 514191589, 814985450, 260951422, 187161058, 22316970, 806106670, 759397054, 158423624, 419813636, 462241316, 438231460, 108466764, 212745115,
            386264342, 176072326, 767127195, 399981627, 762991681, 173125691, 464627163, 770046798, 179369718, 829917528, 693004603, 178596003, 422852852, 182684967, 662425026, 713404098,
            766206683, 130088738, 321282752, 134898541, 86701214, 120555423, 464987852, 82865891, 758340585, 138256323, 308997895, 659614345, 510091933, 822699180, 464631718, 819896232,
            120792059, 160708255, 462868879, 72974246, 260451492, 120601343, 228097712, 369436704, 155304088, 74380537, 732305166, 203294189, 307421597, 96510570, 634243454, 486539430,
            16204477, 241987531, 317824421, 510180366, 794475492, 262770124, 441034891, 741864347, 205569410, 684844547, 340863522, 440616421, 454438375, 26285496, 141886125, 648947081,
            3791510, 529746935, 317826713, 411458050, 661690316, 45696331, 679684665, 184597094, 829228068, 375683582, 591739456, 855242340, 628594662, 30968619, 363932244, 103091463,
            614269714, 465960778, 791477766, 332731888, 853151007, 266045534, 132189407, 435008168, 65667470, 669304246, 760035868, 481409581, 36650645, 523634336, 702968013, 351902214,
            284360680, 34261165, 593134528, 337534074, 239112910, 710342799, 163287447, 20209506, 780785984, 480727309, 125776519, 691236193, 603228570, 48261672, 183120677, 73638683,
            3430616, 568026489, 808739797, 298585898, 64471573, 724550960, 568093636, 187449517, 655699449, 672689645, 829049456, 263525899, 612969883, 621652807, 186362075, 731851539,
            377104257, 39335761, 210768226, 253965025, 201921517, 715681274, 369453531, 18897741, 612559390, 660723864, 476963596, 585483298, 318614839, 227626072, 298891387, 110505944,
            814885802, 177563961, 443724544, 374856237, 577963338, 617516835, 475669105, 633353115, 12579943, 796644307, 569746680, 22381253, 343603333, 724567543, 845363898, 4023795,
            801359177, 347489967, 214644600, 78674056, 131782857, 284041623, 660502381, 161470286, 668158595, 765738294, 715872268, 678418089, 280458288, 758715787, 9311288, 490771912,
            757112000, 253990619, 698573830, 390611635, 52593584, 421202448, 494394112, 386893540, 29349323, 533111491, 774401558, 108660117, 405990553, 143728136, 852741683, 354532633,
            440222591, 663461253, 593338391, 298882952, 758170600, 660294062, 332348846, 541714172, 77716403, 169377728, 71932929, 110210904, 776771173, 645222398, 162195941, 792388932,
            502165627, 146897021, 243625970, 139123400, 462352793, 409369440, 247509680, 270865496, 539140627, 16949766, 245869282, 637926655, 37386603, 383033875, 316560876, 707909555,
            367315004, 173821041, 529529257, 227507318, 831716891, 830055847, 228911074, 205127100, 178872273, 819938491, 129875615, 764680417, 97028082, 560682982, 433649390, 727508847,
            494848582, 81279272, 435186566, 174468080, 69172161, 241860102, 692179355, 333985572, 788895276, 469576414, 594155471, 157828532, 182105752, 310394758, 673085082, 695719789,
            39004854, 251000641, 98748282, 744318650, 815050298, 622456803, 240419561, 403871914, 202214044, 627433637, 649505808, 668918393, 334630440, 386856024, 352649543, 135139523,
            216499252, 736376783, 269223150, 468318208, 801808348, 180378366, 640086372, 672618369, 291378195, 732195369, 805632553, 518515631, 603280165, 629836417, 59712833, 531020081,
            708771168, 539819295, 179149444, 552251927, 458994127, 584987693, 238644928, 640603619, 46728500, 843989005, 688747457, 236924093, 261539965, 705411056, 765907765, 38095657,
            382461698, 146650814, 351462947, 749417520, 628887925, 800857475, 790554154, 695483946, 160495923, 40896482, 471385785, 535516195, 197056285, 622795937, 368016917, 696525353,
            377315918, 58087122, 246518254, 431338589, 795949654, 611141265, 406307405, 365750089, 396243561, 843849531, 33802729, 573076974, 557841126, 411725124, 109489622, 370935707,
            372610558, 769825999, 367932152, 231499145, 240819898, 22648665, 418344529, 142438794, 552806180, 669450690, 614608056, 784369586, 258710636, 474742428, 166021530, 805595815,
            603578176, 686703780, 412868426, 26588048, 379895115, 77550061, 751188758, 294447541, 433574579, 234362222, 821492181, 23912038, 681093196, 483584545, 404339808, 396405029,
            744756742, 702481685, 413127074, 204115019, 187381271, 633523978, 433629465, 628184183, 783160918, 268799033, 646479372, 160458176, 602612912, 644506365, 391554011, 676966578,
            386430153, 98736426, 412745127, 296141927, 685909285, 355152260, 361415843, 127323093, 586337666, 1734791, 368678692, 155431915, 597290023, 109507713, 291804866, 135016081,
            144077689, 35054937, 16808265, 431962815, 534195521, 629326143, 309352001, 319948849, 443083246, 336744161, 100845182, 314804947, 476736581, 468528479, 416978018, 35141019,
            43314058, 384847955, 665126798, 295857628, 768013680, 741182796, 157855570, 695547618, 145251639, 818473396, 708640763, 87460130, 736400748, 465173936, 376720282, 437268868,
            137236663, 693860377, 247960644, 402124416, 656418852, 231401654, 248187016, 628418583, 224261112, 120581342, 49749199, 588812480, 309599954, 111357387, 14507354, 754564049,
            513444423, 816496110, 509193085, 361635970, 190608265, 697367838, 230953561, 140447357, 27745100, 163340427, 607823059, 325305463, 383028479, 269707244, 475022415, 708990989,
            738971809, 797646021, 126610937, 589310701, 191123172, 819715815, 337443183, 432224976, 337343783, 257301390, 172631141, 560659319, 646332329, 55110483, 467212803, 442977895,
            311159578, 569890333, 669396086, 536323022, 542648615, 366162176, 88951009, 408335586, 276237497, 384733042, 525960156, 74199534, 338209206, 676233089, 264342641, 241682204,
            226505461, 165013960, 129858819, 664852498, 432090291, 165700308, 382150900, 537002255, 368893910, 61006155, 238726881, 92317627, 632392147, 404715651, 802622348, 126100061,
            306024238, 397891265, 214661020, 211132870, 783722518, 149847645, 665379914, 624725195, 85864665, 496272723, 304811252, 29995710, 410500887, 756406394, 31206753, 647154006,
            596539568, 783214792, 286381882, 24560691, 681500270, 774933112, 506538708, 850347997, 611696036, 512607061, 251719669, 367108021, 456442965, 636694730, 399940257, 73870039,
            85190759, 264953709, 238854238, 395048514, 612738126, 27417876, 652695826, 188238483, 324168828, 736238139, 789061724, 529275445, 382304068, 176318391, 709989466, 14237691,
        };

        private static final long[] zetainv = new long[]{
            146156455, 679827530, 473841853, 326870476, 67084197, 119907782, 531977093, 667907438, 203450095, 828728045, 243407795, 461097407, 617291683, 591192212, 770955162, 782275882,
            456205664, 219451191, 399702956, 489037900, 604426252, 343538860, 244449885, 5797924, 349607213, 81212809, 174645651, 831585230, 569764039, 72931129, 259606353, 208991915,
            824939168, 99739527, 445645034, 826150211, 551334669, 359873198, 770281256, 231420726, 190766007, 706298276, 72423403, 645013051, 641484901, 458254656, 550121683, 730045860,
            53523573, 451430270, 223753774, 763828294, 617419040, 795139766, 487252011, 319143666, 473995021, 690445613, 424055630, 191293423, 726287102, 691131961, 629640460, 614463717,
            591803280, 179912832, 517936715, 781946387, 330185765, 471412879, 579908424, 447810335, 767194912, 489983745, 313497306, 319822899, 186749835, 286255588, 544986343, 413168026,
            388933118, 801035438, 209813592, 295486602, 683514780, 598844531, 518802138, 423920945, 518702738, 36430106, 665022749, 266835220, 729534984, 58499900, 117174112, 147154932,
            381123506, 586438677, 473117442, 530840458, 248322862, 692805494, 828400821, 715698564, 625192360, 158778083, 665537656, 494509951, 346952836, 39649811, 342701498, 101581872,
            841638567, 744788534, 546545967, 267333441, 806396722, 735564579, 631884809, 227727338, 607958905, 624744267, 199727069, 454021505, 608185277, 162285544, 718909258, 418877053,
            479425639, 390971985, 119745173, 768685791, 147505158, 37672525, 710894282, 160598303, 698290351, 114963125, 88132241, 560288293, 191019123, 471297966, 812831863, 821004902,
            439167903, 387617442, 379409340, 541340974, 755300739, 519401760, 413062675, 536197072, 546793920, 226819778, 321950400, 424183106, 839337656, 821090984, 712068232, 721129840,
            564341055, 746638208, 258855898, 700714006, 487467229, 854411130, 269808255, 728822828, 494730078, 500993661, 170236636, 560003994, 443400794, 757409495, 469715768, 179179343,
            464591910, 211639556, 253533009, 695687745, 209666549, 587346888, 72985003, 227961738, 422516456, 222621943, 668764650, 652030902, 443018847, 153664236, 111389179, 459740892,
            451806113, 372561376, 175052725, 832233883, 34653740, 621783699, 422571342, 561698380, 104957163, 778595860, 476250806, 829557873, 443277495, 169442141, 252567745, 50550106,
            690124391, 381403493, 597435285, 71776335, 241537865, 186695231, 303339741, 713707127, 437801392, 833497256, 615326023, 624646776, 488213769, 86319922, 483535363, 485210214,
            746656299, 444420797, 298304795, 283068947, 822343192, 12296390, 459902360, 490395832, 449838516, 245004656, 60196267, 424807332, 609627667, 798058799, 478830003, 159620568,
            488129004, 233349984, 659089636, 320629726, 384760136, 815249439, 695649998, 160661975, 65591767, 55288446, 227257996, 106728401, 504682974, 709495107, 473684223, 818050264,
            90238156, 150734865, 594605956, 619221828, 167398464, 12156916, 809417421, 215542302, 617500993, 271158228, 397151794, 303893994, 676996477, 316326626, 147374753, 325125840,
            796433088, 226309504, 252865756, 337630290, 50513368, 123950552, 564767726, 183527552, 216059549, 675767555, 54337573, 387827713, 586922771, 119769138, 639646669, 721006398,
            503496378, 469289897, 521515481, 187227528, 206640113, 228712284, 653931877, 452274007, 615726360, 233689118, 41095623, 111827271, 757397639, 605145280, 817141067, 160426132,
            183060839, 545751163, 674040169, 698317389, 261990450, 386569507, 67250645, 522160349, 163966566, 614285819, 786973760, 681677841, 420959355, 774866649, 361297339, 128637074,
            422496531, 295462939, 759117839, 91465504, 726270306, 36207430, 677273648, 651018821, 627234847, 26090074, 24429030, 628638603, 326616664, 682324880, 488830917, 148236366,
            539585045, 473112046, 818759318, 218219266, 610276639, 839196155, 317005294, 585280425, 608636241, 446776481, 393793128, 717022521, 612519951, 709248900, 353980294, 63756989,
            693949980, 210923523, 79374748, 745935017, 784212992, 686768193, 778429518, 314431749, 523797075, 195851859, 97975321, 557262969, 262807530, 192684668, 415923330, 501613288,
            3404238, 712417785, 450155368, 747485804, 81744363, 323034430, 826796598, 469252381, 361751809, 434943473, 803552337, 465534286, 157572091, 602155302, 99033921, 365374009,
            846834633, 97430134, 575687633, 177727832, 140273653, 90407627, 187987326, 694675635, 195643540, 572104298, 724363064, 777471865, 641501321, 508655954, 54786744, 852122126,
            10782023, 131578378, 512542588, 833764668, 286399241, 59501614, 843565978, 222792806, 380476816, 238629086, 278182583, 481289684, 412421377, 678581960, 41260119, 745639977,
            557254534, 628519849, 537531082, 270662623, 379182325, 195422057, 243586531, 837248180, 486692390, 140464647, 654224404, 602180896, 645377695, 816810160, 479041664, 124294382,
            669783846, 234493114, 243176038, 592620022, 27096465, 183456276, 200446472, 668696404, 288052285, 131594961, 791674348, 557560023, 47406124, 288119432, 852715305, 782507238,
            673025244, 807884249, 252917351, 164909728, 730369402, 375418612, 75359937, 835936415, 692858474, 145803122, 617033011, 518611847, 263011393, 821884756, 571785241, 504243707,
            153177908, 332511585, 819495276, 374736340, 96110053, 186841675, 790478451, 421137753, 723956514, 590100387, 2994914, 523414033, 64668155, 390185143, 241876207, 753054458,
            492213677, 825177302, 227551259, 903581, 264406465, 480462339, 26917853, 671548827, 176461256, 810449590, 194455605, 444687871, 538319208, 326398986, 852354411, 207198840,
            714259796, 829860425, 401707546, 415529500, 515282399, 171301374, 650576511, 114281574, 415111030, 593375797, 61670429, 345965555, 538321500, 614158390, 839941444, 369606491,
            221902467, 759635351, 548724324, 652851732, 123840755, 781765384, 700841833, 486709217, 628048209, 735544578, 595694429, 783171675, 393277042, 695437666, 735353862, 36249689,
            391514203, 33446741, 346053988, 196531576, 547148026, 717889598, 97805336, 773280030, 391158069, 735590498, 769444707, 721247380, 534863169, 726057183, 89939238, 142741823,
            193720895, 673460954, 433293069, 677549918, 163141318, 26228393, 676776203, 86099123, 391518758, 683020230, 93154240, 456164294, 89018726, 680073595, 469881579, 643400806,
            747679157, 417914461, 393904605, 436332285, 697722297, 96748867, 50039251, 833828951, 668984863, 595194499, 41160471, 341954332, 109054514, 555069517, 144142651, 634954827,
            423063197, 167803304, 774845002, 713180662, 104752570, 419328096, 11318731, 160359491, 478041063, 175007919, 283538756, 781818130, 764137465, 792092680, 740777898, 425473905,
            318952978, 814079371, 430246618, 178747085, 113457777, 340565295, 453279760, 73670386, 292643663, 374066567, 748784922, 413032530, 780159049, 624118029, 334568491, 593578765,
            134544590, 502533121, 387726962, 498705062, 257889843, 38444785, 92762797, 778900869, 815246573, 822774695, 441394596, 449736759, 420926686, 650708620, 305512134, 682148844,
            804523807, 673596769, 484619587, 723817937, 362179649, 783603144, 769520953, 245757957, 316316877, 364147692, 145210965, 317921685, 342754912, 95975806, 844833637, 115647709,
            383929643, 512985562, 194376587, 352514611, 326828642, 398427612, 550316333, 529776680, 545399487, 796388811, 696386238, 128462033, 393925248, 65157735, 394644699, 393437554,
            348731815, 374728641, 12566736, 53994900, 97279340, 698334574, 505061946, 407814529, 333042822, 768034817, 327213653, 263258335, 289578348, 604263987, 615041699, 340682165,
            271212785, 797891217, 828338172, 125148414, 39313390, 351358809, 154868013, 649862089, 365868655, 262393287, 128667807, 603053083, 336825622, 779160613, 582143467, 295714037,
            361060212, 392798079, 194025917, 2968385, 50077881, 83744365, 713053217, 810605573, 247250372, 543815727, 710238428, 98128041, 747805185, 472936516, 492803323, 292534173,
            353034253, 252744162, 546881878, 74261363, 134343672, 707755795, 188647407, 59655152, 362676781, 465033106, 532046207, 720920712, 94872046, 269460580, 257232607, 700447166,
            533042762, 226482284, 28850579, 600197339, 135413760, 23259576, 812139761, 297096013, 782253710, 404849924, 606961217, 292616058, 599951727, 558085164, 794149421, 20175256,
            768669942, 467823789, 757275363, 298017981, 200239249, 648611126, 762981685, 713842825, 648074396, 4292690, 220723979, 303220335, 683846540, 141609760, 150467090, 409584714,
            535360054, 536350095, 507864802, 416996054, 422395695, 504639208, 691129203, 736858799, 365782299, 781932223, 397631397, 21304402, 52006687, 723026822, 746261088, 410630362,
            725425684, 682389824, 710102141, 733343801, 432593419, 268331700, 409738929, 550750562, 391573440, 539275757, 213128365, 19488444, 317255951, 666107168, 721461095, 61225344,
            552453949, 236404517, 819566406, 62280728, 841469722, 234338761, 85237933, 710250951, 185299479, 773537308, 102799593, 362717779, 315379179, 179660879, 205485846, 449491481,
            227150918, 667776136, 110006821, 71013338, 346463458, 160319679, 126544939, 699554155, 211661533, 38447819, 33916454, 461398882, 673800352, 303508809, 655580151, 364775402,
            604077113, 335623531, 533211242, 15752298, 100205972, 284067543, 119483714, 521014166, 188576748, 202640160, 670200679, 644575158, 217989813, 485069852, 808045636, 165124425,
            739805865, 739903210, 447756968, 250390727, 601903585, 106645586, 796643966, 478167863, 619441723, 308216888, 592892170, 46586540, 729181482, 711576683, 249893404, 417597067,
            730068499, 92809366, 773757506, 150435541, 571537027, 355103578, 48204485, 452961441, 469066803, 297300358, 560974680, 179952636, 202222180, 824695592, 314424491, 308006185,
            297135934, 779819713, 330834295, 607966158, 139470846, 532806876, 496761739, 144658310, 596051835, 523120535, 278370351, 259687598, 396035181, 318441635, 708341794, 261702166,
            96131132, 562196508, 712552283, 121414502, 139181388, 369274231, 188501611, 591747839, 321238361, 800859904, 483293761, 574521237, 318624730, 451184298, 845303892, 824439814,
            513057916, 488248363, 110823008, 474732383, 469456681, 693990629, 824427131, 100906910, 393033981, 613525172, 780573584, 732240054, 662144127, 156900476, 412266288, 762627793,
            55879529, 662447594, 435100580, 334994905, 345348008, 216291111, 115536138, 354908192, 480736673, 347619959, 213042018, 132255342, 192070634, 196227843, 171656829, 457430277,
            456173657, 235184482, 708639607, 80162055, 78550737, 659824274, 145948236, 14732004, 377312541, 551950153, 807387365, 517885521, 536344534, 144062333, 788152134, 12135251,
            342084445, 121817512, 115642280, 147002280, 138875114, 74245619, 95327390, 646649415, 207948635, 518439532, 33183835, 74137806, 802754590, 326978677, 329330108, 541984162,
            615015895, 340312953, 218073212, 814998766, 157716436, 203155225, 214901690, 385807168, 392276620, 170965976, 458479761, 35398460, 134705722, 309083692, 60435010, 846143590,
            745522807, 606438974, 750326300, 746569701, 117316274, 717210198, 601189495, 52499415, 136915847, 255901848, 12306030, 304281576, 765340988, 142286353, 789909728, 103773804,
            49871665, 592012809, 266996441, 65625212, 81727898, 594201480, 200644793, 452686638, 43973291, 532301993, 739336488, 682224565, 845517209, 427753763, 474414446, 386025969,
            96949342, 759705038, 589678515, 780837334, 158063634, 325974167, 809607430, 589067353, 176830058, 410812375, 382294428, 258796598, 468141533, 703441408, 673473968, 642305805,
            218673395, 535461624, 674684956, 680203874, 846088654, 52914042, 758979987, 589962189, 325345164, 117477831, 120913707, 782220389, 60703501, 614017575, 99993130, 235368093,
            644276216, 121149740, 315046926, 183533385, 13034140, 721604492, 242970774, 500232976, 316143635, 719601853, 411832633, 206849167, 62309503, 362143540, 172132792, 406642102,
            290947418, 649997984, 400004941, 193289674, 20215276, 604047240, 792504507, 354704972, 661308027, 710569578, 67988066, 573986043, 298011050, 675020897, 371173377, 220311134,
            234250033, 627878145, 805292463, 24071270, 648507616, 814745610, 517644997, 691772925, 511004739, 433787663, 788161195, 196473632, 362036173, 528196877, 697880168, 318651435,
            223922625, 432332761, 605658712, 402713163, 12043466, 723222719, 197191480, 740372189, 835875906, 689010272, 292485650, 101464751, 764616290, 665830492, 830680702, 522703957,
            36639665, 178661761, 847563520, 213367890, 580759073, 795883933, 189665782, 410128628, 104008441, 757987331, 543934116, 420541294, 396733102, 773554582, 422990463, 679308804,
            471610475, 449025573, 293585715, 304333306, 606221987, 668107507, 201587373, 776461576, 54202261, 334132687, 570371370, 729669465, 388035450, 40739162, 294599466, 269999181,
            368420277, 394723115, 506277838, 351687671, 683668119, 82918314, 72721076, 702889204, 841003831, 721904142, 691037495, 575492049, 221172299, 608377016, 584007171, 674474012,
            135083989, 479195654, 408808739, 442284285, 530250590, 390248853, 461685089, 283253906, 717741307, 215568024, 562986577, 134817130, 147002383, 270825931, 379404006, 759183054,
            581866917, 146566613, 784989241, 457129596, 59158644, 750640670, 700398504, 721509487, 402874366, 82387404, 95739856, 281346626, 467686791, 324137743, 11249127, 89157220,
            716002070, 335342053, 246826170, 529385048, 760143990, 10725758, 516293110, 76538324, 257296477, 328165824, 172330118, 546825765, 619673906, 328792017, 788124094, 141927682,
            555365723, 329427916, 607839982, 405389708, 571868667, 470002428, 684585751, 434604631, 204705039, 450529242, 361817407, 727855567, 413589322, 11544453, 803784599, 815775166,
            425469974, 86512573, 86029713, 852702639, 728364190, 118324485, 477615251, 345426513, 219927860, 22417298, 480050287, 224592838, 759159, 131898579, 764335555, 457432197,
            763875505, 642888584, 590641758, 210009158, 390019414, 235949401, 58219618, 562286114, 99631682, 631925366, 753164064, 328774959, 365242602, 385354452, 217542778, 795464774,
            780632705, 678141873, 424450214, 25338472, 268284342, 493213958, 580867867, 15482483, 272837023, 328359708, 782291772, 308114267, 404813197, 333753982, 737682027, 538312006,
            707909990, 234156623, 323140190, 803917719, 91035383, 200098402, 773260410, 554209269, 505977196, 258732217, 577347247, 388868026, 412079442, 312571314, 628683299, 740119334,
            813470861, 86544483, 515146109, 371343866, 687853001, 265823977, 121589622, 808348288, 257353942, 635427508, 834922294, 224797491, 432675367, 731353224, 575538372, 642351606,
            291366364, 210732817, 90658793, 146401688, 40748954, 527574284, 817614743, 547167333, 534136352, 372456076, 706600074, 640500788, 559786839, 845776458, 709348802, 677707036,
            606711824, 349565805, 42095011, 472115432, 177053484, 681164976, 139728272, 510212596, 747795405, 441873933, 187174498, 392929945, 425171378, 555237229, 4315335, 9057268,
            153360848, 99426909, 774527252, 83014618, 412368218, 3495282, 739674290, 826674363, 316599527, 110724402, 435058302, 156418860, 545209527, 681526436, 443190082, 613052844,
            463370538, 710824143, 207309740, 783222241, 141846134, 266325996, 146201876, 449154790, 170683627, 716235176, 607164090, 291006513, 186310404, 43734965, 496486286, 736873833,
            329899967, 408796174, 449053875, 589454563, 727957502, 460484783, 122169115, 75292611, 73671599, 848010384, 303936940, 791662107, 590932920, 125786858, 211282605, 729648214,
            59156462, 152461927, 219894477, 776823847, 437757228, 186542194, 700611431, 257929382, 767315412, 18312688, 806906190, 504497667, 101165190, 603435510, 526872520, 254322283,
            720021990, 779194394, 584710319, 801191565, 703649817, 361258161, 149741435, 808495563, 291596204, 250916275, 340042453, 141837377, 547502361, 181348702, 139498738, 338114582,
            119328746, 177984134, 199957575, 358181386, 57332620, 512567111, 451958433, 156026128, 619998073, 307816265, 338764588, 65822147, 573828018, 487154809, 749222428, 522943099,
            26336097, 186644498, 526288314, 534618890, 828269735, 675600958, 49788769, 453731878, 762637295, 387744335, 173171058, 33040483, 466949551, 843388255, 697432416, 216291746,
            33282177, 240642656, 663436347, 390123214, 254438583, 190922896, 455331923, 296664914, 762697018, 331531324, 851176113, 771233913, 482330259, 389665212, 474944010, 58762628,
            469089651, 436049255, 697216430, 431783325, 138107147, 499492245, 647224366, 407794272, 26067376, 445177552, 520720342, 798948406, 325365361, 117634101, 664099671, 153294810,
            597801361, 640257687, 533951825, 702134729, 111685295, 685214097, 452013666, 317534558, 271219665, 529108611, 586379543, 355661610, 759841823, 446485943, 839034731, 33604088,
            773212146, 191869702, 367354365, 689096322, 345311446, 438596834, 677372537, 542545550, 341130619, 292644024, 281192613, 251893811, 447792713, 520181371, 40921126, 778878825,
            536838039, 230752698, 396625895, 601216134, 188488092, 130103565, 504870771, 413838340, 335573256, 124340986, 368340993, 243753204, 150144590, 808689996, 32468801, 68817331,
            471378712, 566347573, 6430376, 651137151, 497752158, 823732827, 787280015, 789046852, 194658966, 171151811, 118113814, 793917550, 75187158, 717603845, 61671631, 51620383,
            302490719, 78328345, 244847301, 549511806, 420356371, 560795789, 405546061, 302036596, 432306081, 270856136, 330554928, 212724399, 791196206, 445342723, 187781362, 87078067,
            834667388, 218628624, 755629702, 148790011, 845609309, 89984158, 742118272, 475309628, 81731129, 107846408, 74447254, 68656823, 169459843, 643648059, 721924181, 212112779,
            575076242, 471039705, 626114838, 564548835, 506450263, 488329877, 847101683, 592828368, 714089721, 832868261, 393063639, 603199595, 214221357, 747808090, 145225511, 784491117,
            578386518, 253504617, 217256612, 432640963, 696210495, 700338942, 642132261, 394125773, 127189460, 622643989, 65557316, 850423288, 154198317, 360118020, 401298167, 809808378,
            590060278, 378333119, 261388063, 301240958, 211172470, 476577014, 818999735, 320797504, 155490801, 362021897, 416507223, 193972866, 814253796, 555879930, 152626252, 598011677,
            48971665, 590814257, 699100720, 732535868, 42427027, 335391594, 577502901, 72445917, 562054823, 34689534, 850274973, 640356274, 165636151, 309704599, 39996866, 436255023,
            365085534, 208984696, 593049885, 755419039, 376895434, 634901252, 316743954, 476563344, 619551824, 766199910, 783651060, 32670169, 794822305, 435248113, 14247580, 284417137,
            754554090, 30678221, 641072629, 711946716, 568640914, 656468482, 83597913, 356324101, 231391682, 122476642, 505437404, 636148283, 639556222, 262242870, 10083895, 470763095,
            7162643, 490677454, 122627583, 711718981, 252376484, 423795716, 578101600, 275970963, 3053131, 327430341, 435804223, 349044314, 649311691, 234207954, 379806804, 342513855,
            224624649, 181857560, 84797030, 123047825, 95186646, 293471117, 586961654, 111168138, 703259490, 756871363, 606284506, 380213718, 292725815, 463763080, 747629289, 254624782,
            207883602, 849297083, 578506664, 656289117, 454015629, 162235991, 474249177, 633829447, 490767799, 210190430, 48735841, 656982789, 743473215, 47313566, 306689440, 53334547,
            370344121, 419993940, 218969756, 341956367, 296184959, 135682817, 127205066, 744169001, 445909513, 801533404, 605661030, 181244618, 30772614, 196639386, 59911722, 616623643,
            199307436, 551535136, 136575017, 79424355, 92705102, 498046224, 17339996, 698541762, 804348245, 104258042, 484400476, 535014225, 87644978, 121726462, 383782353, 77562877,
            350468417, 724994239, 772938366, 320269449, 203075846, 465307490, 585234251, 271855066, 464423241, 403123130, 202162074, 117126999, 653413020, 8084225, 216658351, 409614891,
            799241223, 600931579, 454131285, 782741932, 376344215, 79696641, 803438191, 565030050, 460657460, 5110534, 472517130, 76991417, 572426425, 92047134, 285371277, 843473400,
            389338704, 704515255, 459914006, 657120075, 708563883, 78813141, 11770883, 688134435, 287808573, 649280542, 765338883, 439803770, 160535862, 617753423, 442051682, 288864924,
            32955626, 326880188, 696887038, 215124062, 791918307, 767157413, 358676037, 30612492, 661971023, 838968782, 465224708, 784600829, 146985424, 799718881, 207906900, 340800263,
            849693954, 44777992, 31326149, 240259940, 508401593, 499528021, 475930852, 690672059, 580019353, 297040464, 236338202, 454171188, 695134912, 508172471, 436504159, 293630619,
            848875161, 37043893, 26993038, 396046068, 722016462, 445419380, 209243403, 503786686, 268117854, 281672598, 205034970, 87894257, 293598267, 46912651, 147959859, 462629641,
            509044664, 700768221, 107374762, 340721447, 163551982, 247501118, 447395984, 318219025, 172114399, 110025830, 810265637, 370215004, 606303954, 462642711, 251114029, 290800715,
            780017258, 789443137, 495480307, 615909633, 431756150, 766376396, 820732666, 686803688, 133668454, 761665150, 326017339, 424112204, 110554261, 386347465, 101066781, 135666139,
            256882780, 205722545, 668032392, 405718561, 350327055, 621444438, 381307379, 421184831, 753121128, 590538618, 366906511, 345326178, 132085192, 40531091, 780676557, 586664955,
            597888984, 693668509, 487104387, 234747974, 572624063, 114516856, 550027276, 316481563, 239535126, 788436714, 847219527, 113421825, 200615887, 815912760, 581164384, 191193216,
            11551938, 606832431, 431210833, 196126697, 92508342, 270544041, 192437514, 99153842, 188585579, 413385580, 745267475, 448172363, 667109106, 85272138, 658601344, 443173146,
            392530856, 589073317, 382995167, 248915715, 375600977, 386782401, 254322056, 790853708, 580714915, 163129486, 824017519, 86419559, 117205367, 634667017, 566451589, 852749522,
            837490424, 330422330, 294598189, 814909626, 505390042, 125578715, 357313675, 450539487, 233746299, 446282749, 755039478, 740350430, 598956163, 116099139, 167482754, 310512355,
            135624781, 470874939, 196356683, 239902897, 693520220, 454942578, 778240578, 45236161, 51101673, 270126615, 94622194, 524282161, 632376971, 703121383, 587013336, 572429454,
            37728898, 143682359, 206045437, 557167425, 770459696, 477771773, 321346425, 290390778, 100874902, 758540246, 746805823, 459566327, 607673901, 158286491, 527010720, 579461268,
            74963118, 420964844, 51316958, 250512679, 452729483, 35670488, 559935164, 734294507, 379228497, 172592106, 126508187, 757555710, 853874620, 808517874, 106015915, 375691866,
            423413164, 423111661, 60250078, 645353691, 853830811, 288310932, 1489804, 127886925, 191505834, 459549138, 542519706, 369115379, 116842790, 784888677, 269818678, 712117130,
            748410048, 139982101, 169805525, 32264681, 532400632, 397389041, 181262233, 703428567, 604760852, 44143128, 69914527, 86615396, 314810965, 68145528, 650868687, 717671367,
            594246701, 641155397, 207406129, 180083553, 414651973, 132523243, 211350471, 397371331, 170688638, 732763563, 132155217, 394688247, 571356350, 93856418, 708831649, 841908230,
        };


        static void poly_uniform(long[] a, byte[] seed, int seedOffset)
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


        static long reduce(long a)
        { // Montgomery reduction
            long u;

            u = (a * (long)PARAM_QINV) & 0xFFFFFFFFL;
            u *= PARAM_Q;
            a += u;
            return a >> 32;
        }


        static void ntt(long[] a, long[] w)
        { // Forward NTT transform
            int NumoProblems = PARAM_N >> 1, jTwiddle = 0;

            for (; NumoProblems > 0; NumoProblems >>= 1)
            {
                int jFirst, j = 0;
                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems)
                {
                    int W = (int)w[jTwiddle++];
                    for (j = jFirst; j < jFirst + NumoProblems; j++)
                    {
                        long temp = barr_reduce(reduce(W * a[j + NumoProblems]));
                        a[j + NumoProblems] = barr_reduce(a[j] + (2L * PARAM_Q - temp));
                        a[j] = barr_reduce(temp + a[j]);
                    }
                }
            }
        }


        static long barr_reduce(long a)
        { // Barrett reduction
            long u = (((long)a * PARAM_BARR_MULT) >> PARAM_BARR_DIV); // TODO u may need to be cast back to int.
            return a - u * PARAM_Q;
        }


        static void nttinv(long[] a, long[] w)
        { // Inverse NTT transform
            int NumoProblems = 1, jTwiddle = 0;
            for (NumoProblems = 1; NumoProblems < PARAM_N; NumoProblems *= 2)
            {
                int jFirst, j = 0;
                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems)
                {
                    int W = (int)w[jTwiddle++];
                    for (j = jFirst; j < jFirst + NumoProblems; j++)
                    {
                        long temp = a[j];

                        a[j] = barr_reduce((temp + a[j + NumoProblems]));
                        a[j + NumoProblems] = barr_reduce(reduce(W * (temp + (2L * PARAM_Q - a[j + NumoProblems]))));
                    }
                }
            }
        }

        static void nttinv(long[] a, int aPos, long[] w)
        { // Inverse NTT transform
            int NumoProblems = 1, jTwiddle = 0;
            for (NumoProblems = 1; NumoProblems < PARAM_N; NumoProblems *= 2)
            {
                int jFirst, j = 0;
                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems)
                {
                    int W = (int)w[jTwiddle++];
                    for (j = jFirst; j < jFirst + NumoProblems; j++)
                    {
                        long temp = a[aPos + j];
                        a[aPos + j] = barr_reduce((temp + a[aPos + j + NumoProblems]));
                        a[aPos + j + NumoProblems] = barr_reduce(reduce((long)W * (temp + (2L * PARAM_Q - a[aPos + j + NumoProblems]))));
                    }
                }

            }
        }


        static void poly_ntt(long[] x_ntt, long[] x)
        { // Call to NTT function. Avoids input destruction

            for (int i = 0; i < PARAM_N; i++)
            {
                x_ntt[i] = x[i];
            }
            ntt(x_ntt, zeta);
        }


        static void poly_pointwise(long[] result, long[] x, long[] y)
        { // Pointwise polynomial multiplication result = x.y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = reduce((long)x[i] * y[i]);
            }
        }

        static void poly_pointwise(long[] result, int rpos, long[] x, int xpos, long[] y)
        { // Pointwise polynomial multiplication result = x.y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i + rpos] = reduce((long)x[i + xpos] * y[i]);
            }
        }


        static void poly_mul(long[] result, long[] x, long[] y)
        { // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)
            // The input x is assumed to be in NTT form
//            long[] y_ntt = new long[PARAM_N];
//
//            for (int i = 0; i < PARAM_N; i++)
//            {
//                y_ntt[i] = y[i];
//            }
//
//            ntt(y_ntt, zeta);
            poly_pointwise(result, x, y);
            nttinv(result, zetainv);
        }


        static void poly_mul(long[] result, int rpos, long[] x, int xpos, long[] y)
        { // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)

            poly_pointwise(result, rpos, x, xpos, y);
            nttinv(result, rpos, zetainv);
        }


        static void poly_add(long[] result, long[] x, long[] y)
        { // Polynomial addition result = x+y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] + y[i];
            }
        }

        static void poly_sub(long[] result, int rpos, long[] x, int xpos, long[] y, int ypos)
        { // Polynomial subtraction result = x-y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[rpos + i] = barr_reduce(x[xpos + i] - y[ypos + i]);
            }
        }


        static void poly_add_correct(long[] result, int rpos, long[] x, int xpos, long[] y, int ypos)
        { // Polynomial addition result = x+y with correction

            for (int i = 0; i < PARAM_N; i++)
            {
                result[rpos + i] = x[xpos + i] + y[ypos + i];
                result[rpos + i] -= PARAM_Q;
                result[rpos + i] += (result[rpos + i] >> (RADIX32 - 1)) & PARAM_Q;   // If result[i] >= q then subtract q
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


        static void sparse_mul8(long[] prod, int ppos, byte[] s, int spos, int[] pos_list, short[] sign_list)
        {
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


        static void sparse_mul8(long[] prod, byte[] s, int[] pos_list, short[] sign_list)
        {
            int i, j, pos;
            byte t[] = s;

            for (i = 0; i < PARAM_N; i++)
            {
                prod[i] = 0;
            }

            for (i = 0; i < PARAM_H; i++)
            {
                pos = pos_list[i];
                for (j = 0; j < pos; j++)
                {
                    prod[j] = prod[j] - sign_list[i] * t[j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    prod[j] = prod[j] + sign_list[i] * t[j - pos];
                }
            }
        }


        static void sparse_mul16(int[] prod, int s[], int pos_list[], short sign_list[])
        {
            int i, j, pos;
//            short[] t = s;

            for (i = 0; i < PARAM_N; i++)
            {
                prod[i] = 0;
            }

            for (i = 0; i < PARAM_H; i++)
            {
                pos = pos_list[i];
                for (j = 0; j < pos; j++)
                {
                    prod[j] = prod[j] - sign_list[i] * s[j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    prod[j] = prod[j] + sign_list[i] * s[j - pos];
                }
            }
        }


        static void sparse_mul32(int[] prod, int[] pk, int[] pos_list, short[] sign_list)
        {
            int i, j, pos;

            for (i = 0; i < PARAM_N; i++)
            {
                prod[i] = 0;
            }

            for (i = 0; i < PARAM_H; i++)
            {
                pos = pos_list[i];
                for (j = 0; j < pos; j++)
                {
                    prod[j] = prod[j] - sign_list[i] * pk[j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    prod[j] = prod[j] + sign_list[i] * pk[j - pos];
                }
            }
        }

        static void sparse_mul32(long[] prod, int ppos, int[] pk, int pkPos, int[] pos_list, short[] sign_list)
        {
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
                    prod[ppos + j] = prod[ppos + j] - sign_list[i] * pk[pkPos + j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    prod[ppos + j] = prod[ppos + j] + sign_list[i] * pk[pkPos + j - pos];
                }
            }
        }


    }

}
