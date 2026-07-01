package org.bouncycastle.pqc.crypto.aimer;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class AIMerEngine
{
    private static final byte HASH_PREFIX_0 = 0;
    private static final byte HASH_PREFIX_1 = 1;
    private static final byte HASH_PREFIX_2 = 2;
    private static final byte HASH_PREFIX_3 = 3;
    private static final byte HASH_PREFIX_4 = 4;
    private static final byte HASH_PREFIX_5 = 5;

    private final int AIM2_NUM_WORDS_FIELD;
    private final int AIM2_NUM_BYTES_FIELD;
    private final int AIM2_NUM_INPUT_SBOX;
    private final int AIM2_NUM_BITS_FIELD;
    private final int AIM2_IV_SIZE;
    private final int AIMER_COMMIT_SIZE;
    private final int shakeBitStrength;
    private final int L;
    private final int T;
    private final int N;
    private final int logN;
    private final int seedSize;
    private final int saltSize;
    private final int logNMask;

    // AIM2 constants (GF elements)
    private final long[][] aim2_constants;
    private final long[][] aim2_e1_power_matrix;
    private final long[][] aim2_e2_power_matrix;
    private final Field field;

    public AIMerEngine(AIMerParameters params)
    {
        AIM2_NUM_WORDS_FIELD = params.getAim2NumWordsField();
        AIM2_NUM_BYTES_FIELD = params.getAim2NumBytesField();
        AIM2_NUM_INPUT_SBOX = params.getAim2NumInputSbox();
        AIM2_NUM_BITS_FIELD = params.getAim2NumBitsField();
        AIM2_IV_SIZE = params.getAim2IVSize();
        AIMER_COMMIT_SIZE = params.getAimerCommitSize();
        aim2_constants = params.aim2_constants;
        aim2_e1_power_matrix = params.aim2_e1_power_matrix;
        aim2_e2_power_matrix = params.aim2_e2_power_matrix;
        L = params.getAimerL();
        T = params.getAimerT();
        N = params.getAimerN();
        logN = params.getAimerLogN();
        logNMask = (1 << logN) - 1;
        seedSize = params.getAimerSeedSize();
        saltSize = params.getAimerSaltSize();
        switch (AIM2_NUM_WORDS_FIELD)
        {
        case 2:
            field = new Field128();
            shakeBitStrength = 128;
            break;
        case 3:
            field = new Field192();
            shakeBitStrength = 256;
            break;
        case 4:
            field = new Field256();
            shakeBitStrength = 256;
            break;
        default:
            throw new IllegalArgumentException("invalid AIM2_NUM_WORDS_FIELD");
        }
    }

    public void generate_matrices_L_and_U(long[][][] matrix_L, long[][][] matrix_U, long[] vector_b, byte[] iv)
    {
        byte[] buf = new byte[AIM2_NUM_BYTES_FIELD];
        SHAKEDigest shake = new SHAKEDigest(shakeBitStrength);
        long[] temp = new long[AIM2_NUM_WORDS_FIELD];

        shake.update(iv, 0, AIM2_IV_SIZE);

        for (int num = 0; num < AIM2_NUM_INPUT_SBOX; num++)
        {
            for (int row = 0; row < AIM2_NUM_BITS_FIELD; row++)
            {
                shake.doOutput(buf, 0, AIM2_NUM_BYTES_FIELD);
                Pack.littleEndianToLong(buf, 0, temp);

                int wordIndex = row >>> 6;
                int bitInWord = row & 63;

                long ormask = 1L << bitInWord;
                long lmask = -1L << bitInWord;
                long umask = ~lmask;

                for (int col_word = 0; col_word < wordIndex; col_word++)
                {
                    // L is zero, U is full
                    matrix_L[num][row][col_word] = 0;
                    matrix_U[num][row][col_word] = temp[col_word];
                }

                matrix_L[num][row][wordIndex] = (temp[wordIndex] & lmask) | ormask;
                matrix_U[num][row][wordIndex] = (temp[wordIndex] & umask) | ormask;

                for (int col_word = wordIndex + 1; col_word < AIM2_NUM_WORDS_FIELD; col_word++)
                {
                    // L is full, U is zero
                    matrix_L[num][row][col_word] = temp[col_word];
                    matrix_U[num][row][col_word] = 0;
                }
            }
        }

        // Generate vector_b
        shake.doOutput(buf, 0, AIM2_NUM_BYTES_FIELD);
        Pack.littleEndianToLong(buf, 0, vector_b);

        shake.reset();
    }

    /**
     * inverse Mersenne S-box with e3 = 7
     * (2 ^ 7 - 1) ^ (-1) mod (2 ^ 256 - 1)
     * = 0xddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76ed
     * ddbb76e ddbb76e ddbb76e ddbb76e ddbb76e ddbb76e ddbb76e ddbb76e ddbb76e d
     */
    public void GF_exp_invmer_e_3(long[] out, long[] in)
    {
        long[] t1 = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_6 = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_7 = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_b = new long[AIM2_NUM_WORDS_FIELD];
        long[] table_d = new long[AIM2_NUM_WORDS_FIELD];

        // t1 = in ^ 3
        field.GF_sqr_s(table_d, in);
        field.GF_mul_s(t1, table_d, in);

        // table_6 = in ^ 6
        field.GF_sqr_s(table_6, t1);
        // table_7 = in ^ 7
        field.GF_mul_s(table_7, table_6, in);
        // table_b = in ^ 11
        field.GF_sqr_s(table_b, table_d);
        field.GF_mul_s(table_b, table_7, table_b);
        // table_d = in ^ 13
        field.GF_mul_s(table_d, table_b, table_d);

        // t1 = in ^ 0xdd
        field.GF_sqr_s(t1, table_d);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_mul_s(t1, t1, table_d);

        // t1 = in ^ 0xdd b
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_mul_s(t1, t1, table_b);

        // t1 = in ^ 0xddb b
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_mul_s(t1, t1, table_b);

        // t1 = in ^ 0xddbb 7
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_mul_s(t1, t1, table_7);

        // t1 = in ^ 0xddbb7 6
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_mul_s(t1, t1, table_6);

        // table_7 = in ^ 0xddbb76 e
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_mul_s(t1, t1, table_7);
        field.GF_sqr_s(table_7, t1);

        // t1 = in ^ 0xddbb76e ddbb76e
        field.GF_sqr_s(t1, table_7);
        for (int i = 1; i < 28; i++)
        {
            field.GF_sqr_s(t1, t1);
        }
        field.GF_mul_s(t1, t1, table_7);

        //block 0: t1 = in ^ 0xddbb76eddbb76e ddbb76e
        //block 1: t1 = in ^ 0xddbb76eddbb76eddbb76e ddbb76e
        //block 2: t1 = in ^ 0xddbb76eddbb76eddbb76eddbb76e ddbb76e
        //block 3: t1 = in ^ 0xddbb76eddbb76eddbb76eddbb76eddbb76e ddbb76e
        //block 4: t1 = in ^ 0xddbb76eddbb76eddbb76eddbb76eddbb76eddbb76e ddbb76e
        //block 5: t1 = in ^ 0xddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76e ddbb76e
        //block 6: t1 = in ^ 0xddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76e ddbb76e
        for (int block = 0; block < 7; block++)
        {
            for (int i = 0; i < 28; i++)
            {
                field.GF_sqr_s(t1, t1);
            }
            field.GF_mul_s(t1, t1, table_7);
        }

        // out = in ^ (0xddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76e d)
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_sqr_s(t1, t1);
        field.GF_mul_s(out, t1, table_d);
    }

    public void GF_transposed_matmul(long[] c, long[] a, long[][] b)
    {
        transposed_matmul(c, a, b, false);
    }

    /**
     * Transposed GF(2)-linear matrix-vector product: c = sum over set bits i of a, of row b[i].
     * Constant-time in the bits of {@code a} (mask-select, no data-dependent branch) because {@code a}
     * carries secret MPC shares. The per-word accumulators stay in registers across the whole bit scan
     * and the result is stored once at the end; specialised per field width to keep them scalar.
     */
    private void transposed_matmul(long[] c, long[] a, long[][] b, boolean add)
    {
        switch (AIM2_NUM_WORDS_FIELD)
        {
        case 2:
            matmul2(c, a, b, add);
            break;
        case 3:
            matmul3(c, a, b, add);
            break;
        default:
            matmul4(c, a, b, add);
            break;
        }
    }

    private static void matmul2(long[] c, long[] a, long[][] b, boolean add)
    {
        long t0 = 0L, t1 = 0L;
        int bIndex = 0;
        for (int i = 0; i < 2; i++)
        {
            long index = a[i];
            for (int bit = 0; bit < 64; bit++)
            {
                long mask = -(index & 1L);
                long[] row = b[bIndex++];
                t0 ^= row[0] & mask;
                t1 ^= row[1] & mask;
                index >>>= 1;
            }
        }
        if (add)
        {
            c[0] ^= t0;
            c[1] ^= t1;
        }
        else
        {
            c[0] = t0;
            c[1] = t1;
        }
    }

    private static void matmul3(long[] c, long[] a, long[][] b, boolean add)
    {
        long t0 = 0L, t1 = 0L, t2 = 0L;
        int bIndex = 0;
        for (int i = 0; i < 3; i++)
        {
            long index = a[i];
            for (int bit = 0; bit < 64; bit++)
            {
                long mask = -(index & 1L);
                long[] row = b[bIndex++];
                t0 ^= row[0] & mask;
                t1 ^= row[1] & mask;
                t2 ^= row[2] & mask;
                index >>>= 1;
            }
        }
        if (add)
        {
            c[0] ^= t0;
            c[1] ^= t1;
            c[2] ^= t2;
        }
        else
        {
            c[0] = t0;
            c[1] = t1;
            c[2] = t2;
        }
    }

    private static void matmul4(long[] c, long[] a, long[][] b, boolean add)
    {
        long t0 = 0L, t1 = 0L, t2 = 0L, t3 = 0L;
        int bIndex = 0;
        for (int i = 0; i < 4; i++)
        {
            long index = a[i];
            for (int bit = 0; bit < 64; bit++)
            {
                long mask = -(index & 1L);
                long[] row = b[bIndex++];
                t0 ^= row[0] & mask;
                t1 ^= row[1] & mask;
                t2 ^= row[2] & mask;
                t3 ^= row[3] & mask;
                index >>>= 1;
            }
        }
        if (add)
        {
            c[0] ^= t0;
            c[1] ^= t1;
            c[2] ^= t2;
            c[3] ^= t3;
        }
        else
        {
            c[0] = t0;
            c[1] = t1;
            c[2] = t2;
            c[3] = t3;
        }
    }

    public void aim2(byte[] ct, byte[] pt, byte[] iv)
    {
        long[][][] matrix_L = new long[AIM2_NUM_INPUT_SBOX][AIM2_NUM_BITS_FIELD][AIM2_NUM_WORDS_FIELD];
        long[][][] matrix_U = new long[AIM2_NUM_INPUT_SBOX][AIM2_NUM_BITS_FIELD][AIM2_NUM_WORDS_FIELD];
        long[] vector_b = new long[AIM2_NUM_WORDS_FIELD];

        long[][] state = new long[AIM2_NUM_INPUT_SBOX][AIM2_NUM_WORDS_FIELD];
        long[] pt_GF = new long[AIM2_NUM_WORDS_FIELD];
        long[] ct_GF = new long[AIM2_NUM_WORDS_FIELD];

        Pack.littleEndianToLong(pt, 0, pt_GF);
        // Generate random matrices L, U and vector b
        generate_matrices_L_and_U(matrix_L, matrix_U, vector_b, iv);

        // Linear component: constant addition
        for (int i = 0; i < AIM2_NUM_INPUT_SBOX; i++)
        {
            Nat.xor64(AIM2_NUM_WORDS_FIELD, pt_GF, aim2_constants[i], state[i]);
        }

        // Non-linear component: inverse Mersenne S-box
        field.GF_exp_invmer_e_1(state[0], state[0]);
        field.GF_exp_invmer_e_2(state[1], state[1]);
        if (AIM2_NUM_WORDS_FIELD == 4)
        {
            GF_exp_invmer_e_3(state[2], state[2]);
        }

        // Linear component: affine layer
        for (int i = 0; i < AIM2_NUM_INPUT_SBOX; i++)
        {
            GF_transposed_matmul(state[i], state[i], matrix_U[i]);
            GF_transposed_matmul(state[i], state[i], matrix_L[i]);
        }

        for (int i = 1; i < AIM2_NUM_INPUT_SBOX; i++)
        {
            Nat.xorTo64(AIM2_NUM_WORDS_FIELD, state[i], state[0]);
        }
        Nat.xorTo64(AIM2_NUM_WORDS_FIELD, vector_b, state[0]);

        // Non-linear component: Mersenne S-box
        field.GF_exp_mer_e_star(state[0], state[0]);
        // Linear component: feed-forward
        Nat.xor64(AIM2_NUM_WORDS_FIELD, state[0], pt_GF, ct_GF);
        Pack.longToLittleEndian(ct_GF, ct, 0);
    }

    /**
     * Expand trees for parallel repetitions
     * <p>
     * Example of tree for [N = 8]
     * x
     * d = 0: 1
     * d = 1: 2         3
     * d = 2: 4   5     6     7
     * d = 3: 8 9 10 11 12 13 14 15
     *
     * @param salt The salt used for hashing
     */
    public void expandTrees(byte[][][] nodes, byte[] salt, SHAKEDigest ctx, SHAKEDigest ctxPre)
    {
        ctxPre.update(HASH_PREFIX_4);
        ctxPre.update(salt, 0, salt.length);
        for (int rep = 0; rep < T; rep++)
        {
            for (int index = 1; index < N; index++)
            {
                // Clone base context and update with buffer
                ctx.reset(ctxPre);
                ctx.update((byte)rep);
                ctx.update((byte)index);
                ctx.update(nodes[rep][index - 1], 0, seedSize);
                ctx.doOutput(nodes[rep][2 * index - 1], 0, seedSize);
                ctx.doOutput(nodes[rep][2 * index], 0, seedSize);
            }
        }
    }

    public void aim2_sbox_outputs(long[][] sboxOutputs, long[] pt)
    {
        // Linear component: constant addition
        for (int i = 0; i < AIM2_NUM_INPUT_SBOX; i++)
        {
            Nat.xor64(AIM2_NUM_WORDS_FIELD, pt, aim2_constants[i], sboxOutputs[i]);
        }
        // Non-linear component: inverse Mersenne S-box
        field.GF_exp_invmer_e_1(sboxOutputs[0], sboxOutputs[0]);
        field.GF_exp_invmer_e_2(sboxOutputs[1], sboxOutputs[1]);

        // For L=3 (aimer256f and aimer256s)
        if (AIM2_NUM_INPUT_SBOX == 3)
        {
            GF_exp_invmer_e_3(sboxOutputs[2], sboxOutputs[2]);
        }
    }

    /**
     * c += sum_i a[i] * b[i]
     * Transposed matrix multiplication with accumulation
     */
    public void GF_transposed_matmul_add(long[] c, long[] a, long[][] b)
    {
        transposed_matmul(c, a, b, true);
    }

    /**
     * AIM2 MPC computation for a single party
     * Computes: z = x * pt for the MPC check equation
     * <p>
     * Equation: pt + c = t^{2^e - 1}
     * Which becomes: t^{2^e} + t * c = t * pt
     * So: z = x * pt (where x = t)
     */
    void aim2_mpc(MultChk mult_chk, long[][][] matrix_A, long[] ct_GF)
    {
        if (AIM2_NUM_WORDS_FIELD != 4)
        {
            // First S-box (e1 = 49)
            // z0 = x0 * pt = x0 * constant0 + x0 * (precomputed power matrix)
            field.GF_mul_s(mult_chk.zShares[0], mult_chk.xShares[0], aim2_constants[0]);
            GF_transposed_matmul_add(mult_chk.zShares[0], mult_chk.xShares[0], aim2_e1_power_matrix);
        }
        else
        {
            // pt + c = t ^ {2 ^ e - 1}
            // --> t ^ {2 ^ e} + t * c = t * pt
            // --> z = x * pt
            field.GF_sqr_s(mult_chk.zShares[0], mult_chk.xShares[0]);
            for (int i = 1; i < 11; i++)
            {
                field.GF_sqr_s(mult_chk.zShares[0], mult_chk.zShares[0]);
            }
            field.GF_mul_add_s(mult_chk.zShares[0], mult_chk.xShares[0], aim2_constants[0]);
        }
        GF_transposed_matmul_add(mult_chk.xShares[L], mult_chk.xShares[0], matrix_A[0]);

        // Second S‑box (e2 = 141)
        field.GF_mul_s(mult_chk.zShares[1], mult_chk.xShares[1], aim2_constants[1]);
        GF_transposed_matmul_add(mult_chk.zShares[1], mult_chk.xShares[1], aim2_e2_power_matrix);
        GF_transposed_matmul_add(mult_chk.xShares[L], mult_chk.xShares[1], matrix_A[1]);

        // Third S‑box (e3 = 7)
        field.GF_sqr_s(mult_chk.zShares[2], mult_chk.xShares[2]);

        if (AIM2_NUM_WORDS_FIELD == 3)
        {
            field.GF_sqr_s(mult_chk.zShares[L], mult_chk.zShares[L]);
            field.GF_sqr_s(mult_chk.zShares[L], mult_chk.zShares[L]);
        }
        else if (AIM2_NUM_WORDS_FIELD == 4)
        {
            field.GF_sqr_s(mult_chk.zShares[2], mult_chk.zShares[2]);
            field.GF_sqr_s(mult_chk.zShares[2], mult_chk.zShares[2]);
            field.GF_sqr_s(mult_chk.zShares[2], mult_chk.zShares[2]);
            field.GF_sqr_s(mult_chk.zShares[2], mult_chk.zShares[2]);
            field.GF_sqr_s(mult_chk.zShares[2], mult_chk.zShares[2]);
            field.GF_sqr_s(mult_chk.zShares[2], mult_chk.zShares[2]);
            field.GF_mul_add_s(mult_chk.zShares[2], mult_chk.xShares[2], aim2_constants[2]);
            GF_transposed_matmul_add(mult_chk.xShares[L], mult_chk.xShares[2], matrix_A[2]);

            // x ^ {2 ^ e - 1} = pt + ct
            // --> x ^ {2 ^ e} + x * ct = x * pt
            // --> z = x * pt
            field.GF_sqr_s(mult_chk.zShares[L], mult_chk.xShares[L]);
        }
        field.GF_sqr_s(mult_chk.zShares[L], mult_chk.zShares[L]);
        field.GF_sqr_s(mult_chk.zShares[L], mult_chk.zShares[L]);
        // Add xL * ct
        field.GF_mul_add_s(mult_chk.zShares[L], mult_chk.xShares[L], ct_GF);
    }

    /**
     * committing to the seeds and the execution views of the parties
     */
    void run_phase_1(AIMerSignature signature,
                     byte[][][] commits,       // [AIMER_T][AIMER_N][AIMER_COMMIT_SIZE]
                     byte[][][] nodes,         // [AIMER_T][2*AIMER_N-1][AIMER_SEED_SIZE]
                     MultChk[][] mult_chk,     // [AIMER_T][AIMER_N]
                     long[][][][] alpha_v_shares, // [AIMER_T][2][AIMER_N][2]
                     byte[] sk,                // secret key
                     byte[] m,                 // message
                     int mlen,                 // message length
                     AIMerParameters params,
                     SecureRandom random)
    {
        long[] pt_GF = new long[AIM2_NUM_WORDS_FIELD];
        long[] ct_GF = new long[AIM2_NUM_WORDS_FIELD];
        long[][] sbox_outputs = new long[L][AIM2_NUM_WORDS_FIELD];
        byte[] mu = new byte[AIMER_COMMIT_SIZE];
        byte[] iv = new byte[AIM2_IV_SIZE];
        byte[] randomBytes = new byte[params.getSecurityBytes()];
        long[][][] matrix_A = new long[L][AIM2_NUM_BITS_FIELD][AIM2_NUM_WORDS_FIELD];
        long[] vector_b = new long[AIM2_NUM_WORDS_FIELD];
        Tape tape = new Tape(params);
        long[] delta_pt_share = new long[AIM2_NUM_WORDS_FIELD];
        long[][] delta_t_shares = new long[L][AIM2_NUM_WORDS_FIELD];
        long[] delta_a_share = new long[AIM2_NUM_WORDS_FIELD];
        long[] delta_c_share = new long[AIM2_NUM_WORDS_FIELD];
        SHAKEDigest hashCtx = new SHAKEDigest(shakeBitStrength);
        SHAKEDigest ctx_precom = new SHAKEDigest(shakeBitStrength);

        Pack.littleEndianToLong(sk, 0, pt_GF);
        Pack.littleEndianToLong(sk, AIM2_NUM_BYTES_FIELD + AIM2_IV_SIZE, ct_GF);
        System.arraycopy(sk, AIM2_IV_SIZE, iv, 0, iv.length);

        // Message pre-hashing
        hashCtx.update(HASH_PREFIX_0);
        hashCtx.update(sk, AIM2_NUM_BYTES_FIELD, AIM2_IV_SIZE + AIM2_NUM_BYTES_FIELD);
        hashCtx.update(m, 0, mlen);
        hashCtx.doOutput(mu, 0, mu.length);

        // compute first L sboxes' outputs
        aim2_sbox_outputs(sbox_outputs, pt_GF);

        // derive the binary matrix and the vector from the initial vector
        generate_matrix_LU(matrix_A, vector_b, iv);

        // Generate per-signature randomness
        random.nextBytes(randomBytes);

        // Generate salt
        hashCtx.reset();
        hashCtx.update(HASH_PREFIX_3);
        hashCtx.update(sk, 0, AIM2_NUM_BYTES_FIELD); // First 16 bytes (pt)
        hashCtx.update(mu, 0, mu.length);
        hashCtx.update(randomBytes, 0, randomBytes.length);
        hashCtx.doOutput(signature.salt, 0, signature.salt.length);

        // Generate root seeds and expand seed trees
        for (int rep = 0; rep < T; rep++)
        {
            hashCtx.doOutput(nodes[rep][0], 0, seedSize);
        }
        expandTrees(nodes, signature.salt, hashCtx, ctx_precom);

        // Hash instance for h_1
        hashCtx.reset();
        hashCtx.update(HASH_PREFIX_1);
        hashCtx.update(mu, 0, mu.length);
        hashCtx.update(signature.salt, 0, signature.salt.length);

        ctx_precom.reset();
        ctx_precom.update(HASH_PREFIX_5);
        ctx_precom.update(signature.salt, 0, signature.salt.length);

        // Process each repetition
        for (int rep = 0; rep < T; rep++)
        {
            Arrays.fill(delta_pt_share, 0L);
            Arrays.fill(delta_a_share, 0L);
            Arrays.fill(delta_c_share, 0L);
            for (int i = 0; i < L; i++)
            {
                Arrays.fill(delta_t_shares[i], 0L);
            }

            for (int party = 0; party < N; party++)
            {
                byte[] seed = nodes[rep][party + N - 1];
                // generate execution views and commitments
                commit_and_expand_tape(tape, commits[rep][party], ctx_precom, seed, rep, party);
                hashCtx.update(commits[rep][party], 0, commits[rep][party].length);

                // compute offsets
                Nat.xorTo64(AIM2_NUM_WORDS_FIELD, tape.ptShare, delta_pt_share);
                for (int i = 0; i < L; i++)
                {
                    Nat.xorTo64(AIM2_NUM_WORDS_FIELD, tape.tShares[i], delta_t_shares[i]);
                }
                Nat.xorTo64(AIM2_NUM_WORDS_FIELD, tape.aShare, delta_a_share);
                Nat.xorTo64(AIM2_NUM_WORDS_FIELD, tape.cShare, delta_c_share);

                // adjust the last share and prepare the proof and h_1
                if (party == N - 1)
                {
                    Nat.xorTo64(AIM2_NUM_WORDS_FIELD, pt_GF, delta_pt_share);
                    Pack.longToLittleEndian(delta_pt_share, signature.proofs[rep].deltaPtBytes, 0);
                    Nat.xorTo64(AIM2_NUM_WORDS_FIELD, delta_pt_share, tape.ptShare);
                    for (int i = 0; i < L; i++)
                    {
                        Nat.xorTo64(AIM2_NUM_WORDS_FIELD, sbox_outputs[i], delta_t_shares[i]);
                        Pack.longToLittleEndian(delta_t_shares[i], signature.proofs[rep].deltaTsBytes[i], 0);
                        Nat.xorTo64(AIM2_NUM_WORDS_FIELD, delta_t_shares[i], tape.tShares[i]);
                    }
                    field.GF_mul_add_s(delta_c_share, pt_GF, delta_a_share);
                    Pack.longToLittleEndian(delta_c_share, signature.proofs[rep].deltaCBytes, 0);
                    Nat.xorTo64(AIM2_NUM_WORDS_FIELD, delta_c_share, tape.cShare);

                    System.arraycopy(vector_b, 0, mult_chk[rep][party].xShares[L], 0, AIM2_NUM_WORDS_FIELD);
                }

                System.arraycopy(tape.ptShare, 0, mult_chk[rep][party].ptShare, 0, AIM2_NUM_WORDS_FIELD);
                for (int i = 0; i < L; i++)
                {
                    System.arraycopy(tape.tShares[i], 0, mult_chk[rep][party].xShares[i], 0, AIM2_NUM_WORDS_FIELD);
                }
                System.arraycopy(tape.aShare, 0, alpha_v_shares[rep][0][party], 0, AIM2_NUM_WORDS_FIELD);
                System.arraycopy(tape.cShare, 0, alpha_v_shares[rep][1][party], 0, AIM2_NUM_WORDS_FIELD);

                aim2_mpc(mult_chk[rep][party], matrix_A, ct_GF);
            }
            // NOTE: depend on the order of values in proof_t
            updateH1(hashCtx, signature.proofs[rep]);
        }
        hashCtx.doOutput(signature.h_1, 0, AIMER_COMMIT_SIZE);
    }

    public void commit_and_expand_tape(Tape tape, byte[] commit, SHAKEDigest ctx, byte[] seed, int rep, int party)
    {
        SHAKEDigest ctx_precom = new SHAKEDigest(ctx);
        ctx_precom.update((byte)rep);
        ctx_precom.update((byte)party);
        ctx_precom.update(seed, 0, seed.length);
        ctx_precom.doOutput(commit, 0, commit.length);
        tape.fromBytes(ctx_precom);
    }

    void generate_matrix_LU(long[][][] matrix_A, long[] vector_b, byte[] iv)
    {
        long[][][] matrix_L = new long[AIM2_NUM_INPUT_SBOX][AIM2_NUM_BITS_FIELD][AIM2_NUM_WORDS_FIELD];
        long[][][] matrix_U = new long[AIM2_NUM_INPUT_SBOX][AIM2_NUM_BITS_FIELD][AIM2_NUM_WORDS_FIELD];

        generate_matrices_L_and_U(matrix_L, matrix_U, vector_b, iv);

        for (int num = 0; num < AIM2_NUM_INPUT_SBOX; num++)
        {
            for (int i = 0; i < AIM2_NUM_BITS_FIELD; i++)
            {
                GF_transposed_matmul(matrix_A[num][i], matrix_U[num][i], matrix_L[num]);
            }
        }
    }

    void run_phase_2_and_3(AIMerSignature sign, long[][][][] alpha_v_shares, MultChk[][] mult_chk)
    {
        long[][] epsilons = new long[L + 1][AIM2_NUM_WORDS_FIELD];
        long[] alpha = new long[AIM2_NUM_WORDS_FIELD];
        byte[] buf = new byte[AIM2_NUM_BYTES_FIELD];

        SHAKEDigest ctx_e = new SHAKEDigest(shakeBitStrength);
        ctx_e.update(sign.h_1, 0, AIMER_COMMIT_SIZE);

        SHAKEDigest ctx = new SHAKEDigest(shakeBitStrength);
        ctx.update(HASH_PREFIX_2);
        ctx.update(sign.h_1, 0, AIMER_COMMIT_SIZE);
        ctx.update(sign.salt, 0, saltSize);

        for (int rep = 0; rep < T; rep++)
        {
            Arrays.fill(alpha, 0L);
            for (int i = 0; i <= L; i++)
            {
                ctx_e.doOutput(buf, 0, AIM2_NUM_BYTES_FIELD);
                Pack.littleEndianToLong(buf, 0, epsilons[i]);
            }
            // alpha_share = a_share + sum x_share[i] * eps[i]
            for (int party = 0; party < N; party++)
            {
                // alpha_share = a_share + sum x_share[i] * eps[i]
                // v_share = c_share - pt_share * alpha + sum z_share[i] * eps[i]
                for (int i = 0; i <= L; i++)
                {
                    field.GF_mul_add_s(alpha_v_shares[rep][0][party], mult_chk[rep][party].xShares[i], epsilons[i]);
                    field.GF_mul_add_s(alpha_v_shares[rep][1][party], mult_chk[rep][party].zShares[i], epsilons[i]);
                }
                Nat.xorTo64(AIM2_NUM_WORDS_FIELD, alpha_v_shares[rep][0][party], alpha);
            }
            // alpha is opened, so we can finish calculating v_share
            for (int party = 0; party < N; party++)
            {
                field.GF_mul_add_s(alpha_v_shares[rep][1][party], mult_chk[rep][party].ptShare, alpha);
            }
            updateH2(N, buf, ctx, alpha_v_shares[rep]);
        }
        ctx.doOutput(sign.h_2, 0, AIMER_COMMIT_SIZE);
    }

    /**
     * Generate an AIMER signature
     *
     * @param sig    Output signature (will be filled)
     * @param m      Message to sign
     * @param mlen   Message length
     * @param sk     Secret key
     * @param params AIMER parameters
     * @return 0 on success, -1 on error
     */
    public int crypto_sign_signature(byte[] sig, byte[] m, int mlen, byte[] sk, AIMerParameters params, SecureRandom random)
    {
        if (sig == null || m == null || sk == null)
        {
            return -1;
        }

        AIMerSignature sign = new AIMerSignature(params);

        //////////////////////////////////////////////////////////////////////////
        // Phase 1: Committing to the seeds and the execution views of parties. //
        //////////////////////////////////////////////////////////////////////////

        // Nodes for seed trees
        byte[][][] nodes = new byte[T][2 * N - 1][seedSize];
        // Commitments for seeds
        byte[][][] commits = new byte[T][N][AIMER_COMMIT_SIZE];
        // Multiplication check outputs
        long[][][][] alpha_v_shares = new long[T][AIM2_NUM_WORDS_FIELD][N][AIM2_NUM_WORDS_FIELD];
        byte[] indicesBytes = new byte[T];
        int[] indices = new int[T];
        int pos;
        SHAKEDigest ctx = new SHAKEDigest(shakeBitStrength);

        // Multiplication check inputs
        MultChk[][] mult_chk = new MultChk[T][N];
        for (int rep = 0; rep < T; rep++)
        {
            for (int party = 0; party < N; party++)
            {
                mult_chk[rep][party] = new MultChk(params);
            }
        }

        // commitments for phase 1
        run_phase_1(sign, commits, nodes, mult_chk, alpha_v_shares, sk, m, mlen, params, random);

        ///////////////////////////////////////////////////////////////////
        // Phase 2, 3: Challenging and committing to the simulation of //
        //             the multiplication checking protocol.           //
        ///////////////////////////////////////////////////////////////////

        run_phase_2_and_3(sign, alpha_v_shares, mult_chk);

        //////////////////////////////////////////////////////
        // Phase 4: Challenging views of the MPC protocols. //
        //////////////////////////////////////////////////////

        ctx.update(sign.h_2, 0, AIMER_COMMIT_SIZE);
        ctx.doOutput(indicesBytes, 0, T);

        for (int rep = 0; rep < T; rep++)
        {
            indices[rep] = (indicesBytes[rep] & 0xFF) & logNMask;
        }

        //////////////////////////////////////////////////////
        // Phase 5: Opening the views of the MPC protocols. //
        //////////////////////////////////////////////////////
        System.arraycopy(m, 0, sig, 0, m.length);
        pos = m.length;
        System.arraycopy(sign.salt, 0, sig, pos, sign.salt.length);
        pos += sign.salt.length;

        // Write h_1 and h_2
        System.arraycopy(sign.h_1, 0, sig, pos, sign.h_1.length);
        pos += sign.h_1.length;

        System.arraycopy(sign.h_2, 0, sig, pos, sign.h_2.length);
        pos += sign.h_2.length;
        for (int rep = 0; rep < T; rep++)
        {
            int i_bar = indices[rep];
            Proof proof = sign.proofs[rep];

            //reveal_all_but(proof.revealPath, nodes[rep], i_bar, params);
            int index = i_bar + N;

            for (int depth = 0; depth < logN; depth++)
            {
                // index ^ 1 is sibling index
                int siblingIndex = (index ^ 1) - 1;
                System.arraycopy(nodes[rep][siblingIndex], 0, sig, pos, seedSize);
                pos += seedSize;
                index >>= 1;
            }

            System.arraycopy(commits[rep][i_bar], 0, sig, pos, AIMER_COMMIT_SIZE);
            pos += AIMER_COMMIT_SIZE;
            System.arraycopy(proof.deltaPtBytes, 0, sig, pos, proof.deltaPtBytes.length);
            pos += proof.deltaPtBytes.length;
            for (int i = 0; i < proof.deltaTsBytes.length; i++)
            {
                System.arraycopy(proof.deltaTsBytes[i], 0, sig, pos, proof.deltaTsBytes[i].length);
                pos += proof.deltaTsBytes[i].length;
            }
            System.arraycopy(proof.deltaCBytes, 0, sig, pos, proof.deltaCBytes.length);
            pos += proof.deltaCBytes.length;

            // Serialize missingAlphaShareBytes
            Pack.longToLittleEndian(alpha_v_shares[rep][0][i_bar], sig, pos);
            pos += AIM2_NUM_BYTES_FIELD;
        }
        return 0;
    }

    /**
     * Reconstruct the Merkle tree nodes from the reveal path.
     *
     * @param salt       the salt (AIMER_SALT_SIZE)
     * @param revealPath the reveal path (AIMER_LOGN x AIMER_SEED_SIZE)
     * @param repIndex   repetition index (used in hash)
     * @param coverIndex the leaf index that is not revealed
     */
    public void reconstructTree(byte[][] nodes, byte[] salt, byte[][] revealPath, int repIndex, int coverIndex)
    {
        SHAKEDigest ctxPre = new SHAKEDigest(shakeBitStrength);
        ctxPre.update(HASH_PREFIX_4);
        ctxPre.update(salt, 0, salt.length);
        SHAKEDigest ctx = new SHAKEDigest(ctxPre);
        int depth;
        for (depth = 1; depth < logN; depth++)
        {
            int path = ((coverIndex + N) >> (logN - depth)) ^ 1;
            System.arraycopy(revealPath[logN - depth], 0, nodes[path - 2], 0, seedSize);
            for (int index = 1 << depth; index < 2 << depth; index++)
            {
                ctx.reset(ctxPre);
                ctx.update((byte)repIndex);
                ctx.update((byte)index);
                ctx.update(nodes[index - 2], 0, seedSize);
                ctx.doOutput(nodes[2 * index - 2], 0, seedSize);
                ctx.doOutput(nodes[2 * index - 1], 0, seedSize);
            }
        }
        int path = ((coverIndex + N) >> (logN - depth)) ^ 1;
        System.arraycopy(revealPath[logN - depth], 0, nodes[path - 2], 0, seedSize);
    }

    /**
     * Verify an AIMER signature.
     *
     * @param sig    the signature bytes
     * @param siglen length of the signature (must equal CRYPTO_BYTES)
     * @param m      the message
     * @param mlen   message length
     * @param pk     the public key (IV || ciphertext)
     * @param params AIMER parameters
     * @return 0 on success, -1 on failure
     */
    public int crypto_sign_verify(byte[] sig, int siglen, byte[] m, int mlen, byte[] pk, AIMerParameters params)
    {
        int expectedSigLen = params.getSignatureBytes();
        if (siglen != expectedSigLen)
        {
            return -1;
        }
        long[] temp = new long[AIM2_NUM_WORDS_FIELD];
        byte[] buf = new byte[AIM2_NUM_BYTES_FIELD];
        long[][] epsilons = new long[L + 1][AIM2_NUM_WORDS_FIELD];
        long[] ct_GF = new long[AIM2_NUM_WORDS_FIELD];
        long[][][] matrix_A = new long[L][AIM2_NUM_BITS_FIELD][AIM2_NUM_WORDS_FIELD];
        long[] vector_b = new long[AIM2_NUM_WORDS_FIELD];
        long[][] pt_shares = new long[N][AIM2_NUM_WORDS_FIELD];
        long[] alpha = new long[AIM2_NUM_WORDS_FIELD];
        // message pre-hashing
        byte[] mu = new byte[AIMER_COMMIT_SIZE];
        byte[] indicesBytes = new byte[T];
        int[] indices = new int[T];
        byte[] commit = new byte[AIMER_COMMIT_SIZE];
        byte[][] nodes = new byte[2 * N - 2][seedSize];
        // Parse the signature
        AIMerSignature sign = new AIMerSignature(sig, params);
        SHAKEDigest ctx = new SHAKEDigest(shakeBitStrength);
        SHAKEDigest ctx_h1 = new SHAKEDigest(shakeBitStrength);

        Pack.littleEndianToLong(pk, AIM2_IV_SIZE, ct_GF);

        // Generate matrix A and vector b from the public key (IV)
        generate_matrix_LU(matrix_A, vector_b, pk);

        ctx.update(sign.h_2, 0, AIMER_COMMIT_SIZE);

        ctx.doOutput(indicesBytes, 0, indicesBytes.length);
        for (int rep = 0; rep < T; rep++)
        {
            indices[rep] = (indicesBytes[rep] & 0xFF) & logNMask;
        }

        // Compute mu = H(prefix0, pk, m)
        ctx.reset();
        ctx.update(HASH_PREFIX_0);
        ctx.update(pk, 0, AIM2_IV_SIZE + AIM2_NUM_BYTES_FIELD);
        ctx.update(m, 0, mlen);
        ctx.doOutput(mu, 0, mu.length);

        // Prepare epsilon stream from h1
        ctx.reset();
        ctx.update(sign.h_1, 0, AIMER_COMMIT_SIZE);

        // Initialise contexts for recomputing h1' and h2'
        ctx_h1.update(HASH_PREFIX_1);
        ctx_h1.update(mu, 0, mu.length);
        ctx_h1.update(sign.salt, 0, saltSize);

        SHAKEDigest ctx_h2 = new SHAKEDigest(shakeBitStrength);

        ctx_h2.update(HASH_PREFIX_2);
        ctx_h2.update(sign.h_1, 0, AIMER_COMMIT_SIZE);
        ctx_h2.update(sign.salt, 0, saltSize);

        // Precomputed context for tape expansion (prefix5 + salt)
        SHAKEDigest ctx_precom = new SHAKEDigest(shakeBitStrength);

        ctx_precom.update(HASH_PREFIX_5);
        ctx_precom.update(sign.salt, 0, saltSize);

        // Process each repetition
        for (int rep = 0; rep < T; rep++)
        {
            long[][][] alpha_v_shares = new long[2][N][AIM2_NUM_WORDS_FIELD];
            int i_bar = indices[rep];
            Arrays.fill(alpha, 0L);
            reconstructTree(nodes, sign.salt, sign.proofs[rep].revealPath, rep, i_bar);

            for (int i = 0; i <= L; i++)
            {
                ctx.doOutput(buf, 0, AIM2_NUM_BYTES_FIELD);
                Pack.littleEndianToLong(buf, 0, epsilons[i]);
            }
            for (int party = 0; party < N; party++)
            {
                if (party == i_bar)
                {
                    ctx_h1.update(sign.proofs[rep].missingCommitment, 0, AIMER_COMMIT_SIZE);
                    Pack.littleEndianToLong(sign.proofs[rep].missingAlphaShareBytes, 0, alpha_v_shares[0][i_bar]);
                    Nat.xorTo64(AIM2_NUM_WORDS_FIELD, alpha_v_shares[0][i_bar], alpha);
                    continue;
                }
                byte[] seed = nodes[N + party - 2];
                Tape tape = new Tape(params);
                commit_and_expand_tape(tape, commit, ctx_precom, seed, rep, party);
                ctx_h1.update(commit, 0, commit.length);

                // Adjust the last share (party == N-1) using delta values from proof
                MultChk mult_chk = new MultChk(params);
                if (party == N - 1)
                {
                    Pack.littleEndianToLong(sign.proofs[rep].deltaPtBytes, 0, temp);
                    Nat.xorTo64(AIM2_NUM_WORDS_FIELD, temp, tape.ptShare);
                    for (int i = 0; i < L; i++)
                    {
                        Pack.littleEndianToLong(sign.proofs[rep].deltaTsBytes[i], 0, temp);
                        Nat.xorTo64(AIM2_NUM_WORDS_FIELD, temp, tape.tShares[i]);
                    }
                    Pack.littleEndianToLong(sign.proofs[rep].deltaCBytes, 0, temp);
                    Nat.xorTo64(AIM2_NUM_WORDS_FIELD, temp, tape.cShare);

                    System.arraycopy(vector_b, 0, mult_chk.xShares[L], 0, AIM2_NUM_WORDS_FIELD);
                }

                // run the MPC simulation and prepare the mult check inputs
                for (int i = 0; i < L; ++i)
                {
                    System.arraycopy(tape.tShares[i], 0, mult_chk.xShares[i], 0, mult_chk.xShares[i].length);
                }
                pt_shares[party] = tape.ptShare;
                alpha_v_shares[0][party] = tape.aShare;
                alpha_v_shares[1][party] = tape.cShare;

                aim2_mpc(mult_chk, matrix_A, ct_GF);

                for (int i = 0; i <= L; i++)
                {
                    field.GF_mul_add_s(alpha_v_shares[0][party], mult_chk.xShares[i], epsilons[i]);
                    field.GF_mul_add_s(alpha_v_shares[1][party], mult_chk.zShares[i], epsilons[i]);
                }
                Nat.xorTo64(AIM2_NUM_WORDS_FIELD, alpha_v_shares[0][party], alpha);
            }

            // alpha is opened, so we can finish calculating v_share
            for (int party = 0; party < N; party++)
            {
                if (party == i_bar)
                {
                    continue;
                }
                field.GF_mul_add_s(alpha_v_shares[1][party], pt_shares[party], alpha);
                Nat.xorTo64(AIM2_NUM_WORDS_FIELD, alpha_v_shares[1][party], alpha_v_shares[1][i_bar]);
            }

            // v is opened
            updateH2(N, buf, ctx_h2, alpha_v_shares);

            // NOTE: depend on the order of values in proof_t
            updateH1(ctx_h1, sign.proofs[rep]);
        }

        // Compute h1' and h2'
        byte[] h1_prime = new byte[AIMER_COMMIT_SIZE];
        ctx_h1.doOutput(h1_prime, 0, h1_prime.length);

        byte[] h2_prime = new byte[AIMER_COMMIT_SIZE];
        ctx_h2.doOutput(h2_prime, 0, h2_prime.length);

        // Compare with signature's h1 and h2
        if (!Arrays.constantTimeAreEqual(h1_prime, sign.h_1) || !Arrays.constantTimeAreEqual(h2_prime, sign.h_2))
        {
            return -1;
        }
        return 0;
    }

    private void updateH1(SHAKEDigest ctx_h1, Proof proof)
    {
        ctx_h1.update(proof.deltaPtBytes, 0, AIM2_NUM_BYTES_FIELD);
        for (int i = 0; i < L; i++)
        {
            ctx_h1.update(proof.deltaTsBytes[i], 0, AIM2_NUM_BYTES_FIELD);
        }
        ctx_h1.update(proof.deltaCBytes, 0, AIM2_NUM_BYTES_FIELD);
    }

    private void updateH2(int N, byte[] buf, SHAKEDigest ctx, long[][][] alpha_v_shares)
    {
        for (int party = 0; party < N; party++)
        {
            // alpha share
            Pack.longToLittleEndian(alpha_v_shares[0][party], buf, 0);
            ctx.update(buf, 0, AIM2_NUM_BYTES_FIELD);
        }

        for (int party = 0; party < N; party++)
        {
            // v share
            Pack.longToLittleEndian(alpha_v_shares[1][party], buf, 0);
            ctx.update(buf, 0, AIM2_NUM_BYTES_FIELD);
        }
    }
}
