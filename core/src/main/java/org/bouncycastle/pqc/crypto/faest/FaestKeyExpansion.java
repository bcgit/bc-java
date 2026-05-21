package org.bouncycastle.pqc.crypto.faest;

/**
 * Key-expansion primitives for the FAEST AES constraint system.
 * <p>
 * These implement the witness layout used by the FAEST prover/verifier for the
 * AES key schedule: {@code keyexpForward} regenerates the expanded round-key
 * bits/tags from the witness, {@code keyexpBackward} undoes one S-box layer
 * (peeling off the affine and round-constant) to recover the round-key bytes
 * that would have been input to {@code Inv} during key expansion, and
 * {@code expkeyConstraintsProver/Verifier} emit the key-schedule constraint
 * polynomial.
 * <p>
 * faest-ref source of truth: {@code faest_aes.c} (lines 2247-3166).
 */
final class FaestKeyExpansion
{
    /** AES round constants. faest-ref: faest_aes.c:82. */
    static final byte[] RCON = {
        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10,
        (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36,
        (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a,
        (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6,
        (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3,
        (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91,
    };

    private FaestKeyExpansion()
    {
    }

    // ====== keyexp_forward ======
    // faest_aes.c:2501 (prover) / faest_aes.c:2607 (verifier).
    //
    // Witness layout: bits 0..lambda-1 are the master key; bits lambda..lambda+Lke
    // are the prover's chosen "linking" bits for non-S-box-derived round-key words.
    // We reconstruct y[32*j ..] for j = 0..R+1:
    //   - For j < Nk: y[32*j] = w[32*j]                (master key)
    //   - For j ≥ Nk where word j is fresh (j%Nk==0 or (Nk>6 && j%Nk==4)):
    //       y[32*j] = w[i_wd]                          (next 32 linking bits)
    //   - Otherwise y[32*j] = y[32*(j-Nk)] XOR y[32*(j-1)] (standard XOR chain)

    static void keyexpForwardProver128(byte[] y, long[] yTag, byte[] w, long[] wTag,
                                       FaestParameters params)
    {
        int lambda = params.getLambda();
        int Nk = lambda / 32;
        int R = params.getR();
        for (int i = 0; i < lambda; i++)
        {
            y[i] = w[i];
            System.arraycopy(wTag, i * BF128.LIMBS, yTag, i * BF128.LIMBS, BF128.LIMBS);
        }
        int iWd = lambda;
        for (int j = Nk; j < 4 * (R + 1); j++)
        {
            if ((j % Nk == 0) || ((Nk > 6) && (j % Nk == 4)))
            {
                System.arraycopy(w, iWd, y, 32 * j, 32);
                System.arraycopy(wTag, iWd * BF128.LIMBS, yTag, 32 * j * BF128.LIMBS,
                    32 * BF128.LIMBS);
                iWd += 32;
            }
            else
            {
                for (int b = 0; b < 32; b++)
                {
                    y[32 * j + b] = (byte)((y[32 * (j - Nk) + b] ^ y[32 * (j - 1) + b]) & 1);
                    BF128.add(yTag, (32 * j + b) * BF128.LIMBS,
                        yTag, (32 * (j - Nk) + b) * BF128.LIMBS,
                        yTag, (32 * (j - 1) + b) * BF128.LIMBS);
                }
            }
        }
    }

    static void keyexpForwardProver192(byte[] y, long[] yTag, byte[] w, long[] wTag,
                                       FaestParameters params)
    {
        int lambda = params.getLambda();
        int Nk = lambda / 32;
        int R = params.getR();
        for (int i = 0; i < lambda; i++)
        {
            y[i] = w[i];
            System.arraycopy(wTag, i * BF192.LIMBS, yTag, i * BF192.LIMBS, BF192.LIMBS);
        }
        int iWd = lambda;
        for (int j = Nk; j < 4 * (R + 1); j++)
        {
            if ((j % Nk == 0) || ((Nk > 6) && (j % Nk == 4)))
            {
                System.arraycopy(w, iWd, y, 32 * j, 32);
                System.arraycopy(wTag, iWd * BF192.LIMBS, yTag, 32 * j * BF192.LIMBS,
                    32 * BF192.LIMBS);
                iWd += 32;
            }
            else
            {
                for (int b = 0; b < 32; b++)
                {
                    y[32 * j + b] = (byte)((y[32 * (j - Nk) + b] ^ y[32 * (j - 1) + b]) & 1);
                    BF192.add(yTag, (32 * j + b) * BF192.LIMBS,
                        yTag, (32 * (j - Nk) + b) * BF192.LIMBS,
                        yTag, (32 * (j - 1) + b) * BF192.LIMBS);
                }
            }
        }
    }

    static void keyexpForwardProver256(byte[] y, long[] yTag, byte[] w, long[] wTag,
                                       FaestParameters params)
    {
        int lambda = params.getLambda();
        int Nk = lambda / 32;
        int R = params.getR();
        for (int i = 0; i < lambda; i++)
        {
            y[i] = w[i];
            System.arraycopy(wTag, i * BF256.LIMBS, yTag, i * BF256.LIMBS, BF256.LIMBS);
        }
        int iWd = lambda;
        for (int j = Nk; j < 4 * (R + 1); j++)
        {
            if ((j % Nk == 0) || ((Nk > 6) && (j % Nk == 4)))
            {
                System.arraycopy(w, iWd, y, 32 * j, 32);
                System.arraycopy(wTag, iWd * BF256.LIMBS, yTag, 32 * j * BF256.LIMBS,
                    32 * BF256.LIMBS);
                iWd += 32;
            }
            else
            {
                for (int b = 0; b < 32; b++)
                {
                    y[32 * j + b] = (byte)((y[32 * (j - Nk) + b] ^ y[32 * (j - 1) + b]) & 1);
                    BF256.add(yTag, (32 * j + b) * BF256.LIMBS,
                        yTag, (32 * (j - Nk) + b) * BF256.LIMBS,
                        yTag, (32 * (j - 1) + b) * BF256.LIMBS);
                }
            }
        }
    }

    static void keyexpForwardVerifier128(long[] yKey, long[] wKey, FaestParameters params)
    {
        int lambda = params.getLambda();
        int Nk = lambda / 32;
        int R = params.getR();
        for (int i = 0; i < lambda; i++)
        {
            System.arraycopy(wKey, i * BF128.LIMBS, yKey, i * BF128.LIMBS, BF128.LIMBS);
        }
        int iWd = lambda;
        for (int j = Nk; j < 4 * (R + 1); j++)
        {
            if ((j % Nk == 0) || ((Nk > 6) && (j % Nk == 4)))
            {
                System.arraycopy(wKey, iWd * BF128.LIMBS, yKey, 32 * j * BF128.LIMBS,
                    32 * BF128.LIMBS);
                iWd += 32;
            }
            else
            {
                for (int b = 0; b < 32; b++)
                {
                    BF128.add(yKey, (32 * j + b) * BF128.LIMBS,
                        yKey, (32 * (j - Nk) + b) * BF128.LIMBS,
                        yKey, (32 * (j - 1) + b) * BF128.LIMBS);
                }
            }
        }
    }

    static void keyexpForwardVerifier192(long[] yKey, long[] wKey, FaestParameters params)
    {
        int lambda = params.getLambda();
        int Nk = lambda / 32;
        int R = params.getR();
        for (int i = 0; i < lambda; i++)
        {
            System.arraycopy(wKey, i * BF192.LIMBS, yKey, i * BF192.LIMBS, BF192.LIMBS);
        }
        int iWd = lambda;
        for (int j = Nk; j < 4 * (R + 1); j++)
        {
            if ((j % Nk == 0) || ((Nk > 6) && (j % Nk == 4)))
            {
                System.arraycopy(wKey, iWd * BF192.LIMBS, yKey, 32 * j * BF192.LIMBS,
                    32 * BF192.LIMBS);
                iWd += 32;
            }
            else
            {
                for (int b = 0; b < 32; b++)
                {
                    BF192.add(yKey, (32 * j + b) * BF192.LIMBS,
                        yKey, (32 * (j - Nk) + b) * BF192.LIMBS,
                        yKey, (32 * (j - 1) + b) * BF192.LIMBS);
                }
            }
        }
    }

    static void keyexpForwardVerifier256(long[] yKey, long[] wKey, FaestParameters params)
    {
        int lambda = params.getLambda();
        int Nk = lambda / 32;
        int R = params.getR();
        for (int i = 0; i < lambda; i++)
        {
            System.arraycopy(wKey, i * BF256.LIMBS, yKey, i * BF256.LIMBS, BF256.LIMBS);
        }
        int iWd = lambda;
        for (int j = Nk; j < 4 * (R + 1); j++)
        {
            if ((j % Nk == 0) || ((Nk > 6) && (j % Nk == 4)))
            {
                System.arraycopy(wKey, iWd * BF256.LIMBS, yKey, 32 * j * BF256.LIMBS,
                    32 * BF256.LIMBS);
                iWd += 32;
            }
            else
            {
                for (int b = 0; b < 32; b++)
                {
                    BF256.add(yKey, (32 * j + b) * BF256.LIMBS,
                        yKey, (32 * (j - Nk) + b) * BF256.LIMBS,
                        yKey, (32 * (j - 1) + b) * BF256.LIMBS);
                }
            }
        }
    }

    // ====== keyexp_backward ======
    // faest_aes.c:2247 (prover) / faest_aes.c:2377 (verifier).
    //
    // For each of Ske S-box invocations during key expansion, compute the
    // pre-affine "x_tilde" byte (= x XOR appropriate round-key byte, plus Rcon
    // when applicable) and apply inverse_affine_byte to it. The result y is the
    // input to the S-box's GF(2^8) inverse — the part FAEST proves separately.

    static void keyexpBackwardProver128(byte[] y, long[] yTag, byte[] x, long[] xTag,
                                        byte[] key, long[] keyTag, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        byte[] xt = new byte[8];
        long[] xtTag = new long[8 * BF128.LIMBS];
        int iwd = 0;
        boolean rmvRcon = true;
        for (int j = 0; j < Ske; j++)
        {
            int rcOff = (lambda == 256) ? j / 8 : j / 4;
            int rc = RCON[rcOff] & 0xff;
            for (int bi = 0; bi < 8; bi++)
            {
                xt[bi] = (byte)((x[j * 8 + bi] ^ key[iwd + (j % 4) * 8 + bi]) & 1);
                BF128.add(xtTag, bi * BF128.LIMBS,
                    xTag, (j * 8 + bi) * BF128.LIMBS,
                    keyTag, (iwd + (j % 4) * 8 + bi) * BF128.LIMBS);
                if (rmvRcon && (j % 4 == 0))
                {
                    xt[bi] = (byte)((xt[bi] ^ ((rc >>> bi) & 1)) & 1);
                }
            }
            FaestProofPrimitives.inverseAffineByteProver128(
                y, 8 * j, yTag, 8 * j * BF128.LIMBS, xt, 0, xtTag, 0);
            if (j % 4 == 3)
            {
                if (lambda == 192)
                {
                    iwd += 192;
                }
                else
                {
                    iwd += 128;
                    if (lambda == 256)
                    {
                        rmvRcon = !rmvRcon;
                    }
                }
            }
        }
    }

    static void keyexpBackwardProver192(byte[] y, long[] yTag, byte[] x, long[] xTag,
                                        byte[] key, long[] keyTag, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        byte[] xt = new byte[8];
        long[] xtTag = new long[8 * BF192.LIMBS];
        int iwd = 0;
        boolean rmvRcon = true;
        for (int j = 0; j < Ske; j++)
        {
            int rcOff = (lambda == 256) ? j / 8 : j / 4;
            int rc = RCON[rcOff] & 0xff;
            for (int bi = 0; bi < 8; bi++)
            {
                xt[bi] = (byte)((x[j * 8 + bi] ^ key[iwd + (j % 4) * 8 + bi]) & 1);
                BF192.add(xtTag, bi * BF192.LIMBS,
                    xTag, (j * 8 + bi) * BF192.LIMBS,
                    keyTag, (iwd + (j % 4) * 8 + bi) * BF192.LIMBS);
                if (rmvRcon && (j % 4 == 0))
                {
                    xt[bi] = (byte)((xt[bi] ^ ((rc >>> bi) & 1)) & 1);
                }
            }
            FaestProofPrimitives.inverseAffineByteProver192(
                y, 8 * j, yTag, 8 * j * BF192.LIMBS, xt, 0, xtTag, 0);
            if (j % 4 == 3)
            {
                if (lambda == 192)
                {
                    iwd += 192;
                }
                else
                {
                    iwd += 128;
                    if (lambda == 256)
                    {
                        rmvRcon = !rmvRcon;
                    }
                }
            }
        }
    }

    static void keyexpBackwardProver256(byte[] y, long[] yTag, byte[] x, long[] xTag,
                                        byte[] key, long[] keyTag, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        byte[] xt = new byte[8];
        long[] xtTag = new long[8 * BF256.LIMBS];
        int iwd = 0;
        boolean rmvRcon = true;
        for (int j = 0; j < Ske; j++)
        {
            int rcOff = (lambda == 256) ? j / 8 : j / 4;
            int rc = RCON[rcOff] & 0xff;
            for (int bi = 0; bi < 8; bi++)
            {
                xt[bi] = (byte)((x[j * 8 + bi] ^ key[iwd + (j % 4) * 8 + bi]) & 1);
                BF256.add(xtTag, bi * BF256.LIMBS,
                    xTag, (j * 8 + bi) * BF256.LIMBS,
                    keyTag, (iwd + (j % 4) * 8 + bi) * BF256.LIMBS);
                if (rmvRcon && (j % 4 == 0))
                {
                    xt[bi] = (byte)((xt[bi] ^ ((rc >>> bi) & 1)) & 1);
                }
            }
            FaestProofPrimitives.inverseAffineByteProver256(
                y, 8 * j, yTag, 8 * j * BF256.LIMBS, xt, 0, xtTag, 0);
            if (j % 4 == 3)
            {
                if (lambda == 192)
                {
                    iwd += 192;
                }
                else
                {
                    iwd += 128;
                    if (lambda == 256)
                    {
                        rmvRcon = !rmvRcon;
                    }
                }
            }
        }
    }

    static void keyexpBackwardVerifier128(long[] yKey, long[] xKey, long[] keyKey,
                                          long[] delta, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        long[] xtKey = new long[8 * BF128.LIMBS];
        long[] rcKey = new long[BF128.LIMBS];
        int iwd = 0;
        boolean rmvRcon = true;
        for (int j = 0; j < Ske; j++)
        {
            int rcOff = (lambda == 256) ? j / 8 : j / 4;
            int rc = RCON[rcOff] & 0xff;
            for (int bi = 0; bi < 8; bi++)
            {
                BF128.add(xtKey, bi * BF128.LIMBS,
                    xKey, (j * 8 + bi) * BF128.LIMBS,
                    keyKey, (iwd + (j % 4) * 8 + bi) * BF128.LIMBS);
                if (rmvRcon && (j % 4 == 0))
                {
                    int c = (rc >>> bi) & 1;
                    BF128.mulBit(rcKey, 0, delta, 0, c);
                    BF128.addInPlace(xtKey, bi * BF128.LIMBS, rcKey, 0);
                }
            }
            FaestProofPrimitives.inverseAffineByteVerifier128(
                yKey, 8 * j * BF128.LIMBS, xtKey, 0, delta);
            if (j % 4 == 3)
            {
                if (lambda == 192)
                {
                    iwd += 192;
                }
                else
                {
                    iwd += 128;
                    if (lambda == 256)
                    {
                        rmvRcon = !rmvRcon;
                    }
                }
            }
        }
    }

    static void keyexpBackwardVerifier192(long[] yKey, long[] xKey, long[] keyKey,
                                          long[] delta, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        long[] xtKey = new long[8 * BF192.LIMBS];
        long[] rcKey = new long[BF192.LIMBS];
        int iwd = 0;
        boolean rmvRcon = true;
        for (int j = 0; j < Ske; j++)
        {
            int rcOff = (lambda == 256) ? j / 8 : j / 4;
            int rc = RCON[rcOff] & 0xff;
            for (int bi = 0; bi < 8; bi++)
            {
                BF192.add(xtKey, bi * BF192.LIMBS,
                    xKey, (j * 8 + bi) * BF192.LIMBS,
                    keyKey, (iwd + (j % 4) * 8 + bi) * BF192.LIMBS);
                if (rmvRcon && (j % 4 == 0))
                {
                    int c = (rc >>> bi) & 1;
                    BF192.mulBit(rcKey, 0, delta, 0, c);
                    BF192.addInPlace(xtKey, bi * BF192.LIMBS, rcKey, 0);
                }
            }
            FaestProofPrimitives.inverseAffineByteVerifier192(
                yKey, 8 * j * BF192.LIMBS, xtKey, 0, delta);
            if (j % 4 == 3)
            {
                if (lambda == 192)
                {
                    iwd += 192;
                }
                else
                {
                    iwd += 128;
                    if (lambda == 256)
                    {
                        rmvRcon = !rmvRcon;
                    }
                }
            }
        }
    }

    static void keyexpBackwardVerifier256(long[] yKey, long[] xKey, long[] keyKey,
                                          long[] delta, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        long[] xtKey = new long[8 * BF256.LIMBS];
        long[] rcKey = new long[BF256.LIMBS];
        int iwd = 0;
        boolean rmvRcon = true;
        for (int j = 0; j < Ske; j++)
        {
            int rcOff = (lambda == 256) ? j / 8 : j / 4;
            int rc = RCON[rcOff] & 0xff;
            for (int bi = 0; bi < 8; bi++)
            {
                BF256.add(xtKey, bi * BF256.LIMBS,
                    xKey, (j * 8 + bi) * BF256.LIMBS,
                    keyKey, (iwd + (j % 4) * 8 + bi) * BF256.LIMBS);
                if (rmvRcon && (j % 4 == 0))
                {
                    int c = (rc >>> bi) & 1;
                    BF256.mulBit(rcKey, 0, delta, 0, c);
                    BF256.addInPlace(xtKey, bi * BF256.LIMBS, rcKey, 0);
                }
            }
            FaestProofPrimitives.inverseAffineByteVerifier256(
                yKey, 8 * j * BF256.LIMBS, xtKey, 0, delta);
            if (j % 4 == 3)
            {
                if (lambda == 192)
                {
                    iwd += 192;
                }
                else
                {
                    iwd += 128;
                    if (lambda == 256)
                    {
                        rmvRcon = !rmvRcon;
                    }
                }
            }
        }
    }

    // ====== expkey_constraints ======
    // faest_aes.c:2702 (prover) / faest_aes.c:2978 (verifier).
    //
    // For each of Ske/4 column groups in the key schedule, build the lifted
    // key/witness conjugates (k_hat, w_hat, and their squares) and emit a pair
    // of degree-2 polynomial constraint coefficients per byte:
    //   z[2r]   = k_hat_sq * w_hat + k_hat_tag_sq * w_hat * delta + k_hat_tag^2 (cross)
    //   z[2r+1] = symmetric variant with k_hat/w_hat roles swapped
    // After Schoenemann's product expansion these split into (z_deg0, z_deg1).

    static void expkeyConstraintsProver128(long[] zDeg0, long[] zDeg1,
                                           byte[] k, long[] kTag,
                                           byte[] w, long[] wTag,
                                           FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        int Nk = lambda / 32;

        keyexpForwardProver128(k, kTag, w, wTag, params);
        byte[] wFlat = new byte[8 * Ske];
        long[] wFlatTag = new long[8 * Ske * BF128.LIMBS];
        // Slice w/wTag from offset lambda.
        byte[] wSlice = new byte[w.length - lambda];
        System.arraycopy(w, lambda, wSlice, 0, wSlice.length);
        long[] wTagSlice = new long[wTag.length - lambda * BF128.LIMBS];
        System.arraycopy(wTag, lambda * BF128.LIMBS, wTagSlice, 0, wTagSlice.length);
        keyexpBackwardProver128(wFlat, wFlatTag, wSlice, wTagSlice, k, kTag, params);

        int iwd = 32 * (Nk - 1);
        boolean doRotWord = true;
        long[] kHat = new long[4 * BF128.LIMBS];
        long[] wHat = new long[4 * BF128.LIMBS];
        long[] kHatSq = new long[4 * BF128.LIMBS];
        long[] wHatSq = new long[4 * BF128.LIMBS];
        long[] kHatTag = new long[4 * BF128.LIMBS];
        long[] wHatTag = new long[4 * BF128.LIMBS];
        long[] kHatTagSq = new long[4 * BF128.LIMBS];
        long[] wHatTagSq = new long[4 * BF128.LIMBS];
        long[] t1 = new long[BF128.LIMBS];
        long[] t2 = new long[BF128.LIMBS];

        for (int j = 0; j < Ske / 4; j++)
        {
            for (int r = 0; r < 4; r++)
            {
                int rPrime = doRotWord ? ((r + 3) % 4) : r;
                BF128.byteCombineBits(kHat, rPrime * BF128.LIMBS, k, iwd + 8 * r);
                BF128.byteCombineBitsSq(kHatSq, rPrime * BF128.LIMBS, k, iwd + 8 * r);
                BF128.byteCombineBits(wHat, r * BF128.LIMBS, wFlat, 32 * j + 8 * r);
                BF128.byteCombineBitsSq(wHatSq, r * BF128.LIMBS, wFlat, 32 * j + 8 * r);
                BF128.byteCombine(kHatTag, rPrime * BF128.LIMBS, kTag, (iwd + 8 * r) * BF128.LIMBS);
                BF128.byteCombineSq(kHatTagSq, rPrime * BF128.LIMBS, kTag, (iwd + 8 * r) * BF128.LIMBS);
                BF128.byteCombine(wHatTag, r * BF128.LIMBS, wFlatTag, (32 * j + 8 * r) * BF128.LIMBS);
                BF128.byteCombineSq(wHatTagSq, r * BF128.LIMBS, wFlatTag, (32 * j + 8 * r) * BF128.LIMBS);
            }
            if (lambda == 256)
            {
                doRotWord = !doRotWord;
            }
            for (int r = 0; r < 4; r++)
            {
                // z_deg1[2r] = k_hat_sq * w_hat_tag + k_hat_tag_sq * w_hat + k_hat_tag
                BF128.mul(t1, 0, kHatSq, r * BF128.LIMBS, wHatTag, r * BF128.LIMBS);
                BF128.mul(t2, 0, kHatTagSq, r * BF128.LIMBS, wHat, r * BF128.LIMBS);
                BF128.add(zDeg1, (8 * j + 2 * r) * BF128.LIMBS, t1, 0, t2, 0);
                BF128.addInPlace(zDeg1, (8 * j + 2 * r) * BF128.LIMBS, kHatTag, r * BF128.LIMBS);
                // z_deg1[2r+1] = k_hat * w_hat_tag_sq + k_hat_tag * w_hat_sq + w_hat_tag
                BF128.mul(t1, 0, kHat, r * BF128.LIMBS, wHatTagSq, r * BF128.LIMBS);
                BF128.mul(t2, 0, kHatTag, r * BF128.LIMBS, wHatSq, r * BF128.LIMBS);
                BF128.add(zDeg1, (8 * j + 2 * r + 1) * BF128.LIMBS, t1, 0, t2, 0);
                BF128.addInPlace(zDeg1, (8 * j + 2 * r + 1) * BF128.LIMBS, wHatTag, r * BF128.LIMBS);
                // z_deg0[2r]   = k_hat_tag_sq * w_hat_tag
                BF128.mul(zDeg0, (8 * j + 2 * r) * BF128.LIMBS,
                    kHatTagSq, r * BF128.LIMBS, wHatTag, r * BF128.LIMBS);
                // z_deg0[2r+1] = k_hat_tag * w_hat_tag_sq
                BF128.mul(zDeg0, (8 * j + 2 * r + 1) * BF128.LIMBS,
                    kHatTag, r * BF128.LIMBS, wHatTagSq, r * BF128.LIMBS);
            }
            iwd += (lambda == 192) ? 192 : 128;
        }
    }

    static void expkeyConstraintsProver192(long[] zDeg0, long[] zDeg1,
                                           byte[] k, long[] kTag,
                                           byte[] w, long[] wTag,
                                           FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        int Nk = lambda / 32;

        keyexpForwardProver192(k, kTag, w, wTag, params);
        byte[] wFlat = new byte[8 * Ske];
        long[] wFlatTag = new long[8 * Ske * BF192.LIMBS];
        byte[] wSlice = new byte[w.length - lambda];
        System.arraycopy(w, lambda, wSlice, 0, wSlice.length);
        long[] wTagSlice = new long[wTag.length - lambda * BF192.LIMBS];
        System.arraycopy(wTag, lambda * BF192.LIMBS, wTagSlice, 0, wTagSlice.length);
        keyexpBackwardProver192(wFlat, wFlatTag, wSlice, wTagSlice, k, kTag, params);

        int iwd = 32 * (Nk - 1);
        boolean doRotWord = true;
        long[] kHat = new long[4 * BF192.LIMBS];
        long[] wHat = new long[4 * BF192.LIMBS];
        long[] kHatSq = new long[4 * BF192.LIMBS];
        long[] wHatSq = new long[4 * BF192.LIMBS];
        long[] kHatTag = new long[4 * BF192.LIMBS];
        long[] wHatTag = new long[4 * BF192.LIMBS];
        long[] kHatTagSq = new long[4 * BF192.LIMBS];
        long[] wHatTagSq = new long[4 * BF192.LIMBS];
        long[] t1 = new long[BF192.LIMBS];
        long[] t2 = new long[BF192.LIMBS];

        for (int j = 0; j < Ske / 4; j++)
        {
            for (int r = 0; r < 4; r++)
            {
                int rPrime = doRotWord ? ((r + 3) % 4) : r;
                BF192.byteCombineBits(kHat, rPrime * BF192.LIMBS, k, iwd + 8 * r);
                BF192.byteCombineBitsSq(kHatSq, rPrime * BF192.LIMBS, k, iwd + 8 * r);
                BF192.byteCombineBits(wHat, r * BF192.LIMBS, wFlat, 32 * j + 8 * r);
                BF192.byteCombineBitsSq(wHatSq, r * BF192.LIMBS, wFlat, 32 * j + 8 * r);
                BF192.byteCombine(kHatTag, rPrime * BF192.LIMBS, kTag, (iwd + 8 * r) * BF192.LIMBS);
                BF192.byteCombineSq(kHatTagSq, rPrime * BF192.LIMBS, kTag, (iwd + 8 * r) * BF192.LIMBS);
                BF192.byteCombine(wHatTag, r * BF192.LIMBS, wFlatTag, (32 * j + 8 * r) * BF192.LIMBS);
                BF192.byteCombineSq(wHatTagSq, r * BF192.LIMBS, wFlatTag, (32 * j + 8 * r) * BF192.LIMBS);
            }
            if (lambda == 256)
            {
                doRotWord = !doRotWord;
            }
            for (int r = 0; r < 4; r++)
            {
                BF192.mul(t1, 0, kHatSq, r * BF192.LIMBS, wHatTag, r * BF192.LIMBS);
                BF192.mul(t2, 0, kHatTagSq, r * BF192.LIMBS, wHat, r * BF192.LIMBS);
                BF192.add(zDeg1, (8 * j + 2 * r) * BF192.LIMBS, t1, 0, t2, 0);
                BF192.addInPlace(zDeg1, (8 * j + 2 * r) * BF192.LIMBS, kHatTag, r * BF192.LIMBS);
                BF192.mul(t1, 0, kHat, r * BF192.LIMBS, wHatTagSq, r * BF192.LIMBS);
                BF192.mul(t2, 0, kHatTag, r * BF192.LIMBS, wHatSq, r * BF192.LIMBS);
                BF192.add(zDeg1, (8 * j + 2 * r + 1) * BF192.LIMBS, t1, 0, t2, 0);
                BF192.addInPlace(zDeg1, (8 * j + 2 * r + 1) * BF192.LIMBS, wHatTag, r * BF192.LIMBS);
                BF192.mul(zDeg0, (8 * j + 2 * r) * BF192.LIMBS,
                    kHatTagSq, r * BF192.LIMBS, wHatTag, r * BF192.LIMBS);
                BF192.mul(zDeg0, (8 * j + 2 * r + 1) * BF192.LIMBS,
                    kHatTag, r * BF192.LIMBS, wHatTagSq, r * BF192.LIMBS);
            }
            iwd += (lambda == 192) ? 192 : 128;
        }
    }

    static void expkeyConstraintsProver256(long[] zDeg0, long[] zDeg1,
                                           byte[] k, long[] kTag,
                                           byte[] w, long[] wTag,
                                           FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        int Nk = lambda / 32;

        keyexpForwardProver256(k, kTag, w, wTag, params);
        byte[] wFlat = new byte[8 * Ske];
        long[] wFlatTag = new long[8 * Ske * BF256.LIMBS];
        byte[] wSlice = new byte[w.length - lambda];
        System.arraycopy(w, lambda, wSlice, 0, wSlice.length);
        long[] wTagSlice = new long[wTag.length - lambda * BF256.LIMBS];
        System.arraycopy(wTag, lambda * BF256.LIMBS, wTagSlice, 0, wTagSlice.length);
        keyexpBackwardProver256(wFlat, wFlatTag, wSlice, wTagSlice, k, kTag, params);

        int iwd = 32 * (Nk - 1);
        boolean doRotWord = true;
        long[] kHat = new long[4 * BF256.LIMBS];
        long[] wHat = new long[4 * BF256.LIMBS];
        long[] kHatSq = new long[4 * BF256.LIMBS];
        long[] wHatSq = new long[4 * BF256.LIMBS];
        long[] kHatTag = new long[4 * BF256.LIMBS];
        long[] wHatTag = new long[4 * BF256.LIMBS];
        long[] kHatTagSq = new long[4 * BF256.LIMBS];
        long[] wHatTagSq = new long[4 * BF256.LIMBS];
        long[] t1 = new long[BF256.LIMBS];
        long[] t2 = new long[BF256.LIMBS];

        for (int j = 0; j < Ske / 4; j++)
        {
            for (int r = 0; r < 4; r++)
            {
                int rPrime = doRotWord ? ((r + 3) % 4) : r;
                BF256.byteCombineBits(kHat, rPrime * BF256.LIMBS, k, iwd + 8 * r);
                BF256.byteCombineBitsSq(kHatSq, rPrime * BF256.LIMBS, k, iwd + 8 * r);
                BF256.byteCombineBits(wHat, r * BF256.LIMBS, wFlat, 32 * j + 8 * r);
                BF256.byteCombineBitsSq(wHatSq, r * BF256.LIMBS, wFlat, 32 * j + 8 * r);
                BF256.byteCombine(kHatTag, rPrime * BF256.LIMBS, kTag, (iwd + 8 * r) * BF256.LIMBS);
                BF256.byteCombineSq(kHatTagSq, rPrime * BF256.LIMBS, kTag, (iwd + 8 * r) * BF256.LIMBS);
                BF256.byteCombine(wHatTag, r * BF256.LIMBS, wFlatTag, (32 * j + 8 * r) * BF256.LIMBS);
                BF256.byteCombineSq(wHatTagSq, r * BF256.LIMBS, wFlatTag, (32 * j + 8 * r) * BF256.LIMBS);
            }
            if (lambda == 256)
            {
                doRotWord = !doRotWord;
            }
            for (int r = 0; r < 4; r++)
            {
                BF256.mul(t1, 0, kHatSq, r * BF256.LIMBS, wHatTag, r * BF256.LIMBS);
                BF256.mul(t2, 0, kHatTagSq, r * BF256.LIMBS, wHat, r * BF256.LIMBS);
                BF256.add(zDeg1, (8 * j + 2 * r) * BF256.LIMBS, t1, 0, t2, 0);
                BF256.addInPlace(zDeg1, (8 * j + 2 * r) * BF256.LIMBS, kHatTag, r * BF256.LIMBS);
                BF256.mul(t1, 0, kHat, r * BF256.LIMBS, wHatTagSq, r * BF256.LIMBS);
                BF256.mul(t2, 0, kHatTag, r * BF256.LIMBS, wHatSq, r * BF256.LIMBS);
                BF256.add(zDeg1, (8 * j + 2 * r + 1) * BF256.LIMBS, t1, 0, t2, 0);
                BF256.addInPlace(zDeg1, (8 * j + 2 * r + 1) * BF256.LIMBS, wHatTag, r * BF256.LIMBS);
                BF256.mul(zDeg0, (8 * j + 2 * r) * BF256.LIMBS,
                    kHatTagSq, r * BF256.LIMBS, wHatTag, r * BF256.LIMBS);
                BF256.mul(zDeg0, (8 * j + 2 * r + 1) * BF256.LIMBS,
                    kHatTag, r * BF256.LIMBS, wHatTagSq, r * BF256.LIMBS);
            }
            iwd += (lambda == 192) ? 192 : 128;
        }
    }

    static void expkeyConstraintsVerifier128(long[] zDeg1, long[] kKey, long[] wKey,
                                             long[] delta, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        int Nk = lambda / 32;

        keyexpForwardVerifier128(kKey, wKey, params);
        long[] wFlatKey = new long[8 * Ske * BF128.LIMBS];
        long[] wKeySlice = new long[wKey.length - lambda * BF128.LIMBS];
        System.arraycopy(wKey, lambda * BF128.LIMBS, wKeySlice, 0, wKeySlice.length);
        keyexpBackwardVerifier128(wFlatKey, wKeySlice, kKey, delta, params);

        int iwd = 32 * (Nk - 1);
        boolean doRotWord = true;
        long[] kHatKey = new long[4 * BF128.LIMBS];
        long[] wHatKey = new long[4 * BF128.LIMBS];
        long[] kHatKeySq = new long[4 * BF128.LIMBS];
        long[] wHatKeySq = new long[4 * BF128.LIMBS];
        long[] t1 = new long[BF128.LIMBS];
        long[] t2 = new long[BF128.LIMBS];

        for (int j = 0; j < Ske / 4; j++)
        {
            for (int r = 0; r < 4; r++)
            {
                int rPrime = doRotWord ? ((r + 3) % 4) : r;
                BF128.byteCombine(kHatKey, rPrime * BF128.LIMBS, kKey, (iwd + 8 * r) * BF128.LIMBS);
                BF128.byteCombineSq(kHatKeySq, rPrime * BF128.LIMBS, kKey, (iwd + 8 * r) * BF128.LIMBS);
                BF128.byteCombine(wHatKey, r * BF128.LIMBS, wFlatKey, (32 * j + 8 * r) * BF128.LIMBS);
                BF128.byteCombineSq(wHatKeySq, r * BF128.LIMBS, wFlatKey, (32 * j + 8 * r) * BF128.LIMBS);
            }
            if (lambda == 256)
            {
                doRotWord = !doRotWord;
            }
            for (int r = 0; r < 4; r++)
            {
                // z_deg1[2r] = k_hat_key_sq * w_hat_key + delta * k_hat_key
                BF128.mul(t1, 0, kHatKeySq, r * BF128.LIMBS, wHatKey, r * BF128.LIMBS);
                BF128.mul(t2, 0, delta, 0, kHatKey, r * BF128.LIMBS);
                BF128.add(zDeg1, (8 * j + 2 * r) * BF128.LIMBS, t1, 0, t2, 0);
                // z_deg1[2r+1] = k_hat_key * w_hat_key_sq + delta * w_hat_key
                BF128.mul(t1, 0, kHatKey, r * BF128.LIMBS, wHatKeySq, r * BF128.LIMBS);
                BF128.mul(t2, 0, delta, 0, wHatKey, r * BF128.LIMBS);
                BF128.add(zDeg1, (8 * j + 2 * r + 1) * BF128.LIMBS, t1, 0, t2, 0);
            }
            iwd += (lambda == 192) ? 192 : 128;
        }
    }

    static void expkeyConstraintsVerifier192(long[] zDeg1, long[] kKey, long[] wKey,
                                             long[] delta, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        int Nk = lambda / 32;

        keyexpForwardVerifier192(kKey, wKey, params);
        long[] wFlatKey = new long[8 * Ske * BF192.LIMBS];
        long[] wKeySlice = new long[wKey.length - lambda * BF192.LIMBS];
        System.arraycopy(wKey, lambda * BF192.LIMBS, wKeySlice, 0, wKeySlice.length);
        keyexpBackwardVerifier192(wFlatKey, wKeySlice, kKey, delta, params);

        int iwd = 32 * (Nk - 1);
        boolean doRotWord = true;
        long[] kHatKey = new long[4 * BF192.LIMBS];
        long[] wHatKey = new long[4 * BF192.LIMBS];
        long[] kHatKeySq = new long[4 * BF192.LIMBS];
        long[] wHatKeySq = new long[4 * BF192.LIMBS];
        long[] t1 = new long[BF192.LIMBS];
        long[] t2 = new long[BF192.LIMBS];

        for (int j = 0; j < Ske / 4; j++)
        {
            for (int r = 0; r < 4; r++)
            {
                int rPrime = doRotWord ? ((r + 3) % 4) : r;
                BF192.byteCombine(kHatKey, rPrime * BF192.LIMBS, kKey, (iwd + 8 * r) * BF192.LIMBS);
                BF192.byteCombineSq(kHatKeySq, rPrime * BF192.LIMBS, kKey, (iwd + 8 * r) * BF192.LIMBS);
                BF192.byteCombine(wHatKey, r * BF192.LIMBS, wFlatKey, (32 * j + 8 * r) * BF192.LIMBS);
                BF192.byteCombineSq(wHatKeySq, r * BF192.LIMBS, wFlatKey, (32 * j + 8 * r) * BF192.LIMBS);
            }
            if (lambda == 256)
            {
                doRotWord = !doRotWord;
            }
            for (int r = 0; r < 4; r++)
            {
                BF192.mul(t1, 0, kHatKeySq, r * BF192.LIMBS, wHatKey, r * BF192.LIMBS);
                BF192.mul(t2, 0, delta, 0, kHatKey, r * BF192.LIMBS);
                BF192.add(zDeg1, (8 * j + 2 * r) * BF192.LIMBS, t1, 0, t2, 0);
                BF192.mul(t1, 0, kHatKey, r * BF192.LIMBS, wHatKeySq, r * BF192.LIMBS);
                BF192.mul(t2, 0, delta, 0, wHatKey, r * BF192.LIMBS);
                BF192.add(zDeg1, (8 * j + 2 * r + 1) * BF192.LIMBS, t1, 0, t2, 0);
            }
            iwd += (lambda == 192) ? 192 : 128;
        }
    }

    static void expkeyConstraintsVerifier256(long[] zDeg1, long[] kKey, long[] wKey,
                                             long[] delta, FaestParameters params)
    {
        int Ske = params.getSke();
        int lambda = params.getLambda();
        int Nk = lambda / 32;

        keyexpForwardVerifier256(kKey, wKey, params);
        long[] wFlatKey = new long[8 * Ske * BF256.LIMBS];
        long[] wKeySlice = new long[wKey.length - lambda * BF256.LIMBS];
        System.arraycopy(wKey, lambda * BF256.LIMBS, wKeySlice, 0, wKeySlice.length);
        keyexpBackwardVerifier256(wFlatKey, wKeySlice, kKey, delta, params);

        int iwd = 32 * (Nk - 1);
        boolean doRotWord = true;
        long[] kHatKey = new long[4 * BF256.LIMBS];
        long[] wHatKey = new long[4 * BF256.LIMBS];
        long[] kHatKeySq = new long[4 * BF256.LIMBS];
        long[] wHatKeySq = new long[4 * BF256.LIMBS];
        long[] t1 = new long[BF256.LIMBS];
        long[] t2 = new long[BF256.LIMBS];

        for (int j = 0; j < Ske / 4; j++)
        {
            for (int r = 0; r < 4; r++)
            {
                int rPrime = doRotWord ? ((r + 3) % 4) : r;
                BF256.byteCombine(kHatKey, rPrime * BF256.LIMBS, kKey, (iwd + 8 * r) * BF256.LIMBS);
                BF256.byteCombineSq(kHatKeySq, rPrime * BF256.LIMBS, kKey, (iwd + 8 * r) * BF256.LIMBS);
                BF256.byteCombine(wHatKey, r * BF256.LIMBS, wFlatKey, (32 * j + 8 * r) * BF256.LIMBS);
                BF256.byteCombineSq(wHatKeySq, r * BF256.LIMBS, wFlatKey, (32 * j + 8 * r) * BF256.LIMBS);
            }
            if (lambda == 256)
            {
                doRotWord = !doRotWord;
            }
            for (int r = 0; r < 4; r++)
            {
                BF256.mul(t1, 0, kHatKeySq, r * BF256.LIMBS, wHatKey, r * BF256.LIMBS);
                BF256.mul(t2, 0, delta, 0, kHatKey, r * BF256.LIMBS);
                BF256.add(zDeg1, (8 * j + 2 * r) * BF256.LIMBS, t1, 0, t2, 0);
                BF256.mul(t1, 0, kHatKey, r * BF256.LIMBS, wHatKeySq, r * BF256.LIMBS);
                BF256.mul(t2, 0, delta, 0, wHatKey, r * BF256.LIMBS);
                BF256.add(zDeg1, (8 * j + 2 * r + 1) * BF256.LIMBS, t1, 0, t2, 0);
            }
            iwd += (lambda == 192) ? 192 : 128;
        }
    }
}
