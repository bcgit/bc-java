package org.bouncycastle.pqc.crypto.faest;

/**
 * FAEST AES constraint orchestration: encryption-round constraint accumulation
 * ({@code enc_constraints}) and the top-level {@code constraints} that wires
 * key-expansion and encryption constraints into the polynomial that proves an
 * AES (or Rijndael, for FAEST-EM) one-way-function evaluation.
 * <p>
 * faest-ref source of truth: {@code faest_aes.c} (lines 3167-4990).
 */
final class FaestAESConstraints
{
    private FaestAESConstraints()
    {
    }

    // ====== enc_constraints prover (128) ======
    // faest_aes.c:3167.
    //
    // For each of R/2 "double rounds" emit:
    //  - per-byte inv_norm_constraint (3 deg-2 constraints per byte at offset 3*r*Nstbytes)
    //  - per-byte SBox/MixColumns/round-key constraint pair (2 deg-2 constraints per byte at offset (3*r+1)*Nstbytes)
    // Total z_deg* output size: 3 * Senc / 2 entries where Senc = R * Nstbits.

    static void encConstraintsProver128(long[] zDeg0, long[] zDeg1, long[] zDeg2,
                                        byte[] owfIn, long[] owfInTag,
                                        byte[] owfOut, long[] owfOutTag,
                                        byte[] w, long[] wTag,
                                        byte[] k, long[] kTag,
                                        FaestParameters params)
    {
        int Nst = params.getNst();
        int Nstbits = 32 * Nst;
        int R = params.getR();
        int Nstbytes = Nstbits / 8;

        byte[] stateBits = new byte[Nstbits];
        long[] stateBitsTag = new long[Nstbits * BF128.LIMBS];
        FaestProofPrimitives.addRoundKeyProver128(stateBits, stateBitsTag,
            owfIn, owfInTag, k, kTag, Nst);

        long[] stateConj = new long[8 * Nstbytes * BF128.LIMBS];
        long[] stateConjTag = new long[8 * Nstbytes * BF128.LIMBS];
        long[] stDashDeg2 = new long[8 * Nstbytes * BF128.LIMBS];
        long[] stDashDeg1 = new long[8 * Nstbytes * BF128.LIMBS];
        long[] stDashDeg0 = new long[8 * Nstbytes * BF128.LIMBS];

        long[] y = new long[4 * BF128.LIMBS];
        long[] yTag = new long[4 * BF128.LIMBS];

        long[] k0Deg0 = new long[Nstbytes * BF128.LIMBS];
        long[] k0Deg1 = new long[Nstbytes * BF128.LIMBS];
        long[] k1Deg0 = new long[Nstbytes * BF128.LIMBS];
        long[] k1Deg1 = new long[Nstbytes * BF128.LIMBS];
        long[] k1Deg2 = new long[Nstbytes * BF128.LIMBS];

        long[][] stBDeg0 = new long[2][Nstbytes * BF128.LIMBS];
        long[][] stBDeg1 = new long[2][Nstbytes * BF128.LIMBS];
        long[][] stBDeg2 = new long[2][Nstbytes * BF128.LIMBS];
        long[][] stBDeg0Tmp = new long[2][Nstbytes * BF128.LIMBS];
        long[][] stBDeg1Tmp = new long[2][Nstbytes * BF128.LIMBS];
        long[][] stBDeg2Tmp = new long[2][Nstbytes * BF128.LIMBS];
        long[] dummyKey = new long[Nstbytes * BF128.LIMBS];

        byte[] sTilde = new byte[Nstbits];
        long[] sTildeTag = new long[Nstbits * BF128.LIMBS];
        byte[] sDashDash = new byte[Nstbits];
        long[] sDashDashTag = new long[Nstbits * BF128.LIMBS];
        byte[] s = new byte[Nstbits];
        long[] sTag = new long[Nstbits * BF128.LIMBS];

        long[] sDeg0 = new long[BF128.LIMBS];
        long[] sDeg1 = new long[BF128.LIMBS];
        long[] sSqDeg0 = new long[BF128.LIMBS];
        long[] sSqDeg1 = new long[BF128.LIMBS];
        long[] tmp = new long[BF128.LIMBS];
        long[] tmp2 = new long[BF128.LIMBS];
        // Scratch for invNormConstraintsProver128's internal field operations,
        // hoisted out of the r×i inner loop.
        long[] invNormT1 = new long[BF128.LIMBS];
        long[] invNormT2 = new long[BF128.LIMBS];

        byte[] tmpState = new byte[Nstbits];
        long[] tmpStateTag = new long[Nstbits * BF128.LIMBS];

        for (int r = 0; r < R / 2; r++)
        {
            FaestProofPrimitives.f256F2Conjugates1_128(stateConj, stateBits, Nst);
            FaestProofPrimitives.f256F2ConjugatesLambda_128(stateConjTag, stateBitsTag, Nst);

            int normsOff = (3 * Nstbits * r) / 2;
            int normTagsOff = ((3 * Nstbits * r) / 2) * BF128.LIMBS;

            for (int i = 0; i < Nstbytes; i++)
            {
                FaestProofPrimitives.invNormToConjugatesProver128(y, yTag,
                    sliceBits(w, normsOff + 4 * i, 4),
                    sliceLongs(wTag, normTagsOff + 4 * i * BF128.LIMBS, 4 * BF128.LIMBS));

                int zOff = (3 * r * Nstbytes + i) * BF128.LIMBS;
                FaestProofPrimitives.invNormConstraintsProver128(
                    zDeg0, zOff, zDeg1, zOff, zDeg2, zOff,
                    sliceLongs(stateConj, 8 * i * BF128.LIMBS, 8 * BF128.LIMBS),
                    sliceLongs(stateConjTag, 8 * i * BF128.LIMBS, 8 * BF128.LIMBS),
                    y, yTag, invNormT1, invNormT2);

                for (int j = 0; j < 8; j++)
                {
                    int conjIndex = (i * 8 + ((j + 4) % 8)) * BF128.LIMBS;
                    int yIndex = (j % 4) * BF128.LIMBS;
                    int dst = (i * 8 + j) * BF128.LIMBS;
                    // st_dash_deg2 = state_conj * y
                    BF128.mul(stDashDeg2, dst, stateConj, conjIndex, y, yIndex);
                    // st_dash_deg1 = state_conj * y_tag + state_conj_tag * y
                    BF128.mul(tmp, 0, stateConj, conjIndex, yTag, yIndex);
                    BF128.mul(tmp2, 0, stateConjTag, conjIndex, y, yIndex);
                    BF128.add(stDashDeg1, dst, tmp, 0, tmp2, 0);
                    // st_dash_deg0 = state_conj_tag * y_tag
                    BF128.mul(stDashDeg0, dst, stateConjTag, conjIndex, yTag, yIndex);
                }
            }

            // k_0 = state_to_bytes(k[(2r+1)*Nstbits..])
            // Note: upstream signature is (k_0_deg1, k_0_deg0, k, k_tag) — deg1 is the
            // byte_combine_bits output (value), deg0 is the byte_combine output (tag).
            FaestProofPrimitives.stateToBytesProver128(k0Deg1, k0Deg0,
                sliceBits(k, (2 * r + 1) * Nstbits, Nstbits),
                sliceLongs(kTag, (2 * r + 1) * Nstbits * BF128.LIMBS, Nstbits * BF128.LIMBS),
                Nst);
            // k_1 = k_0^2 — squaring of the byte-level deg-0/1 elements
            for (int b = 0; b < Nstbytes; b++)
            {
                int off = b * BF128.LIMBS;
                BF128.mul(k1Deg0, off, k0Deg0, off, k0Deg0, off);
                java.util.Arrays.fill(k1Deg1, off, off + BF128.LIMBS, 0L);
                BF128.mul(k1Deg2, off, k0Deg1, off, k0Deg1, off);
            }

            // Zero the st_b accumulators.
            for (int b = 0; b < 2; b++)
            {
                java.util.Arrays.fill(stBDeg0[b], 0, Nstbytes * BF128.LIMBS, 0L);
                java.util.Arrays.fill(stBDeg1[b], 0, Nstbytes * BF128.LIMBS, 0L);
                java.util.Arrays.fill(stBDeg2[b], 0, Nstbytes * BF128.LIMBS, 0L);
            }
            java.util.Arrays.fill(dummyKey, 0L);

            for (int b = 0; b < 2; b++)
            {
                FaestProofPrimitives.sboxAffineProver128(
                    stBDeg0[b], stBDeg1[b], stBDeg2[b],
                    stDashDeg0, stDashDeg1, stDashDeg2, b == 1, Nst);
                FaestProofPrimitives.shiftRowsProver128(
                    stBDeg0Tmp[b], stBDeg1Tmp[b], stBDeg2Tmp[b],
                    stBDeg0[b], stBDeg1[b], stBDeg2[b], Nst);
                System.arraycopy(stBDeg0Tmp[b], 0, stBDeg0[b], 0, Nstbytes * BF128.LIMBS);
                System.arraycopy(stBDeg1Tmp[b], 0, stBDeg1[b], 0, Nstbytes * BF128.LIMBS);
                System.arraycopy(stBDeg2Tmp[b], 0, stBDeg2[b], 0, Nstbytes * BF128.LIMBS);
                FaestProofPrimitives.mixColumnsProver128(
                    stBDeg0[b], stBDeg1[b], stBDeg2[b],
                    stBDeg0Tmp[b], stBDeg1Tmp[b], stBDeg2Tmp[b], b == 1, Nst);
                if (b == 0)
                {
                    FaestProofPrimitives.addRoundKeyBytesProver128(
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        dummyKey, k0Deg0, k0Deg1, Nst);
                }
                else
                {
                    FaestProofPrimitives.addRoundKeyBytesProver128(
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        k1Deg0, k1Deg1, k1Deg2, Nst);
                }
            }

            // s_tilde
            if (r == R / 2 - 1)
            {
                FaestProofPrimitives.addRoundKeyProver128(sTilde, sTildeTag,
                    owfOut, owfOutTag,
                    sliceBits(k, R * Nstbits, Nstbits),
                    sliceLongs(kTag, R * Nstbits * BF128.LIMBS, Nstbits * BF128.LIMBS),
                    Nst);
            }
            else
            {
                int srcOff = Nstbits / 2 + (3 * Nstbits / 2) * r;
                System.arraycopy(w, srcOff, sTilde, 0, Nstbits);
                System.arraycopy(wTag, srcOff * BF128.LIMBS, sTildeTag, 0, Nstbits * BF128.LIMBS);
            }

            FaestProofPrimitives.inverseShiftRowsProver128(sDashDash, sDashDashTag,
                sTilde, sTildeTag, Nst);
            FaestProofPrimitives.inverseAffineProver128(s, sTag, sDashDash, sDashDashTag, Nst);

            for (int byteI = 0; byteI < Nstbytes; byteI++)
            {
                BF128.byteCombineBits(sDeg1, 0, s, 8 * byteI);
                BF128.byteCombine(sDeg0, 0, sTag, 8 * byteI * BF128.LIMBS);
                BF128.byteCombineBitsSq(sSqDeg1, 0, s, 8 * byteI);
                BF128.byteCombineSq(sSqDeg0, 0, sTag, 8 * byteI * BF128.LIMBS);

                int dst0 = ((3 * r + 1) * Nstbytes + 2 * byteI) * BF128.LIMBS;
                int dst1 = ((3 * r + 1) * Nstbytes + 2 * byteI + 1) * BF128.LIMBS;
                int stOff = byteI * BF128.LIMBS;

                // z_deg0[2byte_i]   = s_sq_deg0 * st_b_deg0[0]
                BF128.mul(zDeg0, dst0, sSqDeg0, 0, stBDeg0[0], stOff);
                // z_deg1[2byte_i]   = s_sq_deg0 * st_b_deg1[0] + s_sq_deg1 * st_b_deg0[0]
                BF128.mul(tmp, 0, sSqDeg0, 0, stBDeg1[0], stOff);
                BF128.mul(tmp2, 0, sSqDeg1, 0, stBDeg0[0], stOff);
                BF128.add(zDeg1, dst0, tmp, 0, tmp2, 0);
                // z_deg2[2byte_i]   = s_sq_deg0 * st_b_deg2[0] + s_sq_deg1 * st_b_deg1[0] + s_deg0
                BF128.mul(tmp, 0, sSqDeg0, 0, stBDeg2[0], stOff);
                BF128.mul(tmp2, 0, sSqDeg1, 0, stBDeg1[0], stOff);
                BF128.add(zDeg2, dst0, tmp, 0, tmp2, 0);
                BF128.addInPlace(zDeg2, dst0, sDeg0, 0);

                // z_deg0[2byte_i+1] = s_deg0 * st_b_deg0[1]
                BF128.mul(zDeg0, dst1, sDeg0, 0, stBDeg0[1], stOff);
                // z_deg1[2byte_i+1] = s_deg0 * st_b_deg1[1] + s_deg1 * st_b_deg0[1] + st_b_deg0[0]
                BF128.mul(tmp, 0, sDeg0, 0, stBDeg1[1], stOff);
                BF128.mul(tmp2, 0, sDeg1, 0, stBDeg0[1], stOff);
                BF128.add(zDeg1, dst1, tmp, 0, tmp2, 0);
                BF128.addInPlace(zDeg1, dst1, stBDeg0[0], stOff);
                // z_deg2[2byte_i+1] = s_deg0 * st_b_deg2[1] + s_deg1 * st_b_deg1[1] + st_b_deg1[0]
                BF128.mul(tmp, 0, sDeg0, 0, stBDeg2[1], stOff);
                BF128.mul(tmp2, 0, sDeg1, 0, stBDeg1[1], stOff);
                BF128.add(zDeg2, dst1, tmp, 0, tmp2, 0);
                BF128.addInPlace(zDeg2, dst1, stBDeg1[0], stOff);
            }

            if (r != R / 2 - 1)
            {
                FaestProofPrimitives.bitwiseMixColumnProver128(tmpState, tmpStateTag,
                    sTilde, sTildeTag, Nst);
                FaestProofPrimitives.addRoundKeyProver128(stateBits, stateBitsTag,
                    tmpState, tmpStateTag,
                    sliceBits(k, (2 * r + 2) * Nstbits, Nstbits),
                    sliceLongs(kTag, (2 * r + 2) * Nstbits * BF128.LIMBS, Nstbits * BF128.LIMBS),
                    Nst);
            }
        }
    }

    // ====== enc_constraints verifier (128) ======
    // faest_aes.c:3864.

    static void encConstraintsVerifier128(long[] zKey,
                                          long[] owfInKey, long[] owfOutKey,
                                          long[] wKey, long[] rkeysKey, long[] delta,
                                          FaestParameters params)
    {
        int Nst = params.getNst();
        int Nstbits = 32 * Nst;
        int R = params.getR();
        int Nstbytes = Nstbits / 8;

        long[] stateBitsKey = new long[Nstbits * BF128.LIMBS];
        FaestProofPrimitives.addRoundKeyVerifier128(stateBitsKey, owfInKey, rkeysKey, Nst);

        long[] stateConjKey = new long[8 * Nstbytes * BF128.LIMBS];
        long[] stDashKey = new long[8 * Nstbytes * BF128.LIMBS];

        long[] yKey = new long[4 * BF128.LIMBS];

        long[] k0Key = new long[Nstbytes * BF128.LIMBS];
        long[] k1Key = new long[Nstbytes * BF128.LIMBS];

        long[][] stBKey = new long[2][Nstbytes * BF128.LIMBS];
        long[][] stBTmpKey = new long[2][Nstbytes * BF128.LIMBS];

        long[] sTildeKey = new long[Nstbits * BF128.LIMBS];
        long[] sDashDashKey = new long[Nstbits * BF128.LIMBS];
        long[] sStateKey = new long[Nstbits * BF128.LIMBS];

        long[] sKey = new long[BF128.LIMBS];
        long[] sSqKey = new long[BF128.LIMBS];
        long[] tmp = new long[BF128.LIMBS];
        long[] d2 = new long[BF128.LIMBS];
        BF128.mul(d2, 0, delta, 0, delta, 0);
        // Scratch for invNormConstraintsVerifier128, hoisted out of the r×i inner loop.
        long[] invNormT = new long[BF128.LIMBS];

        long[] tmpStateKey = new long[Nstbits * BF128.LIMBS];

        for (int r = 0; r < R / 2; r++)
        {
            FaestProofPrimitives.f256F2ConjugatesLambda_128(stateConjKey, stateBitsKey, Nst);

            int normKeysOff = ((3 * Nstbits * r) / 2) * BF128.LIMBS;

            for (int i = 0; i < Nstbytes; i++)
            {
                FaestProofPrimitives.invNormToConjugatesVerifier128(yKey,
                    sliceLongs(wKey, normKeysOff + 4 * i * BF128.LIMBS, 4 * BF128.LIMBS));

                int zOff = (3 * r * Nstbytes + i) * BF128.LIMBS;
                FaestProofPrimitives.invNormConstraintsVerifier128(zKey, zOff,
                    sliceLongs(stateConjKey, 8 * i * BF128.LIMBS, 8 * BF128.LIMBS),
                    yKey, d2, invNormT);

                for (int j = 0; j < 8; j++)
                {
                    int conjIndex = (i * 8 + ((j + 4) % 8)) * BF128.LIMBS;
                    int yIndex = (j % 4) * BF128.LIMBS;
                    int dst = (i * 8 + j) * BF128.LIMBS;
                    BF128.mul(stDashKey, dst, stateConjKey, conjIndex, yKey, yIndex);
                }
            }

            FaestProofPrimitives.stateToBytesVerifier128(k0Key,
                sliceLongs(rkeysKey, (2 * r + 1) * Nstbits * BF128.LIMBS, Nstbits * BF128.LIMBS),
                Nst);
            for (int b = 0; b < Nstbytes; b++)
            {
                int off = b * BF128.LIMBS;
                BF128.mul(k1Key, off, k0Key, off, k0Key, off);
            }

            for (int b = 0; b < 2; b++)
            {
                java.util.Arrays.fill(stBKey[b], 0, Nstbytes * BF128.LIMBS, 0L);
                java.util.Arrays.fill(stBTmpKey[b], 0, Nstbytes * BF128.LIMBS, 0L);
            }

            for (int b = 0; b < 2; b++)
            {
                FaestProofPrimitives.sboxAffineVerifier128(stBKey[b], stDashKey, delta, b == 1, Nst);
                FaestProofPrimitives.shiftRowsVerifier128(stBTmpKey[b], stBKey[b], Nst);
                System.arraycopy(stBTmpKey[b], 0, stBKey[b], 0, Nstbytes * BF128.LIMBS);
                FaestProofPrimitives.mixColumnsVerifier128(stBTmpKey[b], stBKey[b], b == 1, Nst);
                System.arraycopy(stBTmpKey[b], 0, stBKey[b], 0, Nstbytes * BF128.LIMBS);
                if (b == 0)
                {
                    FaestProofPrimitives.addRoundKeyBytesVerifier128(
                        stBKey[b], stBKey[b], k0Key, delta, true, Nst);
                }
                else
                {
                    FaestProofPrimitives.addRoundKeyBytesVerifier128(
                        stBKey[b], stBKey[b], k1Key, delta, false, Nst);
                }
            }

            if (r == R / 2 - 1)
            {
                FaestProofPrimitives.addRoundKeyVerifier128(sTildeKey, owfOutKey,
                    sliceLongs(rkeysKey, R * Nstbits * BF128.LIMBS, Nstbits * BF128.LIMBS), Nst);
            }
            else
            {
                int srcOff = (Nstbits / 2 + (3 * Nstbits / 2) * r) * BF128.LIMBS;
                System.arraycopy(wKey, srcOff, sTildeKey, 0, Nstbits * BF128.LIMBS);
            }

            FaestProofPrimitives.inverseShiftRowsVerifier128(sDashDashKey, sTildeKey, Nst);
            FaestProofPrimitives.inverseAffineVerifier128(sStateKey, sDashDashKey, delta, Nst);

            for (int byteI = 0; byteI < Nstbytes; byteI++)
            {
                BF128.byteCombine(sKey, 0, sStateKey, 8 * byteI * BF128.LIMBS);
                BF128.byteCombineSq(sSqKey, 0, sStateKey, 8 * byteI * BF128.LIMBS);

                int dst0 = ((3 * r + 1) * Nstbytes + 2 * byteI) * BF128.LIMBS;
                int dst1 = ((3 * r + 1) * Nstbytes + 2 * byteI + 1) * BF128.LIMBS;
                int stOff = byteI * BF128.LIMBS;

                // z_key[2byte_i] = s_sq_key * st_b_key[0] + delta^2 * s_key
                BF128.mul(zKey, dst0, sSqKey, 0, stBKey[0], stOff);
                BF128.mul(tmp, 0, d2, 0, sKey, 0);
                BF128.addInPlace(zKey, dst0, tmp, 0);

                // z_key[2byte_i+1] = s_key * st_b_key[1] + delta * st_b_key[0]
                BF128.mul(zKey, dst1, sKey, 0, stBKey[1], stOff);
                BF128.mul(tmp, 0, delta, 0, stBKey[0], stOff);
                BF128.addInPlace(zKey, dst1, tmp, 0);
            }

            if (r != R / 2 - 1)
            {
                FaestProofPrimitives.bitwiseMixColumnVerifier128(tmpStateKey, sTildeKey, Nst);
                FaestProofPrimitives.addRoundKeyVerifier128(stateBitsKey, tmpStateKey,
                    sliceLongs(rkeysKey, (2 * r + 2) * Nstbits * BF128.LIMBS, Nstbits * BF128.LIMBS),
                    Nst);
            }
        }
    }

    // ====== constraints orchestrator (128) ======
    // faest_aes.c:4278 (prover) / faest_aes.c:4692 (verifier).
    //
    // Wires expkey_constraints + enc_constraints into the full FAEST AES constraint
    // polynomial. For FAEST-EM (Even-Mansour), the OWF key is public and round keys
    // are derived by running expand_key on owf_in; expkey_constraints is skipped.

    static void constraintsProver128(long[] zDeg0, long[] zDeg1, long[] zDeg2,
                                     byte[] w, long[] wTag,
                                     byte[] owfIn, byte[] owfOut,
                                     FaestParameters params)
    {
        int lambda = params.getLambda();
        int R = params.getR();
        int Ske = params.getSke();
        int Lke = params.getLke();
        int Lenc = params.getLenc();
        int Senc = params.getSenc();
        int Nk = lambda / 32;
        int Nst = params.getNst();
        int numEncConstraints = 3 * Senc / 2;
        int blocksize = 32 * Nst;
        int beta = (lambda + blocksize - 1) / blocksize;
        boolean isEM = params.isEm();

        // z_deg0[0] = 0; z_deg1[0] = w_tag[0] * w_tag[1]; z_deg2[0] = w_tag[0]*w[1] + w_tag[1]*w[0]
        java.util.Arrays.fill(zDeg0, 0, BF128.LIMBS, 0L);
        BF128.mul(zDeg1, 0, wTag, 0, wTag, BF128.LIMBS);
        long[] t1 = new long[BF128.LIMBS];
        long[] t2 = new long[BF128.LIMBS];
        BF128.mulBit(t1, 0, wTag, 0, w[1]);
        BF128.mulBit(t2, 0, wTag, BF128.LIMBS, w[0]);
        BF128.add(zDeg2, 0, t1, 0, t2, 0);

        byte[] in = new byte[blocksize];
        long[] inTag = new long[blocksize * BF128.LIMBS];
        byte[] out = new byte[beta * blocksize];
        long[] outTag = new long[beta * blocksize * BF128.LIMBS];
        byte[] rkeys = new byte[(R + 1) * blocksize];
        long[] rkeysTag = new long[(R + 1) * blocksize * BF128.LIMBS];

        if (isEM)
        {
            // Derive round keys from owf_in (public).
            byte[] rkBytes = new byte[(R + 1) * 4 * Nk];
            FaestAES.expandKey(rkBytes, owfIn, 0, Nk, Nk, R);
            int idx = 0;
            for (int rr = 0; rr < R + 1; rr++)
            {
                for (int n = 0; n < Nst; n++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        int rk = rkBytes[rr * 4 * Nk + n * 4 + i] & 0xff;
                        for (int j = 0; j < 8; j++)
                        {
                            rkeys[8 * idx + j] = (byte)((rk >>> j) & 1);
                            // rkeys_tag[8*idx + j] = 0
                        }
                        idx++;
                    }
                }
            }
            for (int i = 0; i < blocksize; i++)
            {
                in[i] = w[i];
                System.arraycopy(wTag, i * BF128.LIMBS, inTag, i * BF128.LIMBS, BF128.LIMBS);
            }
            for (int i = 0; i < blocksize; i++)
            {
                out[i] = (byte)((w[i] ^ ((owfOut[i / 8] >>> (i % 8)) & 1)) & 1);
                System.arraycopy(wTag, i * BF128.LIMBS, outTag, i * BF128.LIMBS, BF128.LIMBS);
            }
        }
        else
        {
            // AES: in and out are public.
            for (int i = 0; i < blocksize; i++)
            {
                in[i] = (byte)(((owfIn[i / 8] >>> (i % 8)) & 1) & 1);
            }
            FaestProofPrimitives.constantToVoleProver128(inTag, blocksize);
            for (int i = 0; i < beta * blocksize; i++)
            {
                out[i] = (byte)(((owfOut[i / 8] >>> (i % 8)) & 1) & 1);
            }
            FaestProofPrimitives.constantToVoleProver128(outTag, blocksize);

            long[] zTildeDeg0Tag = new long[2 * Ske * BF128.LIMBS];
            long[] zTildeDeg1Val = new long[2 * Ske * BF128.LIMBS];
            FaestKeyExpansion.expkeyConstraintsProver128(zTildeDeg0Tag, zTildeDeg1Val,
                rkeys, rkeysTag, w, wTag, params);
            // Raise degree: z_deg0[1+i]=0, z_deg1[1+i]=z_tilde_deg0_tag, z_deg2[1+i]=z_tilde_deg1_val
            for (int i = 0; i < 2 * Ske; i++)
            {
                int off = (1 + i) * BF128.LIMBS;
                java.util.Arrays.fill(zDeg0, off, off + BF128.LIMBS, 0L);
                System.arraycopy(zTildeDeg0Tag, i * BF128.LIMBS, zDeg1, off, BF128.LIMBS);
                System.arraycopy(zTildeDeg1Val, i * BF128.LIMBS, zDeg2, off, BF128.LIMBS);
            }
        }

        byte[] wTilde = new byte[Lenc];
        long[] wTildeTag = new long[Lenc * BF128.LIMBS];
        long[] zTildeDeg0 = new long[numEncConstraints * BF128.LIMBS];
        long[] zTildeDeg1 = new long[numEncConstraints * BF128.LIMBS];
        long[] zTildeDeg2 = new long[numEncConstraints * BF128.LIMBS];

        int outOff = 0;
        for (int b = 0; b < beta; b++)
        {
            for (int i = 0; i < Lenc; i++)
            {
                wTilde[i] = w[Lke + b * Lenc + i];
                System.arraycopy(wTag, (Lke + b * Lenc + i) * BF128.LIMBS, wTildeTag,
                    i * BF128.LIMBS, BF128.LIMBS);
            }
            java.util.Arrays.fill(zTildeDeg0, 0L);
            java.util.Arrays.fill(zTildeDeg1, 0L);
            java.util.Arrays.fill(zTildeDeg2, 0L);

            if (b == 1)
            {
                in[0] = (byte)((in[0] ^ 1) & 1);
                // in_tag[0] += 1: add one to the low byte of in_tag's first element
                long[] one = new long[BF128.LIMBS];
                BF128.one(one, 0);
                BF128.addInPlace(inTag, 0, one, 0);
                outOff = blocksize;
            }

            encConstraintsProver128(zTildeDeg0, zTildeDeg1, zTildeDeg2,
                in, inTag,
                sliceBits(out, outOff, blocksize),
                sliceLongs(outTag, outOff * BF128.LIMBS, blocksize * BF128.LIMBS),
                wTilde, wTildeTag, rkeys, rkeysTag, params);

            for (int i = 0; i < numEncConstraints; i++)
            {
                int dst = (1 + 2 * Ske + b * numEncConstraints + i) * BF128.LIMBS;
                int src = i * BF128.LIMBS;
                System.arraycopy(zTildeDeg0, src, zDeg0, dst, BF128.LIMBS);
                System.arraycopy(zTildeDeg1, src, zDeg1, dst, BF128.LIMBS);
                System.arraycopy(zTildeDeg2, src, zDeg2, dst, BF128.LIMBS);
            }
        }
    }

    static void constraintsVerifier128(long[] zKey, long[] wKey,
                                       byte[] owfIn, byte[] owfOut, long[] delta,
                                       FaestParameters params)
    {
        int lambda = params.getLambda();
        int R = params.getR();
        int Lke = params.getLke();
        int Lenc = params.getLenc();
        int Senc = params.getSenc();
        int Ske = params.getSke();
        int Nk = lambda / 32;
        int Nst = params.getNst();
        int numEncConstraints = 3 * Senc / 2;
        int numKsConstraints = 2 * Ske;
        int blocksize = 32 * Nst;
        int beta = (lambda + blocksize - 1) / blocksize;
        boolean isEM = params.isEm();

        // z_key[0] = delta * w_key[0] * w_key[1]
        long[] t = new long[BF128.LIMBS];
        BF128.mul(t, 0, wKey, 0, wKey, BF128.LIMBS);
        BF128.mul(zKey, 0, delta, 0, t, 0);

        long[] rkeysKey = new long[(R + 1) * blocksize * BF128.LIMBS];
        long[] inKey = new long[blocksize * BF128.LIMBS];
        long[] outKey = new long[beta * blocksize * BF128.LIMBS];

        if (isEM)
        {
            byte[] rkBytes = new byte[(R + 1) * 4 * Nk];
            FaestAES.expandKey(rkBytes, owfIn, 0, Nk, Nk, R);
            int idx = 0;
            for (int rr = 0; rr < R + 1; rr++)
            {
                for (int n = 0; n < Nst; n++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        int rk = rkBytes[rr * 4 * Nk + n * 4 + i] & 0xff;
                        for (int j = 0; j < 8; j++)
                        {
                            BF128.mulBit(rkeysKey, (8 * idx + j) * BF128.LIMBS,
                                delta, 0, (rk >>> j) & 1);
                        }
                        idx++;
                    }
                }
            }
            for (int i = 0; i < blocksize; i++)
            {
                System.arraycopy(wKey, i * BF128.LIMBS, inKey, i * BF128.LIMBS, BF128.LIMBS);
                int bit = (owfOut[i / 8] >>> (i % 8)) & 1;
                long[] bd = new long[BF128.LIMBS];
                BF128.mulBit(bd, 0, delta, 0, bit);
                BF128.add(outKey, i * BF128.LIMBS, wKey, i * BF128.LIMBS, bd, 0);
            }
        }
        else
        {
            FaestProofPrimitives.constantToVoleVerifier128(inKey, owfIn, delta, blocksize);
            FaestProofPrimitives.constantToVoleVerifier128(outKey, owfOut, delta, beta * blocksize);

            long[] zTildeKey = new long[2 * Ske * BF128.LIMBS];
            FaestKeyExpansion.expkeyConstraintsVerifier128(zTildeKey, rkeysKey, wKey, delta, params);
            for (int i = 0; i < numKsConstraints; i++)
            {
                BF128.mul(zKey, (1 + i) * BF128.LIMBS, delta, 0, zTildeKey, i * BF128.LIMBS);
            }
        }

        long[] wTildeKey = new long[Lenc * BF128.LIMBS];
        long[] zTildeEncKey = new long[numEncConstraints * BF128.LIMBS];
        int outOff = 0;
        for (int b = 0; b < beta; b++)
        {
            for (int i = 0; i < Lenc; i++)
            {
                System.arraycopy(wKey, (Lke + b * Lenc + i) * BF128.LIMBS, wTildeKey,
                    i * BF128.LIMBS, BF128.LIMBS);
            }
            java.util.Arrays.fill(zTildeEncKey, 0L);
            if (b == 1)
            {
                BF128.addInPlace(inKey, 0, delta, 0);
                outOff = blocksize;
            }
            encConstraintsVerifier128(zTildeEncKey, inKey,
                sliceLongs(outKey, outOff * BF128.LIMBS, blocksize * BF128.LIMBS),
                wTildeKey, rkeysKey, delta, params);
            for (int i = 0; i < numEncConstraints; i++)
            {
                int dst = (1 + numKsConstraints + b * numEncConstraints + i) * BF128.LIMBS;
                int src = i * BF128.LIMBS;
                System.arraycopy(zTildeEncKey, src, zKey, dst, BF128.LIMBS);
            }
        }
    }

    // ====== helpers ======

    /** Returns a copy of {@code src[off..off+n]} so we can pass slices into routines
     * that require offset-0 access. Slightly wasteful but keeps the code readable. */
    private static byte[] sliceBits(byte[] src, int off, int n)
    {
        byte[] r = new byte[n];
        System.arraycopy(src, off, r, 0, n);
        return r;
    }

    private static long[] sliceLongs(long[] src, int off, int n)
    {
        long[] r = new long[n];
        System.arraycopy(src, off, r, 0, n);
        return r;
    }


    // ====== enc_constraints prover (192) ======
    // faest_aes.c:3167.
    //
    // For each of R/2 "double rounds" emit:
    //  - per-byte inv_norm_constraint (3 deg-2 constraints per byte at offset 3*r*Nstbytes)
    //  - per-byte SBox/MixColumns/round-key constraint pair (2 deg-2 constraints per byte at offset (3*r+1)*Nstbytes)
    // Total z_deg* output size: 3 * Senc / 2 entries where Senc = R * Nstbits.

    static void encConstraintsProver192(long[] zDeg0, long[] zDeg1, long[] zDeg2,
                                        byte[] owfIn, long[] owfInTag,
                                        byte[] owfOut, long[] owfOutTag,
                                        byte[] w, long[] wTag,
                                        byte[] k, long[] kTag,
                                        FaestParameters params)
    {
        int Nst = params.getNst();
        int Nstbits = 32 * Nst;
        int R = params.getR();
        int Nstbytes = Nstbits / 8;

        byte[] stateBits = new byte[Nstbits];
        long[] stateBitsTag = new long[Nstbits * BF192.LIMBS];
        FaestProofPrimitives.addRoundKeyProver192(stateBits, stateBitsTag,
            owfIn, owfInTag, k, kTag, Nst);

        long[] stateConj = new long[8 * Nstbytes * BF192.LIMBS];
        long[] stateConjTag = new long[8 * Nstbytes * BF192.LIMBS];
        long[] stDashDeg2 = new long[8 * Nstbytes * BF192.LIMBS];
        long[] stDashDeg1 = new long[8 * Nstbytes * BF192.LIMBS];
        long[] stDashDeg0 = new long[8 * Nstbytes * BF192.LIMBS];

        long[] y = new long[4 * BF192.LIMBS];
        long[] yTag = new long[4 * BF192.LIMBS];

        long[] k0Deg0 = new long[Nstbytes * BF192.LIMBS];
        long[] k0Deg1 = new long[Nstbytes * BF192.LIMBS];
        long[] k1Deg0 = new long[Nstbytes * BF192.LIMBS];
        long[] k1Deg1 = new long[Nstbytes * BF192.LIMBS];
        long[] k1Deg2 = new long[Nstbytes * BF192.LIMBS];

        long[][] stBDeg0 = new long[2][Nstbytes * BF192.LIMBS];
        long[][] stBDeg1 = new long[2][Nstbytes * BF192.LIMBS];
        long[][] stBDeg2 = new long[2][Nstbytes * BF192.LIMBS];
        long[][] stBDeg0Tmp = new long[2][Nstbytes * BF192.LIMBS];
        long[][] stBDeg1Tmp = new long[2][Nstbytes * BF192.LIMBS];
        long[][] stBDeg2Tmp = new long[2][Nstbytes * BF192.LIMBS];
        long[] dummyKey = new long[Nstbytes * BF192.LIMBS];

        byte[] sTilde = new byte[Nstbits];
        long[] sTildeTag = new long[Nstbits * BF192.LIMBS];
        byte[] sDashDash = new byte[Nstbits];
        long[] sDashDashTag = new long[Nstbits * BF192.LIMBS];
        byte[] s = new byte[Nstbits];
        long[] sTag = new long[Nstbits * BF192.LIMBS];

        long[] sDeg0 = new long[BF192.LIMBS];
        long[] sDeg1 = new long[BF192.LIMBS];
        long[] sSqDeg0 = new long[BF192.LIMBS];
        long[] sSqDeg1 = new long[BF192.LIMBS];
        long[] tmp = new long[BF192.LIMBS];
        long[] tmp2 = new long[BF192.LIMBS];
        long[] invNormT1 = new long[BF192.LIMBS];
        long[] invNormT2 = new long[BF192.LIMBS];

        byte[] tmpState = new byte[Nstbits];
        long[] tmpStateTag = new long[Nstbits * BF192.LIMBS];

        for (int r = 0; r < R / 2; r++)
        {
            FaestProofPrimitives.f256F2Conjugates1_192(stateConj, stateBits, Nst);
            FaestProofPrimitives.f256F2ConjugatesLambda_192(stateConjTag, stateBitsTag, Nst);

            int normsOff = (3 * Nstbits * r) / 2;
            int normTagsOff = ((3 * Nstbits * r) / 2) * BF192.LIMBS;

            for (int i = 0; i < Nstbytes; i++)
            {
                FaestProofPrimitives.invNormToConjugatesProver192(y, yTag,
                    sliceBits(w, normsOff + 4 * i, 4),
                    sliceLongs(wTag, normTagsOff + 4 * i * BF192.LIMBS, 4 * BF192.LIMBS));

                int zOff = (3 * r * Nstbytes + i) * BF192.LIMBS;
                FaestProofPrimitives.invNormConstraintsProver192(
                    zDeg0, zOff, zDeg1, zOff, zDeg2, zOff,
                    sliceLongs(stateConj, 8 * i * BF192.LIMBS, 8 * BF192.LIMBS),
                    sliceLongs(stateConjTag, 8 * i * BF192.LIMBS, 8 * BF192.LIMBS),
                    y, yTag, invNormT1, invNormT2);

                for (int j = 0; j < 8; j++)
                {
                    int conjIndex = (i * 8 + ((j + 4) % 8)) * BF192.LIMBS;
                    int yIndex = (j % 4) * BF192.LIMBS;
                    int dst = (i * 8 + j) * BF192.LIMBS;
                    // st_dash_deg2 = state_conj * y
                    BF192.mul(stDashDeg2, dst, stateConj, conjIndex, y, yIndex);
                    // st_dash_deg1 = state_conj * y_tag + state_conj_tag * y
                    BF192.mul(tmp, 0, stateConj, conjIndex, yTag, yIndex);
                    BF192.mul(tmp2, 0, stateConjTag, conjIndex, y, yIndex);
                    BF192.add(stDashDeg1, dst, tmp, 0, tmp2, 0);
                    // st_dash_deg0 = state_conj_tag * y_tag
                    BF192.mul(stDashDeg0, dst, stateConjTag, conjIndex, yTag, yIndex);
                }
            }

            // k_0 = state_to_bytes(k[(2r+1)*Nstbits..])
            // Note: upstream signature is (k_0_deg1, k_0_deg0, k, k_tag) — deg1 is the
            // byte_combine_bits output (value), deg0 is the byte_combine output (tag).
            FaestProofPrimitives.stateToBytesProver192(k0Deg1, k0Deg0,
                sliceBits(k, (2 * r + 1) * Nstbits, Nstbits),
                sliceLongs(kTag, (2 * r + 1) * Nstbits * BF192.LIMBS, Nstbits * BF192.LIMBS),
                Nst);
            // k_1 = k_0^2 — squaring of the byte-level deg-0/1 elements
            for (int b = 0; b < Nstbytes; b++)
            {
                int off = b * BF192.LIMBS;
                BF192.mul(k1Deg0, off, k0Deg0, off, k0Deg0, off);
                java.util.Arrays.fill(k1Deg1, off, off + BF192.LIMBS, 0L);
                BF192.mul(k1Deg2, off, k0Deg1, off, k0Deg1, off);
            }

            // Zero the st_b accumulators.
            for (int b = 0; b < 2; b++)
            {
                java.util.Arrays.fill(stBDeg0[b], 0, Nstbytes * BF192.LIMBS, 0L);
                java.util.Arrays.fill(stBDeg1[b], 0, Nstbytes * BF192.LIMBS, 0L);
                java.util.Arrays.fill(stBDeg2[b], 0, Nstbytes * BF192.LIMBS, 0L);
            }
            java.util.Arrays.fill(dummyKey, 0L);

            for (int b = 0; b < 2; b++)
            {
                FaestProofPrimitives.sboxAffineProver192(
                    stBDeg0[b], stBDeg1[b], stBDeg2[b],
                    stDashDeg0, stDashDeg1, stDashDeg2, b == 1, Nst);
                FaestProofPrimitives.shiftRowsProver192(
                    stBDeg0Tmp[b], stBDeg1Tmp[b], stBDeg2Tmp[b],
                    stBDeg0[b], stBDeg1[b], stBDeg2[b], Nst);
                System.arraycopy(stBDeg0Tmp[b], 0, stBDeg0[b], 0, Nstbytes * BF192.LIMBS);
                System.arraycopy(stBDeg1Tmp[b], 0, stBDeg1[b], 0, Nstbytes * BF192.LIMBS);
                System.arraycopy(stBDeg2Tmp[b], 0, stBDeg2[b], 0, Nstbytes * BF192.LIMBS);
                FaestProofPrimitives.mixColumnsProver192(
                    stBDeg0[b], stBDeg1[b], stBDeg2[b],
                    stBDeg0Tmp[b], stBDeg1Tmp[b], stBDeg2Tmp[b], b == 1, Nst);
                if (b == 0)
                {
                    FaestProofPrimitives.addRoundKeyBytesProver192(
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        dummyKey, k0Deg0, k0Deg1, Nst);
                }
                else
                {
                    FaestProofPrimitives.addRoundKeyBytesProver192(
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        k1Deg0, k1Deg1, k1Deg2, Nst);
                }
            }

            // s_tilde
            if (r == R / 2 - 1)
            {
                FaestProofPrimitives.addRoundKeyProver192(sTilde, sTildeTag,
                    owfOut, owfOutTag,
                    sliceBits(k, R * Nstbits, Nstbits),
                    sliceLongs(kTag, R * Nstbits * BF192.LIMBS, Nstbits * BF192.LIMBS),
                    Nst);
            }
            else
            {
                int srcOff = Nstbits / 2 + (3 * Nstbits / 2) * r;
                System.arraycopy(w, srcOff, sTilde, 0, Nstbits);
                System.arraycopy(wTag, srcOff * BF192.LIMBS, sTildeTag, 0, Nstbits * BF192.LIMBS);
            }

            FaestProofPrimitives.inverseShiftRowsProver192(sDashDash, sDashDashTag,
                sTilde, sTildeTag, Nst);
            FaestProofPrimitives.inverseAffineProver192(s, sTag, sDashDash, sDashDashTag, Nst);

            for (int byteI = 0; byteI < Nstbytes; byteI++)
            {
                BF192.byteCombineBits(sDeg1, 0, s, 8 * byteI);
                BF192.byteCombine(sDeg0, 0, sTag, 8 * byteI * BF192.LIMBS);
                BF192.byteCombineBitsSq(sSqDeg1, 0, s, 8 * byteI);
                BF192.byteCombineSq(sSqDeg0, 0, sTag, 8 * byteI * BF192.LIMBS);

                int dst0 = ((3 * r + 1) * Nstbytes + 2 * byteI) * BF192.LIMBS;
                int dst1 = ((3 * r + 1) * Nstbytes + 2 * byteI + 1) * BF192.LIMBS;
                int stOff = byteI * BF192.LIMBS;

                // z_deg0[2byte_i]   = s_sq_deg0 * st_b_deg0[0]
                BF192.mul(zDeg0, dst0, sSqDeg0, 0, stBDeg0[0], stOff);
                // z_deg1[2byte_i]   = s_sq_deg0 * st_b_deg1[0] + s_sq_deg1 * st_b_deg0[0]
                BF192.mul(tmp, 0, sSqDeg0, 0, stBDeg1[0], stOff);
                BF192.mul(tmp2, 0, sSqDeg1, 0, stBDeg0[0], stOff);
                BF192.add(zDeg1, dst0, tmp, 0, tmp2, 0);
                // z_deg2[2byte_i]   = s_sq_deg0 * st_b_deg2[0] + s_sq_deg1 * st_b_deg1[0] + s_deg0
                BF192.mul(tmp, 0, sSqDeg0, 0, stBDeg2[0], stOff);
                BF192.mul(tmp2, 0, sSqDeg1, 0, stBDeg1[0], stOff);
                BF192.add(zDeg2, dst0, tmp, 0, tmp2, 0);
                BF192.addInPlace(zDeg2, dst0, sDeg0, 0);

                // z_deg0[2byte_i+1] = s_deg0 * st_b_deg0[1]
                BF192.mul(zDeg0, dst1, sDeg0, 0, stBDeg0[1], stOff);
                // z_deg1[2byte_i+1] = s_deg0 * st_b_deg1[1] + s_deg1 * st_b_deg0[1] + st_b_deg0[0]
                BF192.mul(tmp, 0, sDeg0, 0, stBDeg1[1], stOff);
                BF192.mul(tmp2, 0, sDeg1, 0, stBDeg0[1], stOff);
                BF192.add(zDeg1, dst1, tmp, 0, tmp2, 0);
                BF192.addInPlace(zDeg1, dst1, stBDeg0[0], stOff);
                // z_deg2[2byte_i+1] = s_deg0 * st_b_deg2[1] + s_deg1 * st_b_deg1[1] + st_b_deg1[0]
                BF192.mul(tmp, 0, sDeg0, 0, stBDeg2[1], stOff);
                BF192.mul(tmp2, 0, sDeg1, 0, stBDeg1[1], stOff);
                BF192.add(zDeg2, dst1, tmp, 0, tmp2, 0);
                BF192.addInPlace(zDeg2, dst1, stBDeg1[0], stOff);
            }

            if (r != R / 2 - 1)
            {
                FaestProofPrimitives.bitwiseMixColumnProver192(tmpState, tmpStateTag,
                    sTilde, sTildeTag, Nst);
                FaestProofPrimitives.addRoundKeyProver192(stateBits, stateBitsTag,
                    tmpState, tmpStateTag,
                    sliceBits(k, (2 * r + 2) * Nstbits, Nstbits),
                    sliceLongs(kTag, (2 * r + 2) * Nstbits * BF192.LIMBS, Nstbits * BF192.LIMBS),
                    Nst);
            }
        }
    }

    // ====== enc_constraints verifier (192) ======
    // faest_aes.c:3864.

    static void encConstraintsVerifier192(long[] zKey,
                                          long[] owfInKey, long[] owfOutKey,
                                          long[] wKey, long[] rkeysKey, long[] delta,
                                          FaestParameters params)
    {
        int Nst = params.getNst();
        int Nstbits = 32 * Nst;
        int R = params.getR();
        int Nstbytes = Nstbits / 8;

        long[] stateBitsKey = new long[Nstbits * BF192.LIMBS];
        FaestProofPrimitives.addRoundKeyVerifier192(stateBitsKey, owfInKey, rkeysKey, Nst);

        long[] stateConjKey = new long[8 * Nstbytes * BF192.LIMBS];
        long[] stDashKey = new long[8 * Nstbytes * BF192.LIMBS];

        long[] yKey = new long[4 * BF192.LIMBS];

        long[] k0Key = new long[Nstbytes * BF192.LIMBS];
        long[] k1Key = new long[Nstbytes * BF192.LIMBS];

        long[][] stBKey = new long[2][Nstbytes * BF192.LIMBS];
        long[][] stBTmpKey = new long[2][Nstbytes * BF192.LIMBS];

        long[] sTildeKey = new long[Nstbits * BF192.LIMBS];
        long[] sDashDashKey = new long[Nstbits * BF192.LIMBS];
        long[] sStateKey = new long[Nstbits * BF192.LIMBS];

        long[] sKey = new long[BF192.LIMBS];
        long[] sSqKey = new long[BF192.LIMBS];
        long[] tmp = new long[BF192.LIMBS];
        long[] d2 = new long[BF192.LIMBS];
        BF192.mul(d2, 0, delta, 0, delta, 0);
        long[] invNormT = new long[BF192.LIMBS];

        long[] tmpStateKey = new long[Nstbits * BF192.LIMBS];

        for (int r = 0; r < R / 2; r++)
        {
            FaestProofPrimitives.f256F2ConjugatesLambda_192(stateConjKey, stateBitsKey, Nst);

            int normKeysOff = ((3 * Nstbits * r) / 2) * BF192.LIMBS;

            for (int i = 0; i < Nstbytes; i++)
            {
                FaestProofPrimitives.invNormToConjugatesVerifier192(yKey,
                    sliceLongs(wKey, normKeysOff + 4 * i * BF192.LIMBS, 4 * BF192.LIMBS));

                int zOff = (3 * r * Nstbytes + i) * BF192.LIMBS;
                FaestProofPrimitives.invNormConstraintsVerifier192(zKey, zOff,
                    sliceLongs(stateConjKey, 8 * i * BF192.LIMBS, 8 * BF192.LIMBS),
                    yKey, d2, invNormT);

                for (int j = 0; j < 8; j++)
                {
                    int conjIndex = (i * 8 + ((j + 4) % 8)) * BF192.LIMBS;
                    int yIndex = (j % 4) * BF192.LIMBS;
                    int dst = (i * 8 + j) * BF192.LIMBS;
                    BF192.mul(stDashKey, dst, stateConjKey, conjIndex, yKey, yIndex);
                }
            }

            FaestProofPrimitives.stateToBytesVerifier192(k0Key,
                sliceLongs(rkeysKey, (2 * r + 1) * Nstbits * BF192.LIMBS, Nstbits * BF192.LIMBS),
                Nst);
            for (int b = 0; b < Nstbytes; b++)
            {
                int off = b * BF192.LIMBS;
                BF192.mul(k1Key, off, k0Key, off, k0Key, off);
            }

            for (int b = 0; b < 2; b++)
            {
                java.util.Arrays.fill(stBKey[b], 0, Nstbytes * BF192.LIMBS, 0L);
                java.util.Arrays.fill(stBTmpKey[b], 0, Nstbytes * BF192.LIMBS, 0L);
            }

            for (int b = 0; b < 2; b++)
            {
                FaestProofPrimitives.sboxAffineVerifier192(stBKey[b], stDashKey, delta, b == 1, Nst);
                FaestProofPrimitives.shiftRowsVerifier192(stBTmpKey[b], stBKey[b], Nst);
                System.arraycopy(stBTmpKey[b], 0, stBKey[b], 0, Nstbytes * BF192.LIMBS);
                FaestProofPrimitives.mixColumnsVerifier192(stBTmpKey[b], stBKey[b], b == 1, Nst);
                System.arraycopy(stBTmpKey[b], 0, stBKey[b], 0, Nstbytes * BF192.LIMBS);
                if (b == 0)
                {
                    FaestProofPrimitives.addRoundKeyBytesVerifier192(
                        stBKey[b], stBKey[b], k0Key, delta, true, Nst);
                }
                else
                {
                    FaestProofPrimitives.addRoundKeyBytesVerifier192(
                        stBKey[b], stBKey[b], k1Key, delta, false, Nst);
                }
            }

            if (r == R / 2 - 1)
            {
                FaestProofPrimitives.addRoundKeyVerifier192(sTildeKey, owfOutKey,
                    sliceLongs(rkeysKey, R * Nstbits * BF192.LIMBS, Nstbits * BF192.LIMBS), Nst);
            }
            else
            {
                int srcOff = (Nstbits / 2 + (3 * Nstbits / 2) * r) * BF192.LIMBS;
                System.arraycopy(wKey, srcOff, sTildeKey, 0, Nstbits * BF192.LIMBS);
            }

            FaestProofPrimitives.inverseShiftRowsVerifier192(sDashDashKey, sTildeKey, Nst);
            FaestProofPrimitives.inverseAffineVerifier192(sStateKey, sDashDashKey, delta, Nst);

            for (int byteI = 0; byteI < Nstbytes; byteI++)
            {
                BF192.byteCombine(sKey, 0, sStateKey, 8 * byteI * BF192.LIMBS);
                BF192.byteCombineSq(sSqKey, 0, sStateKey, 8 * byteI * BF192.LIMBS);

                int dst0 = ((3 * r + 1) * Nstbytes + 2 * byteI) * BF192.LIMBS;
                int dst1 = ((3 * r + 1) * Nstbytes + 2 * byteI + 1) * BF192.LIMBS;
                int stOff = byteI * BF192.LIMBS;

                // z_key[2byte_i] = s_sq_key * st_b_key[0] + delta^2 * s_key
                BF192.mul(zKey, dst0, sSqKey, 0, stBKey[0], stOff);
                BF192.mul(tmp, 0, d2, 0, sKey, 0);
                BF192.addInPlace(zKey, dst0, tmp, 0);

                // z_key[2byte_i+1] = s_key * st_b_key[1] + delta * st_b_key[0]
                BF192.mul(zKey, dst1, sKey, 0, stBKey[1], stOff);
                BF192.mul(tmp, 0, delta, 0, stBKey[0], stOff);
                BF192.addInPlace(zKey, dst1, tmp, 0);
            }

            if (r != R / 2 - 1)
            {
                FaestProofPrimitives.bitwiseMixColumnVerifier192(tmpStateKey, sTildeKey, Nst);
                FaestProofPrimitives.addRoundKeyVerifier192(stateBitsKey, tmpStateKey,
                    sliceLongs(rkeysKey, (2 * r + 2) * Nstbits * BF192.LIMBS, Nstbits * BF192.LIMBS),
                    Nst);
            }
        }
    }

    // ====== constraints orchestrator (192) ======
    // faest_aes.c:4278 (prover) / faest_aes.c:4692 (verifier).
    //
    // Wires expkey_constraints + enc_constraints into the full FAEST AES constraint
    // polynomial. For FAEST-EM (Even-Mansour), the OWF key is public and round keys
    // are derived by running expand_key on owf_in; expkey_constraints is skipped.

    static void constraintsProver192(long[] zDeg0, long[] zDeg1, long[] zDeg2,
                                     byte[] w, long[] wTag,
                                     byte[] owfIn, byte[] owfOut,
                                     FaestParameters params)
    {
        int lambda = params.getLambda();
        int R = params.getR();
        int Ske = params.getSke();
        int Lke = params.getLke();
        int Lenc = params.getLenc();
        int Senc = params.getSenc();
        int Nk = lambda / 32;
        int Nst = params.getNst();
        int numEncConstraints = 3 * Senc / 2;
        int blocksize = 32 * Nst;
        int beta = (lambda + blocksize - 1) / blocksize;
        boolean isEM = params.isEm();

        // z_deg0[0] = 0; z_deg1[0] = w_tag[0] * w_tag[1]; z_deg2[0] = w_tag[0]*w[1] + w_tag[1]*w[0]
        java.util.Arrays.fill(zDeg0, 0, BF192.LIMBS, 0L);
        BF192.mul(zDeg1, 0, wTag, 0, wTag, BF192.LIMBS);
        long[] t1 = new long[BF192.LIMBS];
        long[] t2 = new long[BF192.LIMBS];
        BF192.mulBit(t1, 0, wTag, 0, w[1]);
        BF192.mulBit(t2, 0, wTag, BF192.LIMBS, w[0]);
        BF192.add(zDeg2, 0, t1, 0, t2, 0);

        byte[] in = new byte[blocksize];
        long[] inTag = new long[blocksize * BF192.LIMBS];
        byte[] out = new byte[beta * blocksize];
        long[] outTag = new long[beta * blocksize * BF192.LIMBS];
        byte[] rkeys = new byte[(R + 1) * blocksize];
        long[] rkeysTag = new long[(R + 1) * blocksize * BF192.LIMBS];

        if (isEM)
        {
            // Derive round keys from owf_in (public).
            byte[] rkBytes = new byte[(R + 1) * 4 * Nk];
            FaestAES.expandKey(rkBytes, owfIn, 0, Nk, Nk, R);
            int idx = 0;
            for (int rr = 0; rr < R + 1; rr++)
            {
                for (int n = 0; n < Nst; n++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        int rk = rkBytes[rr * 4 * Nk + n * 4 + i] & 0xff;
                        for (int j = 0; j < 8; j++)
                        {
                            rkeys[8 * idx + j] = (byte)((rk >>> j) & 1);
                            // rkeys_tag[8*idx + j] = 0
                        }
                        idx++;
                    }
                }
            }
            for (int i = 0; i < blocksize; i++)
            {
                in[i] = w[i];
                System.arraycopy(wTag, i * BF192.LIMBS, inTag, i * BF192.LIMBS, BF192.LIMBS);
            }
            for (int i = 0; i < blocksize; i++)
            {
                out[i] = (byte)((w[i] ^ ((owfOut[i / 8] >>> (i % 8)) & 1)) & 1);
                System.arraycopy(wTag, i * BF192.LIMBS, outTag, i * BF192.LIMBS, BF192.LIMBS);
            }
        }
        else
        {
            // AES: in and out are public.
            for (int i = 0; i < blocksize; i++)
            {
                in[i] = (byte)(((owfIn[i / 8] >>> (i % 8)) & 1) & 1);
            }
            FaestProofPrimitives.constantToVoleProver192(inTag, blocksize);
            for (int i = 0; i < beta * blocksize; i++)
            {
                out[i] = (byte)(((owfOut[i / 8] >>> (i % 8)) & 1) & 1);
            }
            FaestProofPrimitives.constantToVoleProver192(outTag, blocksize);

            long[] zTildeDeg0Tag = new long[2 * Ske * BF192.LIMBS];
            long[] zTildeDeg1Val = new long[2 * Ske * BF192.LIMBS];
            FaestKeyExpansion.expkeyConstraintsProver192(zTildeDeg0Tag, zTildeDeg1Val,
                rkeys, rkeysTag, w, wTag, params);
            // Raise degree: z_deg0[1+i]=0, z_deg1[1+i]=z_tilde_deg0_tag, z_deg2[1+i]=z_tilde_deg1_val
            for (int i = 0; i < 2 * Ske; i++)
            {
                int off = (1 + i) * BF192.LIMBS;
                java.util.Arrays.fill(zDeg0, off, off + BF192.LIMBS, 0L);
                System.arraycopy(zTildeDeg0Tag, i * BF192.LIMBS, zDeg1, off, BF192.LIMBS);
                System.arraycopy(zTildeDeg1Val, i * BF192.LIMBS, zDeg2, off, BF192.LIMBS);
            }
        }

        byte[] wTilde = new byte[Lenc];
        long[] wTildeTag = new long[Lenc * BF192.LIMBS];
        long[] zTildeDeg0 = new long[numEncConstraints * BF192.LIMBS];
        long[] zTildeDeg1 = new long[numEncConstraints * BF192.LIMBS];
        long[] zTildeDeg2 = new long[numEncConstraints * BF192.LIMBS];

        int outOff = 0;
        for (int b = 0; b < beta; b++)
        {
            for (int i = 0; i < Lenc; i++)
            {
                wTilde[i] = w[Lke + b * Lenc + i];
                System.arraycopy(wTag, (Lke + b * Lenc + i) * BF192.LIMBS, wTildeTag,
                    i * BF192.LIMBS, BF192.LIMBS);
            }
            java.util.Arrays.fill(zTildeDeg0, 0L);
            java.util.Arrays.fill(zTildeDeg1, 0L);
            java.util.Arrays.fill(zTildeDeg2, 0L);

            if (b == 1)
            {
                in[0] = (byte)((in[0] ^ 1) & 1);
                // 192 prover differs from 128: only in[] is toggled, inTag stays.
                outOff = blocksize;
            }

            encConstraintsProver192(zTildeDeg0, zTildeDeg1, zTildeDeg2,
                in, inTag,
                sliceBits(out, outOff, blocksize),
                sliceLongs(outTag, outOff * BF192.LIMBS, blocksize * BF192.LIMBS),
                wTilde, wTildeTag, rkeys, rkeysTag, params);

            for (int i = 0; i < numEncConstraints; i++)
            {
                int dst = (1 + 2 * Ske + b * numEncConstraints + i) * BF192.LIMBS;
                int src = i * BF192.LIMBS;
                System.arraycopy(zTildeDeg0, src, zDeg0, dst, BF192.LIMBS);
                System.arraycopy(zTildeDeg1, src, zDeg1, dst, BF192.LIMBS);
                System.arraycopy(zTildeDeg2, src, zDeg2, dst, BF192.LIMBS);
            }
        }
    }

    static void constraintsVerifier192(long[] zKey, long[] wKey,
                                       byte[] owfIn, byte[] owfOut, long[] delta,
                                       FaestParameters params)
    {
        int lambda = params.getLambda();
        int R = params.getR();
        int Lke = params.getLke();
        int Lenc = params.getLenc();
        int Senc = params.getSenc();
        int Ske = params.getSke();
        int Nk = lambda / 32;
        int Nst = params.getNst();
        int numEncConstraints = 3 * Senc / 2;
        int numKsConstraints = 2 * Ske;
        int blocksize = 32 * Nst;
        int beta = (lambda + blocksize - 1) / blocksize;
        boolean isEM = params.isEm();

        // z_key[0] = delta * w_key[0] * w_key[1]
        long[] t = new long[BF192.LIMBS];
        BF192.mul(t, 0, wKey, 0, wKey, BF192.LIMBS);
        BF192.mul(zKey, 0, delta, 0, t, 0);

        long[] rkeysKey = new long[(R + 1) * blocksize * BF192.LIMBS];
        long[] inKey = new long[blocksize * BF192.LIMBS];
        long[] outKey = new long[beta * blocksize * BF192.LIMBS];

        if (isEM)
        {
            byte[] rkBytes = new byte[(R + 1) * 4 * Nk];
            FaestAES.expandKey(rkBytes, owfIn, 0, Nk, Nk, R);
            int idx = 0;
            for (int rr = 0; rr < R + 1; rr++)
            {
                for (int n = 0; n < Nst; n++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        int rk = rkBytes[rr * 4 * Nk + n * 4 + i] & 0xff;
                        for (int j = 0; j < 8; j++)
                        {
                            BF192.mulBit(rkeysKey, (8 * idx + j) * BF192.LIMBS,
                                delta, 0, (rk >>> j) & 1);
                        }
                        idx++;
                    }
                }
            }
            for (int i = 0; i < blocksize; i++)
            {
                System.arraycopy(wKey, i * BF192.LIMBS, inKey, i * BF192.LIMBS, BF192.LIMBS);
                int bit = (owfOut[i / 8] >>> (i % 8)) & 1;
                long[] bd = new long[BF192.LIMBS];
                BF192.mulBit(bd, 0, delta, 0, bit);
                BF192.add(outKey, i * BF192.LIMBS, wKey, i * BF192.LIMBS, bd, 0);
            }
        }
        else
        {
            FaestProofPrimitives.constantToVoleVerifier192(inKey, owfIn, delta, blocksize);
            FaestProofPrimitives.constantToVoleVerifier192(outKey, owfOut, delta, beta * blocksize);

            long[] zTildeKey = new long[2 * Ske * BF192.LIMBS];
            FaestKeyExpansion.expkeyConstraintsVerifier192(zTildeKey, rkeysKey, wKey, delta, params);
            for (int i = 0; i < numKsConstraints; i++)
            {
                BF192.mul(zKey, (1 + i) * BF192.LIMBS, delta, 0, zTildeKey, i * BF192.LIMBS);
            }
        }

        long[] wTildeKey = new long[Lenc * BF192.LIMBS];
        long[] zTildeEncKey = new long[numEncConstraints * BF192.LIMBS];
        int outOff = 0;
        for (int b = 0; b < beta; b++)
        {
            for (int i = 0; i < Lenc; i++)
            {
                System.arraycopy(wKey, (Lke + b * Lenc + i) * BF192.LIMBS, wTildeKey,
                    i * BF192.LIMBS, BF192.LIMBS);
            }
            java.util.Arrays.fill(zTildeEncKey, 0L);
            if (b == 1)
            {
                BF192.addInPlace(inKey, 0, delta, 0);
                outOff = blocksize;
            }
            encConstraintsVerifier192(zTildeEncKey, inKey,
                sliceLongs(outKey, outOff * BF192.LIMBS, blocksize * BF192.LIMBS),
                wTildeKey, rkeysKey, delta, params);
            for (int i = 0; i < numEncConstraints; i++)
            {
                int dst = (1 + numKsConstraints + b * numEncConstraints + i) * BF192.LIMBS;
                int src = i * BF192.LIMBS;
                System.arraycopy(zTildeEncKey, src, zKey, dst, BF192.LIMBS);
            }
        }
    }


    // ====== enc_constraints prover (256) ======
    // faest_aes.c:3167.
    //
    // For each of R/2 "double rounds" emit:
    //  - per-byte inv_norm_constraint (3 deg-2 constraints per byte at offset 3*r*Nstbytes)
    //  - per-byte SBox/MixColumns/round-key constraint pair (2 deg-2 constraints per byte at offset (3*r+1)*Nstbytes)
    // Total z_deg* output size: 3 * Senc / 2 entries where Senc = R * Nstbits.

    static void encConstraintsProver256(long[] zDeg0, long[] zDeg1, long[] zDeg2,
                                        byte[] owfIn, long[] owfInTag,
                                        byte[] owfOut, long[] owfOutTag,
                                        byte[] w, long[] wTag,
                                        byte[] k, long[] kTag,
                                        FaestParameters params)
    {
        int Nst = params.getNst();
        int Nstbits = 32 * Nst;
        int R = params.getR();
        int Nstbytes = Nstbits / 8;

        byte[] stateBits = new byte[Nstbits];
        long[] stateBitsTag = new long[Nstbits * BF256.LIMBS];
        FaestProofPrimitives.addRoundKeyProver256(stateBits, stateBitsTag,
            owfIn, owfInTag, k, kTag, Nst);

        long[] stateConj = new long[8 * Nstbytes * BF256.LIMBS];
        long[] stateConjTag = new long[8 * Nstbytes * BF256.LIMBS];
        long[] stDashDeg2 = new long[8 * Nstbytes * BF256.LIMBS];
        long[] stDashDeg1 = new long[8 * Nstbytes * BF256.LIMBS];
        long[] stDashDeg0 = new long[8 * Nstbytes * BF256.LIMBS];

        long[] y = new long[4 * BF256.LIMBS];
        long[] yTag = new long[4 * BF256.LIMBS];

        long[] k0Deg0 = new long[Nstbytes * BF256.LIMBS];
        long[] k0Deg1 = new long[Nstbytes * BF256.LIMBS];
        long[] k1Deg0 = new long[Nstbytes * BF256.LIMBS];
        long[] k1Deg1 = new long[Nstbytes * BF256.LIMBS];
        long[] k1Deg2 = new long[Nstbytes * BF256.LIMBS];

        long[][] stBDeg0 = new long[2][Nstbytes * BF256.LIMBS];
        long[][] stBDeg1 = new long[2][Nstbytes * BF256.LIMBS];
        long[][] stBDeg2 = new long[2][Nstbytes * BF256.LIMBS];
        long[][] stBDeg0Tmp = new long[2][Nstbytes * BF256.LIMBS];
        long[][] stBDeg1Tmp = new long[2][Nstbytes * BF256.LIMBS];
        long[][] stBDeg2Tmp = new long[2][Nstbytes * BF256.LIMBS];
        long[] dummyKey = new long[Nstbytes * BF256.LIMBS];

        byte[] sTilde = new byte[Nstbits];
        long[] sTildeTag = new long[Nstbits * BF256.LIMBS];
        byte[] sDashDash = new byte[Nstbits];
        long[] sDashDashTag = new long[Nstbits * BF256.LIMBS];
        byte[] s = new byte[Nstbits];
        long[] sTag = new long[Nstbits * BF256.LIMBS];

        long[] sDeg0 = new long[BF256.LIMBS];
        long[] sDeg1 = new long[BF256.LIMBS];
        long[] sSqDeg0 = new long[BF256.LIMBS];
        long[] sSqDeg1 = new long[BF256.LIMBS];
        long[] tmp = new long[BF256.LIMBS];
        long[] tmp2 = new long[BF256.LIMBS];
        long[] invNormT1 = new long[BF256.LIMBS];
        long[] invNormT2 = new long[BF256.LIMBS];

        byte[] tmpState = new byte[Nstbits];
        long[] tmpStateTag = new long[Nstbits * BF256.LIMBS];

        for (int r = 0; r < R / 2; r++)
        {
            FaestProofPrimitives.f256F2Conjugates1_256(stateConj, stateBits, Nst);
            FaestProofPrimitives.f256F2ConjugatesLambda_256(stateConjTag, stateBitsTag, Nst);

            int normsOff = (3 * Nstbits * r) / 2;
            int normTagsOff = ((3 * Nstbits * r) / 2) * BF256.LIMBS;

            for (int i = 0; i < Nstbytes; i++)
            {
                FaestProofPrimitives.invNormToConjugatesProver256(y, yTag,
                    sliceBits(w, normsOff + 4 * i, 4),
                    sliceLongs(wTag, normTagsOff + 4 * i * BF256.LIMBS, 4 * BF256.LIMBS));

                int zOff = (3 * r * Nstbytes + i) * BF256.LIMBS;
                FaestProofPrimitives.invNormConstraintsProver256(
                    zDeg0, zOff, zDeg1, zOff, zDeg2, zOff,
                    sliceLongs(stateConj, 8 * i * BF256.LIMBS, 8 * BF256.LIMBS),
                    sliceLongs(stateConjTag, 8 * i * BF256.LIMBS, 8 * BF256.LIMBS),
                    y, yTag, invNormT1, invNormT2);

                for (int j = 0; j < 8; j++)
                {
                    int conjIndex = (i * 8 + ((j + 4) % 8)) * BF256.LIMBS;
                    int yIndex = (j % 4) * BF256.LIMBS;
                    int dst = (i * 8 + j) * BF256.LIMBS;
                    // st_dash_deg2 = state_conj * y
                    BF256.mul(stDashDeg2, dst, stateConj, conjIndex, y, yIndex);
                    // st_dash_deg1 = state_conj * y_tag + state_conj_tag * y
                    BF256.mul(tmp, 0, stateConj, conjIndex, yTag, yIndex);
                    BF256.mul(tmp2, 0, stateConjTag, conjIndex, y, yIndex);
                    BF256.add(stDashDeg1, dst, tmp, 0, tmp2, 0);
                    // st_dash_deg0 = state_conj_tag * y_tag
                    BF256.mul(stDashDeg0, dst, stateConjTag, conjIndex, yTag, yIndex);
                }
            }

            // k_0 = state_to_bytes(k[(2r+1)*Nstbits..])
            // Note: upstream signature is (k_0_deg1, k_0_deg0, k, k_tag) — deg1 is the
            // byte_combine_bits output (value), deg0 is the byte_combine output (tag).
            FaestProofPrimitives.stateToBytesProver256(k0Deg1, k0Deg0,
                sliceBits(k, (2 * r + 1) * Nstbits, Nstbits),
                sliceLongs(kTag, (2 * r + 1) * Nstbits * BF256.LIMBS, Nstbits * BF256.LIMBS),
                Nst);
            // k_1 = k_0^2 — squaring of the byte-level deg-0/1 elements
            for (int b = 0; b < Nstbytes; b++)
            {
                int off = b * BF256.LIMBS;
                BF256.mul(k1Deg0, off, k0Deg0, off, k0Deg0, off);
                java.util.Arrays.fill(k1Deg1, off, off + BF256.LIMBS, 0L);
                BF256.mul(k1Deg2, off, k0Deg1, off, k0Deg1, off);
            }

            // Zero the st_b accumulators.
            for (int b = 0; b < 2; b++)
            {
                java.util.Arrays.fill(stBDeg0[b], 0, Nstbytes * BF256.LIMBS, 0L);
                java.util.Arrays.fill(stBDeg1[b], 0, Nstbytes * BF256.LIMBS, 0L);
                java.util.Arrays.fill(stBDeg2[b], 0, Nstbytes * BF256.LIMBS, 0L);
            }
            java.util.Arrays.fill(dummyKey, 0L);

            for (int b = 0; b < 2; b++)
            {
                FaestProofPrimitives.sboxAffineProver256(
                    stBDeg0[b], stBDeg1[b], stBDeg2[b],
                    stDashDeg0, stDashDeg1, stDashDeg2, b == 1, Nst);
                FaestProofPrimitives.shiftRowsProver256(
                    stBDeg0Tmp[b], stBDeg1Tmp[b], stBDeg2Tmp[b],
                    stBDeg0[b], stBDeg1[b], stBDeg2[b], Nst);
                System.arraycopy(stBDeg0Tmp[b], 0, stBDeg0[b], 0, Nstbytes * BF256.LIMBS);
                System.arraycopy(stBDeg1Tmp[b], 0, stBDeg1[b], 0, Nstbytes * BF256.LIMBS);
                System.arraycopy(stBDeg2Tmp[b], 0, stBDeg2[b], 0, Nstbytes * BF256.LIMBS);
                FaestProofPrimitives.mixColumnsProver256(
                    stBDeg0[b], stBDeg1[b], stBDeg2[b],
                    stBDeg0Tmp[b], stBDeg1Tmp[b], stBDeg2Tmp[b], b == 1, Nst);
                if (b == 0)
                {
                    FaestProofPrimitives.addRoundKeyBytesProver256(
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        dummyKey, k0Deg0, k0Deg1, Nst);
                }
                else
                {
                    FaestProofPrimitives.addRoundKeyBytesProver256(
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        stBDeg0[b], stBDeg1[b], stBDeg2[b],
                        k1Deg0, k1Deg1, k1Deg2, Nst);
                }
            }

            // s_tilde
            if (r == R / 2 - 1)
            {
                FaestProofPrimitives.addRoundKeyProver256(sTilde, sTildeTag,
                    owfOut, owfOutTag,
                    sliceBits(k, R * Nstbits, Nstbits),
                    sliceLongs(kTag, R * Nstbits * BF256.LIMBS, Nstbits * BF256.LIMBS),
                    Nst);
            }
            else
            {
                int srcOff = Nstbits / 2 + (3 * Nstbits / 2) * r;
                System.arraycopy(w, srcOff, sTilde, 0, Nstbits);
                System.arraycopy(wTag, srcOff * BF256.LIMBS, sTildeTag, 0, Nstbits * BF256.LIMBS);
            }

            FaestProofPrimitives.inverseShiftRowsProver256(sDashDash, sDashDashTag,
                sTilde, sTildeTag, Nst);
            FaestProofPrimitives.inverseAffineProver256(s, sTag, sDashDash, sDashDashTag, Nst);

            for (int byteI = 0; byteI < Nstbytes; byteI++)
            {
                BF256.byteCombineBits(sDeg1, 0, s, 8 * byteI);
                BF256.byteCombine(sDeg0, 0, sTag, 8 * byteI * BF256.LIMBS);
                BF256.byteCombineBitsSq(sSqDeg1, 0, s, 8 * byteI);
                BF256.byteCombineSq(sSqDeg0, 0, sTag, 8 * byteI * BF256.LIMBS);

                int dst0 = ((3 * r + 1) * Nstbytes + 2 * byteI) * BF256.LIMBS;
                int dst1 = ((3 * r + 1) * Nstbytes + 2 * byteI + 1) * BF256.LIMBS;
                int stOff = byteI * BF256.LIMBS;

                // z_deg0[2byte_i]   = s_sq_deg0 * st_b_deg0[0]
                BF256.mul(zDeg0, dst0, sSqDeg0, 0, stBDeg0[0], stOff);
                // z_deg1[2byte_i]   = s_sq_deg0 * st_b_deg1[0] + s_sq_deg1 * st_b_deg0[0]
                BF256.mul(tmp, 0, sSqDeg0, 0, stBDeg1[0], stOff);
                BF256.mul(tmp2, 0, sSqDeg1, 0, stBDeg0[0], stOff);
                BF256.add(zDeg1, dst0, tmp, 0, tmp2, 0);
                // z_deg2[2byte_i]   = s_sq_deg0 * st_b_deg2[0] + s_sq_deg1 * st_b_deg1[0] + s_deg0
                BF256.mul(tmp, 0, sSqDeg0, 0, stBDeg2[0], stOff);
                BF256.mul(tmp2, 0, sSqDeg1, 0, stBDeg1[0], stOff);
                BF256.add(zDeg2, dst0, tmp, 0, tmp2, 0);
                BF256.addInPlace(zDeg2, dst0, sDeg0, 0);

                // z_deg0[2byte_i+1] = s_deg0 * st_b_deg0[1]
                BF256.mul(zDeg0, dst1, sDeg0, 0, stBDeg0[1], stOff);
                // z_deg1[2byte_i+1] = s_deg0 * st_b_deg1[1] + s_deg1 * st_b_deg0[1] + st_b_deg0[0]
                BF256.mul(tmp, 0, sDeg0, 0, stBDeg1[1], stOff);
                BF256.mul(tmp2, 0, sDeg1, 0, stBDeg0[1], stOff);
                BF256.add(zDeg1, dst1, tmp, 0, tmp2, 0);
                BF256.addInPlace(zDeg1, dst1, stBDeg0[0], stOff);
                // z_deg2[2byte_i+1] = s_deg0 * st_b_deg2[1] + s_deg1 * st_b_deg1[1] + st_b_deg1[0]
                BF256.mul(tmp, 0, sDeg0, 0, stBDeg2[1], stOff);
                BF256.mul(tmp2, 0, sDeg1, 0, stBDeg1[1], stOff);
                BF256.add(zDeg2, dst1, tmp, 0, tmp2, 0);
                BF256.addInPlace(zDeg2, dst1, stBDeg1[0], stOff);
            }

            if (r != R / 2 - 1)
            {
                FaestProofPrimitives.bitwiseMixColumnProver256(tmpState, tmpStateTag,
                    sTilde, sTildeTag, Nst);
                FaestProofPrimitives.addRoundKeyProver256(stateBits, stateBitsTag,
                    tmpState, tmpStateTag,
                    sliceBits(k, (2 * r + 2) * Nstbits, Nstbits),
                    sliceLongs(kTag, (2 * r + 2) * Nstbits * BF256.LIMBS, Nstbits * BF256.LIMBS),
                    Nst);
            }
        }
    }

    // ====== enc_constraints verifier (256) ======
    // faest_aes.c:3864.

    static void encConstraintsVerifier256(long[] zKey,
                                          long[] owfInKey, long[] owfOutKey,
                                          long[] wKey, long[] rkeysKey, long[] delta,
                                          FaestParameters params)
    {
        int Nst = params.getNst();
        int Nstbits = 32 * Nst;
        int R = params.getR();
        int Nstbytes = Nstbits / 8;

        long[] stateBitsKey = new long[Nstbits * BF256.LIMBS];
        FaestProofPrimitives.addRoundKeyVerifier256(stateBitsKey, owfInKey, rkeysKey, Nst);

        long[] stateConjKey = new long[8 * Nstbytes * BF256.LIMBS];
        long[] stDashKey = new long[8 * Nstbytes * BF256.LIMBS];

        long[] yKey = new long[4 * BF256.LIMBS];

        long[] k0Key = new long[Nstbytes * BF256.LIMBS];
        long[] k1Key = new long[Nstbytes * BF256.LIMBS];

        long[][] stBKey = new long[2][Nstbytes * BF256.LIMBS];
        long[][] stBTmpKey = new long[2][Nstbytes * BF256.LIMBS];

        long[] sTildeKey = new long[Nstbits * BF256.LIMBS];
        long[] sDashDashKey = new long[Nstbits * BF256.LIMBS];
        long[] sStateKey = new long[Nstbits * BF256.LIMBS];

        long[] sKey = new long[BF256.LIMBS];
        long[] sSqKey = new long[BF256.LIMBS];
        long[] tmp = new long[BF256.LIMBS];
        long[] d2 = new long[BF256.LIMBS];
        BF256.mul(d2, 0, delta, 0, delta, 0);
        long[] invNormT = new long[BF256.LIMBS];

        long[] tmpStateKey = new long[Nstbits * BF256.LIMBS];

        for (int r = 0; r < R / 2; r++)
        {
            FaestProofPrimitives.f256F2ConjugatesLambda_256(stateConjKey, stateBitsKey, Nst);

            int normKeysOff = ((3 * Nstbits * r) / 2) * BF256.LIMBS;

            for (int i = 0; i < Nstbytes; i++)
            {
                FaestProofPrimitives.invNormToConjugatesVerifier256(yKey,
                    sliceLongs(wKey, normKeysOff + 4 * i * BF256.LIMBS, 4 * BF256.LIMBS));

                int zOff = (3 * r * Nstbytes + i) * BF256.LIMBS;
                FaestProofPrimitives.invNormConstraintsVerifier256(zKey, zOff,
                    sliceLongs(stateConjKey, 8 * i * BF256.LIMBS, 8 * BF256.LIMBS),
                    yKey, d2, invNormT);

                for (int j = 0; j < 8; j++)
                {
                    int conjIndex = (i * 8 + ((j + 4) % 8)) * BF256.LIMBS;
                    int yIndex = (j % 4) * BF256.LIMBS;
                    int dst = (i * 8 + j) * BF256.LIMBS;
                    BF256.mul(stDashKey, dst, stateConjKey, conjIndex, yKey, yIndex);
                }
            }

            FaestProofPrimitives.stateToBytesVerifier256(k0Key,
                sliceLongs(rkeysKey, (2 * r + 1) * Nstbits * BF256.LIMBS, Nstbits * BF256.LIMBS),
                Nst);
            for (int b = 0; b < Nstbytes; b++)
            {
                int off = b * BF256.LIMBS;
                BF256.mul(k1Key, off, k0Key, off, k0Key, off);
            }

            for (int b = 0; b < 2; b++)
            {
                java.util.Arrays.fill(stBKey[b], 0, Nstbytes * BF256.LIMBS, 0L);
                java.util.Arrays.fill(stBTmpKey[b], 0, Nstbytes * BF256.LIMBS, 0L);
            }

            for (int b = 0; b < 2; b++)
            {
                FaestProofPrimitives.sboxAffineVerifier256(stBKey[b], stDashKey, delta, b == 1, Nst);
                FaestProofPrimitives.shiftRowsVerifier256(stBTmpKey[b], stBKey[b], Nst);
                System.arraycopy(stBTmpKey[b], 0, stBKey[b], 0, Nstbytes * BF256.LIMBS);
                FaestProofPrimitives.mixColumnsVerifier256(stBTmpKey[b], stBKey[b], b == 1, Nst);
                System.arraycopy(stBTmpKey[b], 0, stBKey[b], 0, Nstbytes * BF256.LIMBS);
                if (b == 0)
                {
                    FaestProofPrimitives.addRoundKeyBytesVerifier256(
                        stBKey[b], stBKey[b], k0Key, delta, true, Nst);
                }
                else
                {
                    FaestProofPrimitives.addRoundKeyBytesVerifier256(
                        stBKey[b], stBKey[b], k1Key, delta, false, Nst);
                }
            }

            if (r == R / 2 - 1)
            {
                FaestProofPrimitives.addRoundKeyVerifier256(sTildeKey, owfOutKey,
                    sliceLongs(rkeysKey, R * Nstbits * BF256.LIMBS, Nstbits * BF256.LIMBS), Nst);
            }
            else
            {
                int srcOff = (Nstbits / 2 + (3 * Nstbits / 2) * r) * BF256.LIMBS;
                System.arraycopy(wKey, srcOff, sTildeKey, 0, Nstbits * BF256.LIMBS);
            }

            FaestProofPrimitives.inverseShiftRowsVerifier256(sDashDashKey, sTildeKey, Nst);
            FaestProofPrimitives.inverseAffineVerifier256(sStateKey, sDashDashKey, delta, Nst);

            for (int byteI = 0; byteI < Nstbytes; byteI++)
            {
                BF256.byteCombine(sKey, 0, sStateKey, 8 * byteI * BF256.LIMBS);
                BF256.byteCombineSq(sSqKey, 0, sStateKey, 8 * byteI * BF256.LIMBS);

                int dst0 = ((3 * r + 1) * Nstbytes + 2 * byteI) * BF256.LIMBS;
                int dst1 = ((3 * r + 1) * Nstbytes + 2 * byteI + 1) * BF256.LIMBS;
                int stOff = byteI * BF256.LIMBS;

                // z_key[2byte_i] = s_sq_key * st_b_key[0] + delta^2 * s_key
                BF256.mul(zKey, dst0, sSqKey, 0, stBKey[0], stOff);
                BF256.mul(tmp, 0, d2, 0, sKey, 0);
                BF256.addInPlace(zKey, dst0, tmp, 0);

                // z_key[2byte_i+1] = s_key * st_b_key[1] + delta * st_b_key[0]
                BF256.mul(zKey, dst1, sKey, 0, stBKey[1], stOff);
                BF256.mul(tmp, 0, delta, 0, stBKey[0], stOff);
                BF256.addInPlace(zKey, dst1, tmp, 0);
            }

            if (r != R / 2 - 1)
            {
                FaestProofPrimitives.bitwiseMixColumnVerifier256(tmpStateKey, sTildeKey, Nst);
                FaestProofPrimitives.addRoundKeyVerifier256(stateBitsKey, tmpStateKey,
                    sliceLongs(rkeysKey, (2 * r + 2) * Nstbits * BF256.LIMBS, Nstbits * BF256.LIMBS),
                    Nst);
            }
        }
    }

    // ====== constraints orchestrator (256) ======
    // faest_aes.c:4278 (prover) / faest_aes.c:4692 (verifier).
    //
    // Wires expkey_constraints + enc_constraints into the full FAEST AES constraint
    // polynomial. For FAEST-EM (Even-Mansour), the OWF key is public and round keys
    // are derived by running expand_key on owf_in; expkey_constraints is skipped.

    static void constraintsProver256(long[] zDeg0, long[] zDeg1, long[] zDeg2,
                                     byte[] w, long[] wTag,
                                     byte[] owfIn, byte[] owfOut,
                                     FaestParameters params)
    {
        int lambda = params.getLambda();
        int R = params.getR();
        int Ske = params.getSke();
        int Lke = params.getLke();
        int Lenc = params.getLenc();
        int Senc = params.getSenc();
        int Nk = lambda / 32;
        int Nst = params.getNst();
        int numEncConstraints = 3 * Senc / 2;
        int blocksize = 32 * Nst;
        int beta = (lambda + blocksize - 1) / blocksize;
        boolean isEM = params.isEm();

        // z_deg0[0] = 0; z_deg1[0] = w_tag[0] * w_tag[1]; z_deg2[0] = w_tag[0]*w[1] + w_tag[1]*w[0]
        java.util.Arrays.fill(zDeg0, 0, BF256.LIMBS, 0L);
        BF256.mul(zDeg1, 0, wTag, 0, wTag, BF256.LIMBS);
        long[] t1 = new long[BF256.LIMBS];
        long[] t2 = new long[BF256.LIMBS];
        BF256.mulBit(t1, 0, wTag, 0, w[1]);
        BF256.mulBit(t2, 0, wTag, BF256.LIMBS, w[0]);
        BF256.add(zDeg2, 0, t1, 0, t2, 0);

        byte[] in = new byte[blocksize];
        long[] inTag = new long[blocksize * BF256.LIMBS];
        byte[] out = new byte[beta * blocksize];
        long[] outTag = new long[beta * blocksize * BF256.LIMBS];
        byte[] rkeys = new byte[(R + 1) * blocksize];
        long[] rkeysTag = new long[(R + 1) * blocksize * BF256.LIMBS];

        if (isEM)
        {
            // Derive round keys from owf_in (public).
            byte[] rkBytes = new byte[(R + 1) * 4 * Nk];
            FaestAES.expandKey(rkBytes, owfIn, 0, Nk, Nk, R);
            int idx = 0;
            for (int rr = 0; rr < R + 1; rr++)
            {
                for (int n = 0; n < Nst; n++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        int rk = rkBytes[rr * 4 * Nk + n * 4 + i] & 0xff;
                        for (int j = 0; j < 8; j++)
                        {
                            rkeys[8 * idx + j] = (byte)((rk >>> j) & 1);
                            // rkeys_tag[8*idx + j] = 0
                        }
                        idx++;
                    }
                }
            }
            for (int i = 0; i < blocksize; i++)
            {
                in[i] = w[i];
                System.arraycopy(wTag, i * BF256.LIMBS, inTag, i * BF256.LIMBS, BF256.LIMBS);
            }
            for (int i = 0; i < blocksize; i++)
            {
                out[i] = (byte)((w[i] ^ ((owfOut[i / 8] >>> (i % 8)) & 1)) & 1);
                System.arraycopy(wTag, i * BF256.LIMBS, outTag, i * BF256.LIMBS, BF256.LIMBS);
            }
        }
        else
        {
            // AES: in and out are public.
            for (int i = 0; i < blocksize; i++)
            {
                in[i] = (byte)(((owfIn[i / 8] >>> (i % 8)) & 1) & 1);
            }
            FaestProofPrimitives.constantToVoleProver256(inTag, blocksize);
            for (int i = 0; i < beta * blocksize; i++)
            {
                out[i] = (byte)(((owfOut[i / 8] >>> (i % 8)) & 1) & 1);
            }
            FaestProofPrimitives.constantToVoleProver256(outTag, blocksize);

            long[] zTildeDeg0Tag = new long[2 * Ske * BF256.LIMBS];
            long[] zTildeDeg1Val = new long[2 * Ske * BF256.LIMBS];
            FaestKeyExpansion.expkeyConstraintsProver256(zTildeDeg0Tag, zTildeDeg1Val,
                rkeys, rkeysTag, w, wTag, params);
            // Raise degree: z_deg0[1+i]=0, z_deg1[1+i]=z_tilde_deg0_tag, z_deg2[1+i]=z_tilde_deg1_val
            for (int i = 0; i < 2 * Ske; i++)
            {
                int off = (1 + i) * BF256.LIMBS;
                java.util.Arrays.fill(zDeg0, off, off + BF256.LIMBS, 0L);
                System.arraycopy(zTildeDeg0Tag, i * BF256.LIMBS, zDeg1, off, BF256.LIMBS);
                System.arraycopy(zTildeDeg1Val, i * BF256.LIMBS, zDeg2, off, BF256.LIMBS);
            }
        }

        byte[] wTilde = new byte[Lenc];
        long[] wTildeTag = new long[Lenc * BF256.LIMBS];
        long[] zTildeDeg0 = new long[numEncConstraints * BF256.LIMBS];
        long[] zTildeDeg1 = new long[numEncConstraints * BF256.LIMBS];
        long[] zTildeDeg2 = new long[numEncConstraints * BF256.LIMBS];

        int outOff = 0;
        for (int b = 0; b < beta; b++)
        {
            for (int i = 0; i < Lenc; i++)
            {
                wTilde[i] = w[Lke + b * Lenc + i];
                System.arraycopy(wTag, (Lke + b * Lenc + i) * BF256.LIMBS, wTildeTag,
                    i * BF256.LIMBS, BF256.LIMBS);
            }
            java.util.Arrays.fill(zTildeDeg0, 0L);
            java.util.Arrays.fill(zTildeDeg1, 0L);
            java.util.Arrays.fill(zTildeDeg2, 0L);

            if (b == 1)
            {
                in[0] = (byte)((in[0] ^ 1) & 1);
                // 256 prover differs from 128: only in[] is toggled, inTag stays.
                outOff = blocksize;
            }

            encConstraintsProver256(zTildeDeg0, zTildeDeg1, zTildeDeg2,
                in, inTag,
                sliceBits(out, outOff, blocksize),
                sliceLongs(outTag, outOff * BF256.LIMBS, blocksize * BF256.LIMBS),
                wTilde, wTildeTag, rkeys, rkeysTag, params);

            for (int i = 0; i < numEncConstraints; i++)
            {
                int dst = (1 + 2 * Ske + b * numEncConstraints + i) * BF256.LIMBS;
                int src = i * BF256.LIMBS;
                System.arraycopy(zTildeDeg0, src, zDeg0, dst, BF256.LIMBS);
                System.arraycopy(zTildeDeg1, src, zDeg1, dst, BF256.LIMBS);
                System.arraycopy(zTildeDeg2, src, zDeg2, dst, BF256.LIMBS);
            }
        }
    }

    static void constraintsVerifier256(long[] zKey, long[] wKey,
                                       byte[] owfIn, byte[] owfOut, long[] delta,
                                       FaestParameters params)
    {
        int lambda = params.getLambda();
        int R = params.getR();
        int Lke = params.getLke();
        int Lenc = params.getLenc();
        int Senc = params.getSenc();
        int Ske = params.getSke();
        int Nk = lambda / 32;
        int Nst = params.getNst();
        int numEncConstraints = 3 * Senc / 2;
        int numKsConstraints = 2 * Ske;
        int blocksize = 32 * Nst;
        int beta = (lambda + blocksize - 1) / blocksize;
        boolean isEM = params.isEm();

        // z_key[0] = delta * w_key[0] * w_key[1]
        long[] t = new long[BF256.LIMBS];
        BF256.mul(t, 0, wKey, 0, wKey, BF256.LIMBS);
        BF256.mul(zKey, 0, delta, 0, t, 0);

        long[] rkeysKey = new long[(R + 1) * blocksize * BF256.LIMBS];
        long[] inKey = new long[blocksize * BF256.LIMBS];
        long[] outKey = new long[beta * blocksize * BF256.LIMBS];

        if (isEM)
        {
            byte[] rkBytes = new byte[(R + 1) * 4 * Nk];
            FaestAES.expandKey(rkBytes, owfIn, 0, Nk, Nk, R);
            int idx = 0;
            for (int rr = 0; rr < R + 1; rr++)
            {
                for (int n = 0; n < Nst; n++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        int rk = rkBytes[rr * 4 * Nk + n * 4 + i] & 0xff;
                        for (int j = 0; j < 8; j++)
                        {
                            BF256.mulBit(rkeysKey, (8 * idx + j) * BF256.LIMBS,
                                delta, 0, (rk >>> j) & 1);
                        }
                        idx++;
                    }
                }
            }
            for (int i = 0; i < blocksize; i++)
            {
                System.arraycopy(wKey, i * BF256.LIMBS, inKey, i * BF256.LIMBS, BF256.LIMBS);
                int bit = (owfOut[i / 8] >>> (i % 8)) & 1;
                long[] bd = new long[BF256.LIMBS];
                BF256.mulBit(bd, 0, delta, 0, bit);
                BF256.add(outKey, i * BF256.LIMBS, wKey, i * BF256.LIMBS, bd, 0);
            }
        }
        else
        {
            FaestProofPrimitives.constantToVoleVerifier256(inKey, owfIn, delta, blocksize);
            FaestProofPrimitives.constantToVoleVerifier256(outKey, owfOut, delta, beta * blocksize);

            long[] zTildeKey = new long[2 * Ske * BF256.LIMBS];
            FaestKeyExpansion.expkeyConstraintsVerifier256(zTildeKey, rkeysKey, wKey, delta, params);
            for (int i = 0; i < numKsConstraints; i++)
            {
                BF256.mul(zKey, (1 + i) * BF256.LIMBS, delta, 0, zTildeKey, i * BF256.LIMBS);
            }
        }

        long[] wTildeKey = new long[Lenc * BF256.LIMBS];
        long[] zTildeEncKey = new long[numEncConstraints * BF256.LIMBS];
        int outOff = 0;
        for (int b = 0; b < beta; b++)
        {
            for (int i = 0; i < Lenc; i++)
            {
                System.arraycopy(wKey, (Lke + b * Lenc + i) * BF256.LIMBS, wTildeKey,
                    i * BF256.LIMBS, BF256.LIMBS);
            }
            java.util.Arrays.fill(zTildeEncKey, 0L);
            if (b == 1)
            {
                BF256.addInPlace(inKey, 0, delta, 0);
                outOff = blocksize;
            }
            encConstraintsVerifier256(zTildeEncKey, inKey,
                sliceLongs(outKey, outOff * BF256.LIMBS, blocksize * BF256.LIMBS),
                wTildeKey, rkeysKey, delta, params);
            for (int i = 0; i < numEncConstraints; i++)
            {
                int dst = (1 + numKsConstraints + b * numEncConstraints + i) * BF256.LIMBS;
                int src = i * BF256.LIMBS;
                System.arraycopy(zTildeEncKey, src, zKey, dst, BF256.LIMBS);
            }
        }
    }
}
