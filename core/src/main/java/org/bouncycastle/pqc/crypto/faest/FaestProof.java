package org.bouncycastle.pqc.crypto.faest;

/**
 * Top-level FAEST AES prover and verifier — the QuickSilver-style proof
 * generator that ties VOLE commitments into the constraint accumulator from
 * {@link FaestAESConstraints}.
 * <p>
 * faest-ref source of truth: {@code faest_aes.c} (lines 4992-5375).
 */
final class FaestProof
{
    private FaestProof()
    {
    }

    /**
     * Column-to-row-major reshape of the VOLE matrix V (or Q). Each column
     * {@code V[col]} is a packed bit array of length {@code (ell + 2*lambda + 7) / 8}
     * bytes. The output is an array of {@code ell + 2*lambda} field elements,
     * where the i-th element holds bit {@code i} of every column packed across
     * its {@code lambda} bits.
     */
    static void columnToRowMajorAndShrinkV128(long[] out, byte[][] V, int ell)
    {
        int rows = ell + 2 * 128;
        byte[] rowBytes = new byte[BF128.BYTES];
        for (int row = 0; row < rows; row++)
        {
            java.util.Arrays.fill(rowBytes, (byte)0);
            for (int col = 0; col < 128; col++)
            {
                int bit = (V[col][row >> 3] >>> (row & 7)) & 1;
                rowBytes[col >> 3] |= (byte)(bit << (col & 7));
            }
            BF128.load(out, row * BF128.LIMBS, rowBytes, 0);
        }
    }

    static void columnToRowMajorAndShrinkV192(long[] out, byte[][] V, int ell)
    {
        int rows = ell + 2 * 192;
        byte[] rowBytes = new byte[BF192.BYTES];
        for (int row = 0; row < rows; row++)
        {
            java.util.Arrays.fill(rowBytes, (byte)0);
            for (int col = 0; col < 192; col++)
            {
                int bit = (V[col][row >> 3] >>> (row & 7)) & 1;
                rowBytes[col >> 3] |= (byte)(bit << (col & 7));
            }
            BF192.load(out, row * BF192.LIMBS, rowBytes, 0);
        }
    }

    static void columnToRowMajorAndShrinkV256(long[] out, byte[][] V, int ell)
    {
        int rows = ell + 2 * 256;
        byte[] rowBytes = new byte[BF256.BYTES];
        for (int row = 0; row < rows; row++)
        {
            java.util.Arrays.fill(rowBytes, (byte)0);
            for (int col = 0; col < 256; col++)
            {
                int bit = (V[col][row >> 3] >>> (row & 7)) & 1;
                rowBytes[col >> 3] |= (byte)(bit << (col & 7));
            }
            BF256.load(out, row * BF256.LIMBS, rowBytes, 0);
        }
    }

    // ====== aes_<lambda>_prover ======
    // faest_aes.c:4992 (128) / 5050 (192) / 5107 (256).
    //
    // Outputs three lambda-byte values (a0_tilde, a1_tilde, a2_tilde) that
    // collectively prove the AES (or Rijndael, for EM) constraint polynomial.
    // The challenge {@code chall2} keys the zk_hash universal hash.

    static void aesProver128(byte[] a0Tilde, byte[] a1Tilde, byte[] a2Tilde,
                             byte[] wBits, byte[] uBits, byte[][] V,
                             byte[] owfIn, byte[] owfOut, byte[] chall2,
                             FaestParameters params)
    {
        int lambda = params.getLambda();
        int c = params.getC();
        int ell = params.getEll();

        long[] wTag = new long[(ell + 2 * lambda) * BF128.LIMBS];
        columnToRowMajorAndShrinkV128(wTag, V, ell);

        // bf_u_bits[i] = from_bit(u_bits[i]) for i in 0..2*lambda
        long[] bfUBits = new long[2 * lambda * BF128.LIMBS];
        for (int i = 0; i < 2 * lambda; i++)
        {
            BF128.fromBit(bfUBits, i * BF128.LIMBS, uBits[i]);
        }
        long[] bfUStar0 = new long[BF128.LIMBS]; BF128.sumPoly(bfUStar0, 0, bfUBits, 0);
        long[] bfUStar1 = new long[BF128.LIMBS]; BF128.sumPoly(bfUStar1, 0, bfUBits, lambda * BF128.LIMBS);
        long[] bfVStar0 = new long[BF128.LIMBS]; BF128.sumPoly(bfVStar0, 0, wTag, ell * BF128.LIMBS);
        long[] bfVStar1 = new long[BF128.LIMBS]; BF128.sumPoly(bfVStar1, 0, wTag, (ell + lambda) * BF128.LIMBS);

        long[] z0Tag = new long[c * BF128.LIMBS];
        long[] z1Val = new long[c * BF128.LIMBS];
        long[] z2Gamma = new long[c * BF128.LIMBS];
        FaestAESConstraints.constraintsProver128(z0Tag, z1Val, z2Gamma,
            wBits, wTag, owfIn, owfOut, params);

        UniversalHashing.ZkHash128 a0Ctx = new UniversalHashing.ZkHash128(chall2, 0);
        UniversalHashing.ZkHash128 a1Ctx = new UniversalHashing.ZkHash128(chall2, 0);
        UniversalHashing.ZkHash128 a2Ctx = new UniversalHashing.ZkHash128(chall2, 0);
        for (int i = 0; i < c; i++)
        {
            a0Ctx.update(z0Tag, i * BF128.LIMBS);
            a1Ctx.update(z1Val, i * BF128.LIMBS);
            a2Ctx.update(z2Gamma, i * BF128.LIMBS);
        }
        a0Ctx.finalize(a0Tilde, 0, bfVStar0, 0);

        long[] u0v1 = new long[BF128.LIMBS];
        BF128.add(u0v1, 0, bfUStar0, 0, bfVStar1, 0);
        a1Ctx.finalize(a1Tilde, 0, u0v1, 0);

        a2Ctx.finalize(a2Tilde, 0, bfUStar1, 0);
    }

    static void aesProver192(byte[] a0Tilde, byte[] a1Tilde, byte[] a2Tilde,
                             byte[] wBits, byte[] uBits, byte[][] V,
                             byte[] owfIn, byte[] owfOut, byte[] chall2,
                             FaestParameters params)
    {
        int lambda = params.getLambda();
        int c = params.getC();
        int ell = params.getEll();

        long[] wTag = new long[(ell + 2 * lambda) * BF192.LIMBS];
        columnToRowMajorAndShrinkV192(wTag, V, ell);

        long[] bfUBits = new long[2 * lambda * BF192.LIMBS];
        for (int i = 0; i < 2 * lambda; i++)
        {
            BF192.fromBit(bfUBits, i * BF192.LIMBS, uBits[i]);
        }
        long[] bfUStar0 = new long[BF192.LIMBS]; BF192.sumPoly(bfUStar0, 0, bfUBits, 0);
        long[] bfUStar1 = new long[BF192.LIMBS]; BF192.sumPoly(bfUStar1, 0, bfUBits, lambda * BF192.LIMBS);
        long[] bfVStar0 = new long[BF192.LIMBS]; BF192.sumPoly(bfVStar0, 0, wTag, ell * BF192.LIMBS);
        long[] bfVStar1 = new long[BF192.LIMBS]; BF192.sumPoly(bfVStar1, 0, wTag, (ell + lambda) * BF192.LIMBS);

        long[] z0Tag = new long[c * BF192.LIMBS];
        long[] z1Val = new long[c * BF192.LIMBS];
        long[] z2Gamma = new long[c * BF192.LIMBS];
        FaestAESConstraints.constraintsProver192(z0Tag, z1Val, z2Gamma,
            wBits, wTag, owfIn, owfOut, params);

        UniversalHashing.ZkHash192 a0Ctx = new UniversalHashing.ZkHash192(chall2, 0);
        UniversalHashing.ZkHash192 a1Ctx = new UniversalHashing.ZkHash192(chall2, 0);
        UniversalHashing.ZkHash192 a2Ctx = new UniversalHashing.ZkHash192(chall2, 0);
        for (int i = 0; i < c; i++)
        {
            a0Ctx.update(z0Tag, i * BF192.LIMBS);
            a1Ctx.update(z1Val, i * BF192.LIMBS);
            a2Ctx.update(z2Gamma, i * BF192.LIMBS);
        }
        a0Ctx.finalize(a0Tilde, 0, bfVStar0, 0);
        long[] u0v1 = new long[BF192.LIMBS];
        BF192.add(u0v1, 0, bfUStar0, 0, bfVStar1, 0);
        a1Ctx.finalize(a1Tilde, 0, u0v1, 0);
        a2Ctx.finalize(a2Tilde, 0, bfUStar1, 0);
    }

    static void aesProver256(byte[] a0Tilde, byte[] a1Tilde, byte[] a2Tilde,
                             byte[] wBits, byte[] uBits, byte[][] V,
                             byte[] owfIn, byte[] owfOut, byte[] chall2,
                             FaestParameters params)
    {
        int lambda = params.getLambda();
        int c = params.getC();
        int ell = params.getEll();

        long[] wTag = new long[(ell + 2 * lambda) * BF256.LIMBS];
        columnToRowMajorAndShrinkV256(wTag, V, ell);

        long[] bfUBits = new long[2 * lambda * BF256.LIMBS];
        for (int i = 0; i < 2 * lambda; i++)
        {
            BF256.fromBit(bfUBits, i * BF256.LIMBS, uBits[i]);
        }
        long[] bfUStar0 = new long[BF256.LIMBS]; BF256.sumPoly(bfUStar0, 0, bfUBits, 0);
        long[] bfUStar1 = new long[BF256.LIMBS]; BF256.sumPoly(bfUStar1, 0, bfUBits, lambda * BF256.LIMBS);
        long[] bfVStar0 = new long[BF256.LIMBS]; BF256.sumPoly(bfVStar0, 0, wTag, ell * BF256.LIMBS);
        long[] bfVStar1 = new long[BF256.LIMBS]; BF256.sumPoly(bfVStar1, 0, wTag, (ell + lambda) * BF256.LIMBS);

        long[] z0Tag = new long[c * BF256.LIMBS];
        long[] z1Val = new long[c * BF256.LIMBS];
        long[] z2Gamma = new long[c * BF256.LIMBS];
        FaestAESConstraints.constraintsProver256(z0Tag, z1Val, z2Gamma,
            wBits, wTag, owfIn, owfOut, params);

        UniversalHashing.ZkHash256 a0Ctx = new UniversalHashing.ZkHash256(chall2, 0);
        UniversalHashing.ZkHash256 a1Ctx = new UniversalHashing.ZkHash256(chall2, 0);
        UniversalHashing.ZkHash256 a2Ctx = new UniversalHashing.ZkHash256(chall2, 0);
        for (int i = 0; i < c; i++)
        {
            a0Ctx.update(z0Tag, i * BF256.LIMBS);
            a1Ctx.update(z1Val, i * BF256.LIMBS);
            a2Ctx.update(z2Gamma, i * BF256.LIMBS);
        }
        a0Ctx.finalize(a0Tilde, 0, bfVStar0, 0);
        long[] u0v1 = new long[BF256.LIMBS];
        BF256.add(u0v1, 0, bfUStar0, 0, bfVStar1, 0);
        a1Ctx.finalize(a1Tilde, 0, u0v1, 0);
        a2Ctx.finalize(a2Tilde, 0, bfUStar1, 0);
    }

    // ====== aes_<lambda>_verifier ======
    // faest_aes.c:5167 (128) / 5225 (192) / 5283 (256).
    //
    // Computes the reconstructed {@code a0_tilde}: combine the constraint
    // polynomial evaluation z2_key with q_star (the universal-hash-finalize term
    // from the verifier-side VOLE projection) and the prover's a1_tilde/a2_tilde
    // adjustments, all evaluated at delta = chall3.

    static void aesVerifier128(byte[] a0TildeOut, byte[] dBits, byte[][] Q,
                               byte[] owfIn, byte[] owfOut,
                               byte[] chall2, byte[] chall3,
                               byte[] a1Tilde, byte[] a2Tilde,
                               FaestParameters params)
    {
        int lambda = params.getLambda();
        int c = params.getC();
        int ell = params.getEll();

        long[] bfDelta = new long[BF128.LIMBS]; BF128.load(bfDelta, 0, chall3, 0);
        long[] bfDeltaSq = new long[BF128.LIMBS]; BF128.mul(bfDeltaSq, 0, bfDelta, 0, bfDelta, 0);

        long[] qKey = new long[(ell + 2 * lambda) * BF128.LIMBS];
        columnToRowMajorAndShrinkV128(qKey, Q, ell);

        long[] qStar0 = new long[BF128.LIMBS]; BF128.sumPoly(qStar0, 0, qKey, ell * BF128.LIMBS);
        long[] qStar1 = new long[BF128.LIMBS]; BF128.sumPoly(qStar1, 0, qKey, (ell + lambda) * BF128.LIMBS);
        long[] qStar = new long[BF128.LIMBS];
        long[] tmp = new long[BF128.LIMBS];
        BF128.mul(tmp, 0, bfDelta, 0, qStar1, 0);
        BF128.add(qStar, 0, qStar0, 0, tmp, 0);

        long[] wKey = new long[ell * BF128.LIMBS];
        for (int i = 0; i < ell; i++)
        {
            BF128.mulBit(tmp, 0, bfDelta, 0, dBits[i]);
            BF128.add(wKey, i * BF128.LIMBS, qKey, i * BF128.LIMBS, tmp, 0);
        }
        long[] z2Key = new long[c * BF128.LIMBS];
        FaestAESConstraints.constraintsVerifier128(z2Key, wKey, owfIn, owfOut, bfDelta, params);

        UniversalHashing.ZkHash128 bCtx = new UniversalHashing.ZkHash128(chall2, 0);
        for (int i = 0; i < c; i++)
        {
            bCtx.update(z2Key, i * BF128.LIMBS);
        }
        byte[] qTilde = new byte[BF128.BYTES];
        bCtx.finalize(qTilde, 0, qStar, 0);

        long[] qTildeF = new long[BF128.LIMBS]; BF128.load(qTildeF, 0, qTilde, 0);
        long[] a1F = new long[BF128.LIMBS]; BF128.load(a1F, 0, a1Tilde, 0);
        long[] a2F = new long[BF128.LIMBS]; BF128.load(a2F, 0, a2Tilde, 0);
        long[] tmp1 = new long[BF128.LIMBS]; BF128.mul(tmp1, 0, a1F, 0, bfDelta, 0);
        long[] tmp2 = new long[BF128.LIMBS]; BF128.mul(tmp2, 0, a2F, 0, bfDeltaSq, 0);
        long[] ret = new long[BF128.LIMBS];
        BF128.add(ret, 0, qTildeF, 0, tmp1, 0);
        BF128.addInPlace(ret, 0, tmp2, 0);
        BF128.store(a0TildeOut, 0, ret, 0);
    }

    static void aesVerifier192(byte[] a0TildeOut, byte[] dBits, byte[][] Q,
                               byte[] owfIn, byte[] owfOut,
                               byte[] chall2, byte[] chall3,
                               byte[] a1Tilde, byte[] a2Tilde,
                               FaestParameters params)
    {
        int lambda = params.getLambda();
        int c = params.getC();
        int ell = params.getEll();

        long[] bfDelta = new long[BF192.LIMBS]; BF192.load(bfDelta, 0, chall3, 0);
        long[] bfDeltaSq = new long[BF192.LIMBS]; BF192.mul(bfDeltaSq, 0, bfDelta, 0, bfDelta, 0);

        long[] qKey = new long[(ell + 2 * lambda) * BF192.LIMBS];
        columnToRowMajorAndShrinkV192(qKey, Q, ell);

        long[] qStar0 = new long[BF192.LIMBS]; BF192.sumPoly(qStar0, 0, qKey, ell * BF192.LIMBS);
        long[] qStar1 = new long[BF192.LIMBS]; BF192.sumPoly(qStar1, 0, qKey, (ell + lambda) * BF192.LIMBS);
        long[] qStar = new long[BF192.LIMBS];
        long[] tmp = new long[BF192.LIMBS];
        BF192.mul(tmp, 0, bfDelta, 0, qStar1, 0);
        BF192.add(qStar, 0, qStar0, 0, tmp, 0);

        long[] wKey = new long[ell * BF192.LIMBS];
        for (int i = 0; i < ell; i++)
        {
            BF192.mulBit(tmp, 0, bfDelta, 0, dBits[i]);
            BF192.add(wKey, i * BF192.LIMBS, qKey, i * BF192.LIMBS, tmp, 0);
        }
        long[] z2Key = new long[c * BF192.LIMBS];
        FaestAESConstraints.constraintsVerifier192(z2Key, wKey, owfIn, owfOut, bfDelta, params);

        UniversalHashing.ZkHash192 bCtx = new UniversalHashing.ZkHash192(chall2, 0);
        for (int i = 0; i < c; i++)
        {
            bCtx.update(z2Key, i * BF192.LIMBS);
        }
        byte[] qTilde = new byte[BF192.BYTES];
        bCtx.finalize(qTilde, 0, qStar, 0);

        long[] qTildeF = new long[BF192.LIMBS]; BF192.load(qTildeF, 0, qTilde, 0);
        long[] a1F = new long[BF192.LIMBS]; BF192.load(a1F, 0, a1Tilde, 0);
        long[] a2F = new long[BF192.LIMBS]; BF192.load(a2F, 0, a2Tilde, 0);
        long[] tmp1 = new long[BF192.LIMBS]; BF192.mul(tmp1, 0, a1F, 0, bfDelta, 0);
        long[] tmp2 = new long[BF192.LIMBS]; BF192.mul(tmp2, 0, a2F, 0, bfDeltaSq, 0);
        long[] ret = new long[BF192.LIMBS];
        BF192.add(ret, 0, qTildeF, 0, tmp1, 0);
        BF192.addInPlace(ret, 0, tmp2, 0);
        BF192.store(a0TildeOut, 0, ret, 0);
    }

    static void aesVerifier256(byte[] a0TildeOut, byte[] dBits, byte[][] Q,
                               byte[] owfIn, byte[] owfOut,
                               byte[] chall2, byte[] chall3,
                               byte[] a1Tilde, byte[] a2Tilde,
                               FaestParameters params)
    {
        int lambda = params.getLambda();
        int c = params.getC();
        int ell = params.getEll();

        long[] bfDelta = new long[BF256.LIMBS]; BF256.load(bfDelta, 0, chall3, 0);
        long[] bfDeltaSq = new long[BF256.LIMBS]; BF256.mul(bfDeltaSq, 0, bfDelta, 0, bfDelta, 0);

        long[] qKey = new long[(ell + 2 * lambda) * BF256.LIMBS];
        columnToRowMajorAndShrinkV256(qKey, Q, ell);

        long[] qStar0 = new long[BF256.LIMBS]; BF256.sumPoly(qStar0, 0, qKey, ell * BF256.LIMBS);
        long[] qStar1 = new long[BF256.LIMBS]; BF256.sumPoly(qStar1, 0, qKey, (ell + lambda) * BF256.LIMBS);
        long[] qStar = new long[BF256.LIMBS];
        long[] tmp = new long[BF256.LIMBS];
        BF256.mul(tmp, 0, bfDelta, 0, qStar1, 0);
        BF256.add(qStar, 0, qStar0, 0, tmp, 0);

        long[] wKey = new long[ell * BF256.LIMBS];
        for (int i = 0; i < ell; i++)
        {
            BF256.mulBit(tmp, 0, bfDelta, 0, dBits[i]);
            BF256.add(wKey, i * BF256.LIMBS, qKey, i * BF256.LIMBS, tmp, 0);
        }
        long[] z2Key = new long[c * BF256.LIMBS];
        FaestAESConstraints.constraintsVerifier256(z2Key, wKey, owfIn, owfOut, bfDelta, params);

        UniversalHashing.ZkHash256 bCtx = new UniversalHashing.ZkHash256(chall2, 0);
        for (int i = 0; i < c; i++)
        {
            bCtx.update(z2Key, i * BF256.LIMBS);
        }
        byte[] qTilde = new byte[BF256.BYTES];
        bCtx.finalize(qTilde, 0, qStar, 0);

        long[] qTildeF = new long[BF256.LIMBS]; BF256.load(qTildeF, 0, qTilde, 0);
        long[] a1F = new long[BF256.LIMBS]; BF256.load(a1F, 0, a1Tilde, 0);
        long[] a2F = new long[BF256.LIMBS]; BF256.load(a2F, 0, a2Tilde, 0);
        long[] tmp1 = new long[BF256.LIMBS]; BF256.mul(tmp1, 0, a1F, 0, bfDelta, 0);
        long[] tmp2 = new long[BF256.LIMBS]; BF256.mul(tmp2, 0, a2F, 0, bfDeltaSq, 0);
        long[] ret = new long[BF256.LIMBS];
        BF256.add(ret, 0, qTildeF, 0, tmp1, 0);
        BF256.addInPlace(ret, 0, tmp2, 0);
        BF256.store(a0TildeOut, 0, ret, 0);
    }

    // ====== dispatchers ======
    // faest_aes.c:5343 (aes_prove) / 5361 (aes_verify).

    /** Lambda-dispatching FAEST prover. */
    static void aesProve(byte[] a0Tilde, byte[] a1Tilde, byte[] a2Tilde,
                         byte[] wBits, byte[] uBits, byte[][] V,
                         byte[] owfIn, byte[] owfOut, byte[] chall2,
                         FaestParameters params)
    {
        switch (params.getLambda())
        {
        case 256: aesProver256(a0Tilde, a1Tilde, a2Tilde, wBits, uBits, V, owfIn, owfOut, chall2, params); break;
        case 192: aesProver192(a0Tilde, a1Tilde, a2Tilde, wBits, uBits, V, owfIn, owfOut, chall2, params); break;
        default:  aesProver128(a0Tilde, a1Tilde, a2Tilde, wBits, uBits, V, owfIn, owfOut, chall2, params); break;
        }
    }

    /** Lambda-dispatching FAEST verifier. Returns the lambda-byte reconstructed
     *  {@code a0_tilde}; the caller compares against the prover-supplied value. */
    static byte[] aesVerify(byte[] dBits, byte[][] Q, byte[] chall2, byte[] chall3,
                            byte[] a1Tilde, byte[] a2Tilde,
                            byte[] owfIn, byte[] owfOut, FaestParameters params)
    {
        byte[] a0 = new byte[params.getLambdaBytes()];
        switch (params.getLambda())
        {
        case 256: aesVerifier256(a0, dBits, Q, owfIn, owfOut, chall2, chall3, a1Tilde, a2Tilde, params); break;
        case 192: aesVerifier192(a0, dBits, Q, owfIn, owfOut, chall2, chall3, a1Tilde, a2Tilde, params); break;
        default:  aesVerifier128(a0, dBits, Q, owfIn, owfOut, chall2, chall3, a1Tilde, a2Tilde, params); break;
        }
        return a0;
    }
}
