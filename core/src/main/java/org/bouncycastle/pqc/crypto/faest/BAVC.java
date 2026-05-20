package org.bouncycastle.pqc.crypto.faest;

/**
 * Batched All-but-One Vector Commitment (BAVC) for FAEST v2.0.
 * <p>
 * A binary tree of {@code 2L-1} nodes is grown from a single root seed by an
 * AES-CTR PRG (see {@link FaestPrg}). The leaves are then committed via
 * {@code leaf_commit}; the per-repetition commitments are hashed together
 * with {@code H_1} to produce the BAVC root hash {@code h}.
 * <p>
 * {@link #open(Commitment, int[], FaestParameters)} produces a decommitment
 * that reveals all leaves except those indexed by {@code i_delta} (one per
 * repetition). {@link #reconstruct(byte[], int[], byte[], FaestParameters)}
 * recomputes {@code h} from the decommitment without ever learning the
 * challenged leaves &mdash; this is the all-but-one binding/hiding property.
 * <p>
 * Source of truth: {@code bavc.c}.
 */
final class BAVC
{
    private BAVC()
    {
    }

    /** Output of {@link #commit}: root hash, root seed, per-leaf commitments and leaf seeds. */
    static final class Commitment
    {
        final byte[] h;     // lambda_bytes * 2
        final byte[] k;     // root seed (= lambda_bytes view into the seed tree's node 0)
        final byte[] com;   // L * com_size
        final byte[] sd;    // L * lambda_bytes
        final byte[] nodes; // full 2L-1 tree (kept alive so k stays valid)

        Commitment(byte[] h, byte[] nodes, byte[] com, byte[] sd, int lambdaBytes)
        {
            this.h = h;
            this.nodes = nodes;
            this.k = new byte[lambdaBytes];
            System.arraycopy(nodes, 0, this.k, 0, lambdaBytes);
            this.com = com;
            this.sd = sd;
        }
    }

    /** Output of {@link #reconstruct}: re-derived root hash and per-leaf seeds for non-challenged leaves. */
    static final class Reconstruction
    {
        final byte[] h;   // lambda_bytes * 2
        final byte[] s;   // (L - tau) * lambda_bytes

        Reconstruction(byte[] h, byte[] s)
        {
            this.h = h;
            this.s = s;
        }
    }

    static int comSize(FaestParameters params)
    {
        return params.isEm()
            ? 2 * params.getLambdaBytes()
            : 3 * params.getLambdaBytes();
    }

    /** {@code bavc_max_node_depth} in bavc.h. */
    static int maxNodeDepth(int i, int tau1, int k)
    {
        return i < tau1 ? k : (k - 1);
    }

    /** {@code bavc_max_node_index} in bavc.h. */
    static int maxNodeIndex(int i, int tau1, int k)
    {
        return 1 << maxNodeDepth(i, tau1, k);
    }

    /** {@code BAVC.PosInTree} in bavc.c:79. */
    static int posInTree(int i, int j, FaestParameters params)
    {
        int L = params.getL();
        int tau = params.getTau();
        int tau1 = params.getTau1();
        int k = params.getK();
        int tmp = 1 << (k - 1);
        if (j < tmp)
        {
            return (L - 1) + tau * j + i;
        }
        int mask = tmp - 1;
        return (L - 1) + tau * tmp + tau1 * (j & mask) + i;
    }

    // ----- commit -----

    /** faest-ref: {@code bavc_commit}, bavc.c:196. */
    static Commitment commit(byte[] rootKey, byte[] iv, FaestParameters params)
    {
        return params.isEm() ? commitEm(rootKey, iv, params) : commitFaest(rootKey, iv, params);
    }

    private static Commitment commitFaest(byte[] rootKey, byte[] iv, FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = params.getLambdaBytes();
        final int L = params.getL();
        final int tau = params.getTau();
        final int tau1 = params.getTau1();
        final int k = params.getK();
        final int comSize = 3 * lambdaBytes;

        byte[] nodes = generateSeeds(rootKey, iv, params);

        // H_0 over IV, then finalize for incremental squeeze.
        RandomOracle uhashCtx = new RandomOracle(lambda);
        uhashCtx.absorb(iv);
        uhashCtx.absorbByte(RandomOracle.DOMAIN_H0);

        // H_1 over all per-repetition h_i.
        RandomOracle h1ComCtx = new RandomOracle(lambda);

        byte[] com = new byte[L * comSize];
        byte[] sd = new byte[L * lambdaBytes];
        byte[] uhash = new byte[3 * lambdaBytes];
        byte[] hi = new byte[2 * lambdaBytes];

        int offset = 0;
        for (int i = 0; i < tau; ++i)
        {
            uhashCtx.squeeze(uhash, 0, 3 * lambdaBytes);

            RandomOracle h1Ctx = new RandomOracle(lambda);
            int Ni = maxNodeIndex(i, tau1, k);
            for (int j = 0; j < Ni; ++j, ++offset)
            {
                int alpha = posInTree(i, j, params);
                faestLeafCommit(sd, offset * lambdaBytes,
                                com, offset * comSize,
                                nodes, alpha * lambdaBytes,
                                iv, /* tweak */ i + L - 1,
                                uhash, 0, lambda);
                h1Ctx.absorb(com, offset * comSize, comSize);
            }

            h1Ctx.absorbByte(RandomOracle.DOMAIN_H1);
            h1Ctx.squeeze(hi, 0, 2 * lambdaBytes);
            h1ComCtx.absorb(hi);
        }

        byte[] h = new byte[2 * lambdaBytes];
        h1ComCtx.absorbByte(RandomOracle.DOMAIN_H1);
        h1ComCtx.squeeze(h, 0, 2 * lambdaBytes);

        return new Commitment(h, nodes, com, sd, lambdaBytes);
    }

    private static Commitment commitEm(byte[] rootKey, byte[] iv, FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = params.getLambdaBytes();
        final int L = params.getL();
        final int tau = params.getTau();
        final int tau1 = params.getTau1();
        final int k = params.getK();
        final int comSize = 2 * lambdaBytes;

        byte[] nodes = generateSeeds(rootKey, iv, params);

        RandomOracle h1ComCtx = new RandomOracle(lambda);

        byte[] com = new byte[L * comSize];
        byte[] sd = new byte[L * lambdaBytes];
        byte[] hi = new byte[2 * lambdaBytes];

        int offset = 0;
        for (int i = 0; i < tau; ++i)
        {
            RandomOracle h1Ctx = new RandomOracle(lambda);
            int Ni = maxNodeIndex(i, tau1, k);
            for (int j = 0; j < Ni; ++j, ++offset)
            {
                int alpha = posInTree(i, j, params);
                faestEmLeafCommit(sd, offset * lambdaBytes,
                                  com, offset * comSize,
                                  nodes, alpha * lambdaBytes,
                                  iv, /* tweak */ i + L - 1, lambda);
                h1Ctx.absorb(com, offset * comSize, comSize);
            }
            h1Ctx.absorbByte(RandomOracle.DOMAIN_H1);
            h1Ctx.squeeze(hi, 0, 2 * lambdaBytes);
            h1ComCtx.absorb(hi);
        }

        byte[] h = new byte[2 * lambdaBytes];
        h1ComCtx.absorbByte(RandomOracle.DOMAIN_H1);
        h1ComCtx.squeeze(h, 0, 2 * lambdaBytes);

        return new Commitment(h, nodes, com, sd, lambdaBytes);
    }

    /** Allocate the 2L-1 tree and expand from the root. faest-ref: {@code generate_seeds}, bavc.c:36. */
    private static byte[] generateSeeds(byte[] rootSeed, byte[] iv, FaestParameters params)
    {
        int lambdaBytes = params.getLambdaBytes();
        int L = params.getL();
        byte[] nodes = new byte[(2 * L - 1) * lambdaBytes];
        System.arraycopy(rootSeed, 0, nodes, 0, lambdaBytes);
        expandSeeds(nodes, iv, params);
        return nodes;
    }

    /** Walk each internal node and PRG into its two children. faest-ref: {@code expand_seeds}, bavc.c:26. */
    private static void expandSeeds(byte[] nodes, byte[] iv, FaestParameters params)
    {
        int lambdaBytes = params.getLambdaBytes();
        int L = params.getL();
        int lambda = params.getLambda();
        for (int alpha = 0; alpha < L - 1; ++alpha)
        {
            FaestPrg.prg(nodes, alpha * lambdaBytes,
                         iv, 0, alpha, lambda,
                         nodes, (2 * alpha + 1) * lambdaBytes,
                         lambdaBytes * 2);
        }
    }

    /** faest-ref: {@code faest_leaf_commit}, bavc.c:48. */
    private static void faestLeafCommit(byte[] sd, int sdOff,
                                        byte[] com, int comOff,
                                        byte[] key, int keyOff,
                                        byte[] iv, long tweak,
                                        byte[] uhash, int uhashOff,
                                        int lambda)
    {
        int lambdaBytes = lambda / 8;
        byte[] buffer = new byte[lambdaBytes * 4];
        FaestPrg.prg(key, keyOff, iv, 0, tweak, lambda, buffer, 0, lambdaBytes * 4);
        UniversalHashing.leafHash(com, comOff, uhash, uhashOff, buffer, 0, lambda);
        System.arraycopy(buffer, 0, sd, sdOff, lambdaBytes);
    }

    /** faest-ref: {@code faest_em_leaf_commit}, bavc.c:59. */
    private static void faestEmLeafCommit(byte[] sd, int sdOff,
                                          byte[] com, int comOff,
                                          byte[] key, int keyOff,
                                          byte[] iv, long tweak, int lambda)
    {
        int lambdaBytes = lambda / 8;
        System.arraycopy(key, keyOff, sd, sdOff, lambdaBytes);
        FaestPrg.prg(key, keyOff, iv, 0, tweak, lambda, com, comOff, lambdaBytes * 2);
    }

    // ----- open -----

    /**
     * Produce a decommitment for the challenge indices {@code iDelta} (one per
     * repetition, value &lt; {@code maxNodeIndex(i, tau1, k)}). Returns {@code null}
     * if the number of co-path seeds needed exceeds {@code T_open} &mdash; the
     * caller is expected to retry with a different challenge in that case.
     * faest-ref: {@code bavc_open}, bavc.c:205.
     */
    static byte[] open(Commitment vc, int[] iDelta, FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = lambda / 8;
        final int L = params.getL();
        final int tau = params.getTau();
        final int tau1 = params.getTau1();
        final int k = params.getK();
        final int tOpen = params.getTOpen();
        final int comSize = comSize(params);

        int decomLen = comSize * tau + tOpen * lambdaBytes;
        byte[] decom = new byte[decomLen];

        byte[] s = new byte[(2 * L - 1 + 7) >>> 3];
        int nh = 0;

        for (int i = 0; i < tau; ++i)
        {
            int alpha = posInTree(i, iDelta[i], params);
            ptrSetBit(s, alpha, 1);
            ++nh;

            while (alpha > 0 && ptrGetBit(s, (alpha - 1) / 2) == 0)
            {
                alpha = (alpha - 1) / 2;
                ptrSetBit(s, alpha, 1);
                ++nh;
            }
        }

        if (nh - 2 * tau + 1 > tOpen)
        {
            return null;
        }

        // Copy each challenged leaf's commitment into the head of the decommitment.
        int comReadOff = 0;
        int decomWriteOff = 0;
        for (int i = 0; i < tau; ++i)
        {
            System.arraycopy(vc.com, comReadOff + iDelta[i] * comSize,
                             decom, decomWriteOff, comSize);
            comReadOff += maxNodeIndex(i, tau1, k) * comSize;
            decomWriteOff += comSize;
        }

        // Walk the internal nodes top-down, emitting the seeds of the
        // co-path siblings (the ones whose subtree contains no challenged leaf).
        for (int i = L - 2; i >= 0; --i)
        {
            int leftSet  = ptrGetBit(s, 2 * i + 1);
            int rightSet = ptrGetBit(s, 2 * i + 2);
            ptrSetBit(s, i, leftSet | rightSet);
            if ((leftSet ^ rightSet) == 1)
            {
                int alpha = 2 * i + 1 + leftSet;
                System.arraycopy(vc.nodes, alpha * lambdaBytes,
                                 decom, decomWriteOff, lambdaBytes);
                decomWriteOff += lambdaBytes;
            }
        }
        // Remaining bytes are zero-initialised by Java default.
        return decom;
    }

    // ----- reconstruct -----

    /**
     * Inverse of {@link #open}: given a decommitment and the challenge indices,
     * recompute the BAVC root hash {@code h} plus the seeds of every non-
     * challenged leaf. Returns {@code null} if the decommitment is malformed
     * (too few co-path seeds, or non-zero padding after the genuine seeds).
     * faest-ref: {@code bavc_reconstruct}, bavc.c:432.
     */
    static Reconstruction reconstruct(byte[] decom, int[] iDelta, byte[] iv, FaestParameters params)
    {
        return params.isEm()
            ? reconstructEm(decom, iDelta, iv, params)
            : reconstructFaest(decom, iDelta, iv, params);
    }

    private static Reconstruction reconstructFaest(byte[] decom, int[] iDelta, byte[] iv,
                                                    FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = lambda / 8;
        final int L = params.getL();
        final int tau = params.getTau();
        final int tau1 = params.getTau1();
        final int k = params.getK();
        final int comSize = 3 * lambdaBytes;

        byte[] s = new byte[(2 * L - 1 + 7) >>> 3];
        byte[] keys = new byte[(2 * L - 1) * lambdaBytes];
        if (!reconstructKeys(s, keys, decom, iDelta, iv, params, comSize))
        {
            return null;
        }

        RandomOracle uhashCtx = new RandomOracle(lambda);
        uhashCtx.absorb(iv);
        uhashCtx.absorbByte(RandomOracle.DOMAIN_H0);

        RandomOracle h1ComCtx = new RandomOracle(lambda);

        byte[] uhash = new byte[3 * lambdaBytes];
        byte[] com  = new byte[comSize];
        byte[] hi   = new byte[2 * lambdaBytes];
        byte[] reconSd = new byte[(L - tau) * lambdaBytes];
        int sdOffset = 0;

        for (int i = 0; i < tau; ++i)
        {
            uhashCtx.squeeze(uhash, 0, 3 * lambdaBytes);

            RandomOracle h1Ctx = new RandomOracle(lambda);
            int Ni = maxNodeIndex(i, tau1, k);
            for (int j = 0; j < Ni; ++j)
            {
                int alpha = posInTree(i, j, params);
                if (ptrGetBit(s, alpha) == 1)
                {
                    h1Ctx.absorb(decom, i * comSize, comSize);
                }
                else
                {
                    faestLeafCommit(reconSd, sdOffset * lambdaBytes,
                                    com, 0,
                                    keys, alpha * lambdaBytes,
                                    iv, /* tweak */ i + L - 1,
                                    uhash, 0, lambda);
                    ++sdOffset;
                    h1Ctx.absorb(com, 0, comSize);
                }
            }
            h1Ctx.absorbByte(RandomOracle.DOMAIN_H1);
            h1Ctx.squeeze(hi, 0, 2 * lambdaBytes);
            h1ComCtx.absorb(hi);
        }

        byte[] h = new byte[2 * lambdaBytes];
        h1ComCtx.absorbByte(RandomOracle.DOMAIN_H1);
        h1ComCtx.squeeze(h, 0, 2 * lambdaBytes);
        return new Reconstruction(h, reconSd);
    }

    private static Reconstruction reconstructEm(byte[] decom, int[] iDelta, byte[] iv,
                                                 FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = lambda / 8;
        final int L = params.getL();
        final int tau = params.getTau();
        final int tau1 = params.getTau1();
        final int k = params.getK();
        final int comSize = 2 * lambdaBytes;

        byte[] s = new byte[(2 * L - 1 + 7) >>> 3];
        byte[] keys = new byte[(2 * L - 1) * lambdaBytes];
        if (!reconstructKeys(s, keys, decom, iDelta, iv, params, comSize))
        {
            return null;
        }

        RandomOracle h1ComCtx = new RandomOracle(lambda);

        byte[] com = new byte[comSize];
        byte[] hi  = new byte[2 * lambdaBytes];
        byte[] reconSd = new byte[(L - tau) * lambdaBytes];
        int sdOffset = 0;

        for (int i = 0; i < tau; ++i)
        {
            RandomOracle h1Ctx = new RandomOracle(lambda);
            int Ni = maxNodeIndex(i, tau1, k);
            for (int j = 0; j < Ni; ++j)
            {
                int alpha = posInTree(i, j, params);
                if (ptrGetBit(s, alpha) == 1)
                {
                    h1Ctx.absorb(decom, i * comSize, comSize);
                }
                else
                {
                    faestEmLeafCommit(reconSd, sdOffset * lambdaBytes,
                                      com, 0,
                                      keys, alpha * lambdaBytes,
                                      iv, /* tweak */ i + L - 1, lambda);
                    ++sdOffset;
                    h1Ctx.absorb(com, 0, comSize);
                }
            }
            h1Ctx.absorbByte(RandomOracle.DOMAIN_H1);
            h1Ctx.squeeze(hi, 0, 2 * lambdaBytes);
            h1ComCtx.absorb(hi);
        }

        byte[] h = new byte[2 * lambdaBytes];
        h1ComCtx.absorbByte(RandomOracle.DOMAIN_H1);
        h1ComCtx.squeeze(h, 0, 2 * lambdaBytes);
        return new Reconstruction(h, reconSd);
    }

    /**
     * Rebuild the seed tree from the co-path seeds in {@code decom} and the
     * challenge indices. Returns false on malformed input. faest-ref:
     * {@code reconstruct_keys}, bavc.c:265.
     */
    private static boolean reconstructKeys(byte[] s, byte[] keys, byte[] decom, int[] iDelta,
                                            byte[] iv, FaestParameters params, int comSize)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = lambda / 8;
        final int L = params.getL();
        final int tau = params.getTau();
        final int tOpen = params.getTOpen();

        int seedsOff = tau * comSize;
        int end = seedsOff + tOpen * lambdaBytes;

        for (int i = 0; i < tau; ++i)
        {
            int alpha = posInTree(i, iDelta[i], params);
            ptrSetBit(s, alpha, 1);
        }

        for (int i = L - 2; i >= 0; --i)
        {
            int leftSet  = ptrGetBit(s, 2 * i + 1);
            int rightSet = ptrGetBit(s, 2 * i + 2);
            ptrSetBit(s, i, leftSet | rightSet);
            if ((leftSet ^ rightSet) == 1)
            {
                if (seedsOff == end)
                {
                    return false;   // not enough seeds supplied
                }
                int alpha = 2 * i + 1 + leftSet;
                System.arraycopy(decom, seedsOff, keys, alpha * lambdaBytes, lambdaBytes);
                seedsOff += lambdaBytes;
            }
        }

        // Tail must be zero-padded.
        for (int p = seedsOff; p < end; ++p)
        {
            if (decom[p] != 0)
            {
                return false;
            }
        }

        // Expand unmarked internal nodes downward (the challenged path stays unknown).
        for (int i = 0; i != L - 1; ++i)
        {
            if (ptrGetBit(s, i) == 0)
            {
                FaestPrg.prg(keys, i * lambdaBytes,
                             iv, 0, i, lambda,
                             keys, (2 * i + 1) * lambdaBytes, 2 * lambdaBytes);
            }
        }

        return true;
    }

    // ----- bit-array helpers (ptr_get_bit / ptr_set_bit in utils.h) -----

    private static int ptrGetBit(byte[] s, int index)
    {
        return (s[index >>> 3] >>> (index & 7)) & 1;
    }

    private static void ptrSetBit(byte[] s, int index, int value)
    {
        int byteIdx = index >>> 3;
        int bit = index & 7;
        s[byteIdx] = (byte)((s[byteIdx] & ~(1 << bit)) | ((value & 1) << bit));
    }
}
