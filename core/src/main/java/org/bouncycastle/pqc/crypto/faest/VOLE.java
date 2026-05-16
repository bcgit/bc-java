package org.bouncycastle.pqc.crypto.faest;

/**
 * VOLE-in-the-Head construction for FAEST v2.0.
 * <p>
 * Sits on top of {@link BAVC}: each repetition's BAVC leaves are converted
 * into a row-wise VOLE correlation via the {@link #convertToVole} kernel.
 * {@link #commit} returns the prover-side ({@code u}, {@code v}, {@code c});
 * {@link #reconstruct} returns the verifier-side ({@code q}) given a BAVC
 * decommitment, the published correction {@code c}, and the decoded
 * challenge indices {@code iDelta}.
 * <p>
 * VOLE relation: for the {@code r}-th row of the resulting matrix,
 * {@code q[r] == v[r] ^ delta[r] * u} where {@code delta[r]} is the
 * concatenated bit of the challenge across repetitions. Repetition 0
 * contributes its rows unmasked (delta-bit applied as 0 by convention);
 * subsequent repetitions XOR-mask {@code c[i-1]} into {@code q[r]}.
 * <p>
 * Source of truth: {@code vole.c}.
 */
final class VOLE
{
    /**
     * Tweak offset (high bit) used to disambiguate VOLE-related PRG calls from
     * BAVC tree-expansion calls. faest-ref: {@code vole.c:17}.
     */
    private static final long TWEAK_OFFSET = 0x80000000L;

    private VOLE()
    {
    }

    /** Output of {@link #commit}. */
    static final class Commit
    {
        final BAVC.Commitment bavc;
        final byte[] c;       // (tau - 1) * ellhatBytes
        final byte[] u;       // ellhatBytes
        final byte[][] v;     // lambda rows of ellhatBytes

        Commit(BAVC.Commitment bavc, byte[] c, byte[] u, byte[][] v)
        {
            this.bavc = bavc;
            this.c = c;
            this.u = u;
            this.v = v;
        }
    }

    /** Output of {@link #reconstruct}. */
    static final class Reconstruct
    {
        final byte[] com;     // 2 * lambdaBytes (BAVC root hash, re-derived)
        final byte[][] q;     // lambda rows of ellhatBytes

        Reconstruct(byte[] com, byte[][] q)
        {
            this.com = com;
            this.q = q;
        }
    }

    /** faest-ref: {@code vole_commit}, vole.c:68. */
    static Commit commit(byte[] rootKey, byte[] iv, int ellhat, FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = params.getLambdaBytes();
        final int ellhatBytes = (ellhat + 7) >>> 3;
        final int tau = params.getTau();
        final int tau1 = params.getTau1();
        final int k = params.getK();

        BAVC.Commitment bavc = BAVC.commit(rootKey, iv, params);

        byte[][] v = new byte[lambda][ellhatBytes];
        byte[] ui = new byte[tau * ellhatBytes];

        int vIdx = 0;
        int sdIOff = 0;
        for (int i = 0; i < tau; ++i)
        {
            int depth = convertToVole(iv, bavc.sd, sdIOff, false, i, ellhatBytes,
                                       ui, i * ellhatBytes, v, vIdx, params);
            vIdx += depth;
            int Ni = BAVC.maxNodeIndex(i, tau1, k);
            sdIOff += lambdaBytes * Ni;
        }
        // zero-pad rows up to lambda. byte[lambda][ellhatBytes] is already zero-init,
        // but for paranoid clarity:
        for (; vIdx != lambda; ++vIdx)
        {
            for (int b = 0; b < ellhatBytes; b++)
            {
                v[vIdx][b] = 0;
            }
        }

        byte[] u = new byte[ellhatBytes];
        System.arraycopy(ui, 0, u, 0, ellhatBytes);

        byte[] c = new byte[(tau - 1) * ellhatBytes];
        for (int i = 1; i < tau; i++)
        {
            for (int b = 0; b < ellhatBytes; b++)
            {
                c[(i - 1) * ellhatBytes + b] = (byte)(u[b] ^ ui[i * ellhatBytes + b]);
            }
        }

        return new Commit(bavc, c, u, v);
    }

    /**
     * Verifier-side reconstruction. faest-ref: {@code vole_reconstruct}, vole.c:105.
     * <p>
     * Returns {@code null} if BAVC reconstruction fails (malformed decommitment).
     */
    static Reconstruct reconstruct(byte[] decom, int[] iDelta, byte[] iv, byte[] c,
                                   int ellhat, FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = params.getLambdaBytes();
        final int ellhatBytes = (ellhat + 7) >>> 3;
        final int tau = params.getTau();
        final int tau1 = params.getTau1();
        final int k = params.getK();

        BAVC.Reconstruction bavcRec = BAVC.reconstruct(decom, iDelta, iv, params);
        if (bavcRec == null)
        {
            return null;
        }

        byte[] sd = new byte[(1 << k) * lambdaBytes];
        byte[][] qtmp = new byte[FaestParameters.MAX_LAMBDA][ellhatBytes];
        byte[][] q = new byte[lambda][ellhatBytes];

        int qIdx = 0;
        int sdIOff = 0;
        for (int i = 0; i < tau; ++i)
        {
            int Ni = BAVC.maxNodeIndex(i, tau1, k);

            // Permute the bavcRec.s seeds back into the (j XOR i_delta[i]) slot of sd,
            // skipping the challenged leaf. faest-ref: vole.c:141-148.
            for (int j = 0; j < Ni; ++j)
            {
                if (j < iDelta[i])
                {
                    System.arraycopy(bavcRec.s, sdIOff + lambdaBytes * j,
                                     sd, (j ^ iDelta[i]) * lambdaBytes, lambdaBytes);
                }
                else if (j == iDelta[i])
                {
                    // skip — this seed was challenged and is not in the reconstruction
                    continue;
                }
                else
                {
                    System.arraycopy(bavcRec.s, sdIOff + lambdaBytes * (j - 1),
                                     sd, (j ^ iDelta[i]) * lambdaBytes, lambdaBytes);
                }
            }

            int ki = convertToVole(iv, sd, 0, /* sd0_bot */ true, i, ellhatBytes,
                                    /* u */ null, 0, qtmp, 0, params);

            if (i == 0)
            {
                for (int d = 0; d < ki; ++d, ++qIdx)
                {
                    System.arraycopy(qtmp[d], 0, q[qIdx], 0, ellhatBytes);
                }
            }
            else
            {
                int cOff = (i - 1) * ellhatBytes;
                for (int d = 0; d < ki; ++d, ++qIdx)
                {
                    int maskBit = (iDelta[i] >>> d) & 1;
                    byte mask = (byte)(-(maskBit));
                    for (int b = 0; b < ellhatBytes; b++)
                    {
                        q[qIdx][b] = (byte)(qtmp[d][b] ^ (c[cOff + b] & mask));
                    }
                }
            }

            sdIOff += lambdaBytes * (Ni - 1);
        }

        for (; qIdx != lambda; ++qIdx)
        {
            for (int b = 0; b < ellhatBytes; b++)
            {
                q[qIdx][b] = 0;
            }
        }

        return new Reconstruct(bavcRec.h, q);
    }

    /**
     * Convert one repetition's BAVC leaves into a VOLE row-block. The number
     * of rows produced is the repetition's depth; the optional {@code u}
     * output is the "all-leaves-XOR" row, only populated when
     * {@code sd0_bot} is false (i.e. seed 0 is known &mdash; the prover side).
     * Returns the depth, which is also the number of rows written into
     * {@code v[vOff..]}. faest-ref: {@code ConvertToVole}, vole.c:23.
     *
     * @param sd0Bot         {@code true} during verify-side reconstruction:
     *                        the leaf at position 0 of {@code sd} is unknown
     *                        ({@code _|_}) and should NOT be PRG-expanded.
     * @param vOff           starting row index in the {@code v} matrix.
     */
    static int convertToVole(byte[] iv, byte[] sd, int sdOff, boolean sd0Bot, int i,
                              int outLenBytes, byte[] u, int uOff,
                              byte[][] v, int vOff, FaestParameters params)
    {
        final int lambda = params.getLambda();
        final int tau1 = params.getTau1();
        final int k = params.getK();
        final int numInstances = BAVC.maxNodeIndex(i, tau1, k);
        final int lambdaBytes = lambda / 8;
        final int depth = BAVC.maxNodeDepth(i, tau1, k);

        // Two-row ring buffer over the per-instance PRG outputs. We only ever
        // need rows j and j+1 simultaneously, so allocating 2*numInstances
        // matches the C version's memory pattern.
        byte[][] r = new byte[2 * numInstances][outLenBytes];

        // C version does memset(v, 0, depth*outLenBytes) here. In commit() the
        // v rows are already zero-initialised by Java, but reconstruct() reuses
        // qtmp across repetitions, so the zeroing is mandatory.
        for (int j = 0; j < depth; j++)
        {
            byte[] vRow = v[vOff + j];
            for (int b = 0; b < outLenBytes; b++)
            {
                vRow[b] = 0;
            }
        }

        long tweak = ((long)i) ^ TWEAK_OFFSET;

        // Row 0: PRG each seed (except slot 0 in verify mode where it's _|_).
        if (!sd0Bot)
        {
            FaestPrg.prg(sd, sdOff, iv, 0, tweak, lambda, r[0], 0, outLenBytes);
        }
        for (int j = 1; j < numInstances; ++j)
        {
            FaestPrg.prg(sd, sdOff + lambdaBytes * j, iv, 0, tweak, lambda,
                         r[j], 0, outLenBytes);
        }

        // Walk the GGM tree: row j+1 = pairwise XOR of row j; v[j] = XOR of right children.
        for (int j = 0; j < depth; j++)
        {
            int rowReadBase  = (j & 1) * numInstances;
            int rowWriteBase = ((j + 1) & 1) * numInstances;
            int depthloop = numInstances >>> (j + 1);
            for (int idx = 0; idx < depthloop; idx++)
            {
                byte[] left  = r[rowReadBase + 2 * idx];
                byte[] right = r[rowReadBase + 2 * idx + 1];
                byte[] vRow  = v[vOff + j];
                byte[] next  = r[rowWriteBase + idx];
                for (int b = 0; b < outLenBytes; b++)
                {
                    vRow[b] = (byte)(vRow[b] ^ right[b]);
                    next[b] = (byte)(left[b] ^ right[b]);
                }
            }
        }

        // Final row holds the prover-side u value, if we had access to seed 0.
        if (!sd0Bot && u != null)
        {
            int finalRowBase = (depth & 1) * numInstances;
            System.arraycopy(r[finalRowBase], 0, u, uOff, outLenBytes);
        }

        return depth;
    }
}
