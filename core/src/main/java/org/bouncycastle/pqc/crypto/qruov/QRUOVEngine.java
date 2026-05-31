package org.bouncycastle.pqc.crypto.qruov;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Port of the QR-UOV Round 2 reference implementation.
 * <p>
 * The original C code (file {@code qruov-round2-main/src/ref/qruov.c}) implements
 * the algorithm in terms of fixed-size C arrays driven by macro parameters; this
 * Java port carries the same dimensions inside a {@link QRUOVParameters} instance
 * so a single engine implementation covers every parameter set.
 * <p>
 * Element-level field ops are over F_q with q in {7, 31, 127} (each Fq fits in
 * a byte). F_q^L = F_q[X] / (x^L - fc * x^fe - fc0) is represented as an L-byte
 * array. Matrices follow the C indexing conventions: {@code MATRIX_VxV[i][k][j]}
 * is V rows, each row holds an L-tuple of length-V vectors.
 * <p>
 * <b>Constant-time properties.</b> Field arithmetic on secret-derived values
 * ({@link #fqAdd}, {@link #fqSub}, {@link #fqInv}) is implemented branchlessly
 * with mask-select / linear-scan idioms so it is L1 (no data-dependent branch)
 * and L3 (no data-dependent memory access) safe. {@link #fqMul} and the final
 * {@code % q} reductions in the polynomial-multiply kernels delegate to the
 * JVM's integer division, which is constant-latency on all modern x86-64 /
 * Arm64 microarchitectures (the same assumption the QR-UOV reference C makes).
 * <p>
 * The following code paths inherit the QR-UOV reference's variable-time
 * behaviour and are <i>not</i> constant-time, matching what the reference C
 * implementation does:
 * <ul>
 *   <li>Rejection sampling in {@link #rejSampPostProcess} — its iteration count
 *       depends on PRG output bytes. The PRG output is mixed from a secret
 *       seed in some call sites (e.g. {@link #expandSk}), so timing of these
 *       expansions leaks rejection statistics. Making this constant-time would
 *       require touching every byte of the auxiliary buffer unconditionally;
 *       neither the reference C nor the published AVX2 variant do so.</li>
 *   <li>{@code luDecompose} / {@code consistent} / {@code sampleASolution} —
 *       the linear-algebra step that solves for the oil part of the signature
 *       uses a Gaussian-elimination-with-row-pivoting on a matrix
 *       ({@code eqn}) derived from the per-signature secret {@code y} and the
 *       secret {@code Sd}. Pivot positions and zero-tests therefore depend on
 *       secret data, and the access pattern through the row-permutation index
 *       {@code ef.eqnIdx} is secret-derived (an L3 cache-line leak). The
 *       linear system is a fresh random object per signature, so the leaked
 *       structure is per-signature rather than long-term key material; the
 *       same trade-off is made in the QR-UOV reference C and in other UOV-
 *       family signature schemes (UOV, MAYO, Snova) that share this pivot-
 *       search idiom.</li>
 *   <li>The {@code do { … } while (!consistent(…))} rejection loop in
 *       {@link #sign} retries on rank-deficient systems. The number of
 *       iterations leaks via timing; for the standard parameter sets the
 *       linear system has full rank with overwhelming probability so the loop
 *       runs once in practice.</li>
 * </ul>
 */
class QRUOVEngine
{
    private static final int PRG_AES = QRUOVParameters.PRG_AES;
    private static final int PRG_SHAKE = QRUOVParameters.PRG_SHAKE;

    private final QRUOVParameters params;
    private final int q;
    private final int L;
    private final int v;
    private final int m;
    private final int fc;
    private final int fe;
    private final int fc0;
    private final int V;
    private final int M;
    private final int N;
    private final int seedLen;
    private final int saltLen;
    private final int muLen;
    private final int ceilLog2Q;
    private final int tau1;
    private final int tau2;
    private final int tau3;
    private final int tau4;
    private final int prgType;
    private final byte[] fqInv;

    // Reusable accumulators for the polynomial-multiply kernels. The engine is
    // single-threaded per operation and these kernels are leaves (never nested
    // or reentrant), so a per-engine buffer avoids allocating a fresh
    // length-(2L-1) array on every one of the O(m*(V+M)) kernel invocations.
    // Each kernel clears its buffer on entry since it accumulates with '+='.
    private final long[] dotScratchV;
    private final long[] dotScratchM;
    private final int[] fqlScratch;

    // Reusable scratch for the matrix kernels. expandPk's r1/r2 hold public
    // (seedPk-derived) PRG output and are fully overwritten on each of the m
    // calls; the transpose buffer ([M][L][V]) and the MxM product buffer
    // ([M][L][M]) are likewise overwritten before use and are never live in two
    // overlapping calls. matrixTranspose / the matrix multiplies touch every
    // element in a fixed, value-independent order, so reusing these buffers
    // does not change any data-dependent branch or memory-access pattern.
    private final byte[] pkExpandR1;
    private final byte[] pkExpandR2;
    private final byte[][][] tmpMLV;
    private final byte[][][] tmpMLM;

    QRUOVEngine(QRUOVParameters params)
    {
        this.params = params;
        this.q = params.getQ();
        this.L = params.getL();
        this.v = params.getV();
        this.m = params.getM();
        this.fc = params.getFc();
        this.fe = params.getFe();
        this.fc0 = params.getFc0();
        this.V = params.getBigV();
        this.M = params.getBigM();
        this.N = params.getBigN();
        this.seedLen = params.getSeedLen();
        this.saltLen = params.getSaltLen();
        this.muLen = params.getMuLen();
        this.ceilLog2Q = params.getCeilLog2Q();
        this.tau1 = params.getTau1();
        this.tau2 = params.getTau2();
        this.tau3 = params.getTau3();
        this.tau4 = params.getTau4();
        this.prgType = params.getPrgType();
        this.fqInv = buildInverseTable(q);
        this.dotScratchV = new long[2 * L - 1];
        this.dotScratchM = new long[2 * L - 1];
        this.fqlScratch = new int[2 * L - 1];
        this.pkExpandR1 = new byte[tau1];
        this.pkExpandR2 = new byte[tau2];
        this.tmpMLV = new byte[M][L][V];
        this.tmpMLM = new byte[M][L][M];
    }

    private static byte[] buildInverseTable(int q)
    {
        byte[] inv = new byte[q];
        inv[0] = 0;
        for (int x = 1; x < q; x++)
        {
            for (int y = 1; y < q; y++)
            {
                if (((x * y) % q) == 1)
                {
                    inv[x] = (byte)y;
                    break;
                }
            }
        }
        return inv;
    }

    int fqInv(int x)
    {
        // Constant-time table read: the secret-indexed lookup fqInv[x & 0xFF]
        // reveals which cache line was touched when the table spans more than
        // one line (q=127 occupies two 64-byte lines). Scan every slot under a
        // mask-select so the access pattern is fixed and content-independent.
        int xm = x & 0xFF;
        int result = 0;
        for (int i = 0; i < q; i++)
        {
            // ((xm ^ i) - 1) >> 31: -1 if xm == i, else 0.
            int mask = ((xm ^ i) - 1) >> 31;
            result |= (fqInv[i] & 0xFF) & mask;
        }
        return result;
    }

    int fqAdd(int a, int b)
    {
        // Branchless reduction: (a+b) is in [0, 2q-2] for a,b in [0,q-1], so
        // a single conditional subtract suffices in place of the variable-
        // latency '% q'.
        int r = (a & 0xFF) + (b & 0xFF) - q;
        return r + (q & (r >> 31));   // r<0 ? r+q : r
    }

    int fqSub(int a, int b)
    {
        // Branchless add-back: (a-b) is in [-(q-1), q-1].
        int r = (a & 0xFF) - (b & 0xFF);
        return r + (q & (r >> 31));   // r<0 ? r+q : r
    }

    int fqMul(int a, int b)
    {
        // (a*b) is in [0, (q-1)^2] <= 15876 for q <= 127. The '% q' compiles to
        // a single idiv, which is constant-latency on modern x86-64 / Arm64.
        return ((a & 0xFF) * (b & 0xFF)) % q;
    }

    // -----------------------------------------------------------------------
    //  PRG primitives (AES-CTR and SHAKE)
    // -----------------------------------------------------------------------

    private final class PRG
    {
        private AESEngine aes;
        private SHAKEDigest shake;
        private final boolean useShake;
        private KeyParameter aesKeyHolder;

        // Per-instance state for yield():
        // - SHAKE: BC's {@link SHAKEDigest#doFinal} resets the state after
        //   squeezing, so consecutive {@code doFinal} calls do NOT produce a
        //   continuous SHAKE stream. We instead use {@link SHAKEDigest#doOutput}
        //   throughout — the first call absorbs the suffix and starts squeezing,
        //   subsequent calls continue the same squeeze. This matches the legacy
        //   QR-UOV {@code MGF_yield} byte-by-byte stream behaviour the KAT
        //   vectors were generated against (the rewritten "max_size = 2*n1"
        //   MGF in mgf.c can only emit two yields and would have failed on KAT
        //   vectors needing 3+ salt iterations).
        // - AES: 128-bit big-endian block counter (matches OpenSSL EVP AES-CTR),
        //   plus a 16-byte buffer holding the unused tail of the last keystream
        //   block. OpenSSL's AES-CTR EVP_EncryptUpdate is byte-aligned (it
        //   keeps the partial trailing block across calls), so non-multiple-of-16
        //   yields (e.g. the 24-byte salt for cat-3) must not throw the partial
        //   block away — otherwise a second yield diverges from the C reference.
        private byte[] aesCtr;
        private byte[] aesPartial;     // last keystream block (only the trailing bytes are unused)
        private int aesPartialOff;     // first unused byte in aesPartial; == 16 means empty

        PRG(byte[] seed)
        {
            this.useShake = (prgType == PRG_SHAKE);
            if (useShake)
            {
                int shakeBits = (seedLen == 16) ? 128 : 256;
                shake = new SHAKEDigest(shakeBits);
                shake.update(seed, 0, seedLen);
            }
            else
            {
                aesKeyHolder = new KeyParameter(seed);
                aes = new AESEngine();
                aes.init(true, aesKeyHolder);
                aesCtr = new byte[16];
                aesPartial = new byte[16];
                aesPartialOff = 16; // empty
            }
        }

        private PRG()
        {
            this.useShake = (prgType == PRG_SHAKE);
        }

        PRG copy()
        {
            PRG c = new PRG();
            if (useShake)
            {
                c.shake = new SHAKEDigest(shake);
            }
            else
            {
                c.aesKeyHolder = aesKeyHolder;
                c.aes = new AESEngine();
                c.aes.init(true, aesKeyHolder);
                c.aesCtr = new byte[16];
                System.arraycopy(aesCtr, 0, c.aesCtr, 0, 16);
                c.aesPartial = new byte[16];
                System.arraycopy(aesPartial, 0, c.aesPartial, 0, 16);
                c.aesPartialOff = aesPartialOff;
            }
            return c;
        }

        /**
         * Stateful XOF yield for the salt-PRG path. Successive calls must produce
         * fresh bytes (the {@code do/while} in {@link #sign} relies on it to find
         * a salt whose hashed message yields a consistent linear system).
         */
        void yield(int length, byte[] dst, int dstOff)
        {
            if (useShake)
            {
                shake.doOutput(dst, dstOff, length);
            }
            else
            {
                // Note: AES yield writes raw keystream directly to dst (no zero-fill needed).
                aesYieldFromCounter(dst, dstOff, length);
            }
        }

        /**
         * Rejection sampling driven by this PRG, indexed by {@code index}.
         * For AES-CTR this re-keys the IV to {@code save64(index, iv)}; for
         * SHAKE it absorbs a 16-bit little-endian index then squeezes.
         */
        void rejSamp(long index, int length, int tau, byte[] dst, int dstOff)
        {
            if (useShake)
            {
                // append 2-byte big-endian counter (C save16 writes hi byte first), then squeeze tau bytes
                shake.update((byte)((index >>> 8) & 0xFF));
                shake.update((byte)(index & 0xFF));
                shake.doFinal(dst, dstOff, tau);
            }
            else
            {
                Arrays.fill(dst, dstOff, dstOff + tau, (byte)0);
                aesCounter(dst, dstOff, tau, index);
            }
            rejSampPostProcess(length, tau, dst, dstOff);
        }

        private void aesCounter(byte[] dst, int dstOff, int length, long ivIndex)
        {
            byte[] ctr = new byte[16];
            // C save64() writes hi byte first into iv[0..7]; iv[8..15] are zero.
            store64BE(ivIndex, ctr, 0);
            aesCounterStream(dst, dstOff, length, ctr);
        }

        /**
         * Byte-aligned AES-CTR keystream yield. Mirrors OpenSSL's
         * {@code EVP_EncryptUpdate} on an AES-CTR context: partial-block bytes
         * are preserved across calls so a 24-byte yield (cat-3 salt) doesn't
         * waste the tail of the second block.
         */
        private void aesYieldFromCounter(byte[] dst, int dstOff, int length)
        {
            int pos = 0;
            // First, drain any bytes left over from the previous yield's last block.
            while (pos < length && aesPartialOff < 16)
            {
                dst[dstOff + pos++] = aesPartial[aesPartialOff++];
            }
            // Then encrypt full blocks against the running counter until we either
            // finish or only have a tail left.
            while (length - pos >= 16)
            {
                aes.processBlock(aesCtr, 0, dst, dstOff + pos);
                pos += 16;
                incrementAesCtr();
            }
            // Tail: emit one more block, write part of it to dst, save the rest.
            if (pos < length)
            {
                aes.processBlock(aesCtr, 0, aesPartial, 0);
                incrementAesCtr();
                aesPartialOff = 0;
                while (pos < length)
                {
                    dst[dstOff + pos++] = aesPartial[aesPartialOff++];
                }
            }
        }

        private void incrementAesCtr()
        {
            for (int j = 15; j >= 0; j--)
            {
                aesCtr[j] = (byte)((aesCtr[j] & 0xFF) + 1);
                if (aesCtr[j] != 0)
                {
                    break;
                }
            }
        }

        private void aesCounterStream(byte[] dst, int dstOff, int length, byte[] ctr)
        {
            byte[] out = new byte[16];
            int remaining = length;
            int pos = 0;
            while (remaining > 0)
            {
                aes.processBlock(ctr, 0, out, 0);
                int take = Math.min(16, remaining);
                for (int i = 0; i < take; i++)
                {
                    dst[dstOff + pos + i] ^= out[i];
                }
                pos += take;
                remaining -= take;
                // Increment counter as a 128-bit big-endian counter (matches OpenSSL EVP_CIPHER aes-ctr)
                for (int j = 15; j >= 0; j--)
                {
                    ctr[j] = (byte)((ctr[j] & 0xFF) + 1);
                    if (ctr[j] != 0)
                    {
                        break;
                    }
                }
            }
        }
    }

    private static void store64BE(long v, byte[] dst, int off)
    {
        dst[off] = (byte)((v >>> 56) & 0xFF);
        dst[off + 1] = (byte)((v >>> 48) & 0xFF);
        dst[off + 2] = (byte)((v >>> 40) & 0xFF);
        dst[off + 3] = (byte)((v >>> 32) & 0xFF);
        dst[off + 4] = (byte)((v >>> 24) & 0xFF);
        dst[off + 5] = (byte)((v >>> 16) & 0xFF);
        dst[off + 6] = (byte)((v >>> 8) & 0xFF);
        dst[off + 7] = (byte)(v & 0xFF);
    }

    /**
     * The C {@code RejSamp(length, tau, dst)} routine:
     * mask each byte with {@code q} (which is one of {7, 31, 127} so the
     * mask is the field upper bound; values equal to q are rejected), then
     * replace any rejected slots from the auxiliary tail.
     */
    private void rejSampPostProcess(int length, int tau, byte[] dst, int dstOff)
    {
        int qMask = q;
        for (int i = 0; i < tau; i++)
        {
            dst[dstOff + i] &= (byte)qMask;
        }
        int auxIdx = dstOff + length;
        while ((dst[auxIdx] & 0xFF) == q)
        {
            auxIdx++;
        }
        for (int i = 0; i < length; i++)
        {
            if ((dst[dstOff + i] & 0xFF) == q)
            {
                dst[dstOff + i] = dst[auxIdx++];
                while ((dst[auxIdx] & 0xFF) == q)
                {
                    auxIdx++;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Expand_* helpers — turn PRG bytes into matrices/vectors
    // -----------------------------------------------------------------------

    private void expandVectorV(byte[] src, int srcOff, byte[][] A)
    {
        // A[L][V_padded] but V_padded = V (no SIMD alignment in ref port)
        int s = srcOff;
        for (int i = 0; i < V; i++)
        {
            for (int k = 0; k < L; k++)
            {
                A[k][i] = src[s++];
            }
        }
    }

    private void expandMatrixVxM(byte[] src, int srcOff, byte[][][] A)
    {
        // A[V][L][M]
        int s = srcOff;
        for (int i = 0; i < V; i++)
        {
            for (int j = 0; j < M; j++)
            {
                for (int k = 0; k < L; k++)
                {
                    A[i][k][j] = src[s++];
                }
            }
        }
    }

    private void expandSymmetricMatrixVxV(byte[] src, int srcOff, byte[][][] A)
    {
        // A[V][L][V], symmetric in the (i,j) outer indices
        int s = srcOff;
        for (int i = 0; i < V; i++)
        {
            for (int j = 0; j < V; j++)
            {
                if (j < i)
                {
                    for (int k = 0; k < L; k++)
                    {
                        A[i][k][j] = A[j][k][i];
                    }
                }
                else
                {
                    for (int k = 0; k < L; k++)
                    {
                        A[i][k][j] = src[s++];
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    //  PRG expansion of sk/pk/y/sol
    // -----------------------------------------------------------------------

    private void expandSk(byte[] seedSk, byte[][][] Sd, byte[][][] SdT)
    {
        int n2 = L * V * M;
        byte[] r2 = new byte[tau2];
        PRG prg = new PRG(seedSk);
        prg.rejSamp(0L, n2, tau2, r2, 0);
        expandMatrixVxM(r2, 0, Sd);
        matrixTransposeVxM(Sd, SdT);
        Arrays.fill(r2, (byte)0);
    }

    private PRG initPkPrg(byte[] seedPk)
    {
        return new PRG(seedPk);
    }

    private void expandPk(PRG ctx0, long index, byte[][][] Pi1, byte[][][] Pi2)
    {
        int n1 = L * V * (V + 1) / 2;
        int n2 = L * V * M;
        // r1/r2 hold public seedPk-derived bytes and are fully rewritten by each
        // rejSamp call, so the per-engine buffers can be reused across the m calls.
        byte[] r1 = pkExpandR1;
        byte[] r2 = pkExpandR2;

        PRG ctx1 = ctx0.copy();
        ctx1.rejSamp(2L * index, n1, tau1, r1, 0);
        expandSymmetricMatrixVxV(r1, 0, Pi1);

        PRG ctx2 = ctx0.copy();
        ctx2.rejSamp(2L * index + 1L, n2, tau2, r2, 0);
        expandMatrixVxM(r2, 0, Pi2);
    }

    private void expandY(byte[] seedY, byte[][] y)
    {
        int n3 = L * V;
        byte[] r3 = new byte[tau3];
        PRG prg = new PRG(seedY);
        prg.rejSamp(0L, n3, tau3, r3, 0);
        expandVectorV(r3, 0, y);
        Arrays.fill(r3, (byte)0);
    }

    private void expandSol(byte[] seedSol, byte[] dst)
    {
        int n4 = L * M;
        byte[] r4 = new byte[tau4];
        PRG prg = new PRG(seedSol);
        prg.rejSamp(0L, n4, tau4, r4, 0);
        System.arraycopy(r4, 0, dst, 0, n4);
        Arrays.fill(r4, (byte)0);
    }

    // -----------------------------------------------------------------------
    //  Fql arithmetic: F_q[X]/(x^L - fc*x^fe - fc0)
    // -----------------------------------------------------------------------

    void fqlAdd(byte[] X, byte[] Y, byte[] Z)
    {
        for (int i = 0; i < L; i++)
        {
            Z[i] = (byte)fqAdd(X[i] & 0xFF, Y[i] & 0xFF);
        }
    }

    void fqlSub(byte[] X, byte[] Y, byte[] Z)
    {
        for (int i = 0; i < L; i++)
        {
            Z[i] = (byte)fqSub(X[i] & 0xFF, Y[i] & 0xFF);
        }
    }

    void fqlMul(byte[] X, byte[] Y, byte[] Z)
    {
        int[] T = fqlScratch;
        Arrays.fill(T, 0);
        for (int i = 0; i < L; i++)
        {
            int xi = X[i] & 0xFF;
            for (int j = 0; j < L; j++)
            {
                T[i + j] += xi * (Y[j] & 0xFF);
            }
        }
        for (int i = 2 * L - 2; i >= L; i--)
        {
            int t = T[i];
            T[i - L] += fc0 * t;
            T[i - L + fe] += fc * t;
        }
        for (int i = 0; i < L; i++)
        {
            Z[i] = (byte)(T[i] % q);
        }
    }

    int fql2Fq(byte[] Z, int i)
    {
        return Z[i] & 0xFF;
    }

    void fq2Fql(byte[] c, byte[] out)
    {
        System.arraycopy(c, 0, out, 0, L);
    }

    // -----------------------------------------------------------------------
    //  bit-packed serialization
    // -----------------------------------------------------------------------

    private static void storeBits(int x, int numBits, byte[] pool, long[] poolBits)
    {
        int shift = (int)(poolBits[0] & 7);
        int index = (int)(poolBits[0] >>> 3);
        int mask = (1 << numBits) - 1;
        x &= mask;
        x <<= shift;
        byte x0 = (byte)(x & 0xFF);
        if (shift == 0)
        {
            pool[index] = x0;
        }
        else
        {
            pool[index] |= x0;
        }
        if (shift + numBits > 8)
        {
            pool[index + 1] = (byte)((x >>> 8) & 0xFF);
        }
        poolBits[0] += numBits;
    }

    private static int restoreBits(byte[] pool, long[] poolBits, int numBits)
    {
        int shift = (int)(poolBits[0] & 7);
        int index = (int)(poolBits[0] >>> 3);
        int mask = (1 << numBits) - 1;
        int x = (pool[index] & 0xFF)
            | (((shift + numBits > 8) ? (pool[index + 1] & 0xFF) : 0) << 8);
        x >>>= shift;
        x &= mask;
        poolBits[0] += numBits;
        return x;
    }

    void storeFq(int x, byte[] pool, long[] poolBits)
    {
        storeBits(x, ceilLog2Q, pool, poolBits);
    }

    int restoreFq(byte[] pool, long[] poolBits)
    {
        return restoreBits(pool, poolBits, ceilLog2Q);
    }

    void storeSeed(byte[] seed, byte[] pool, long[] poolBits)
    {
        int index = (int)(poolBits[0] >>> 3);
        System.arraycopy(seed, 0, pool, index, seedLen);
        poolBits[0] += (long)seedLen << 3;
    }

    void restoreSeed(byte[] pool, long[] poolBits, byte[] seedOut)
    {
        int index = (int)(poolBits[0] >>> 3);
        System.arraycopy(pool, index, seedOut, 0, seedLen);
        poolBits[0] += (long)seedLen << 3;
    }

    void storeSalt(byte[] salt, byte[] pool, long[] poolBits)
    {
        int index = (int)(poolBits[0] >>> 3);
        System.arraycopy(salt, 0, pool, index, saltLen);
        poolBits[0] += (long)saltLen << 3;
    }

    void restoreSalt(byte[] pool, long[] poolBits, byte[] saltOut)
    {
        int index = (int)(poolBits[0] >>> 3);
        System.arraycopy(pool, index, saltOut, 0, saltLen);
        poolBits[0] += (long)saltLen << 3;
    }

    void storeP3(byte[][][][] P3, byte[] pool, long[] poolBits)
    {
        // P3 dimensions: [m][M][L][M]
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < M; j++)
            {
                for (int k = 0; k < M; k++)
                {
                    if (k < j)
                    {
                        continue;
                    }
                    for (int n = 0; n < L; n++)
                    {
                        storeFq(P3[i][j][n][k] & 0xFF, pool, poolBits);
                    }
                }
            }
        }
    }

    void restoreP3(byte[] pool, long[] poolBits, byte[][][][] P3)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < M; j++)
            {
                for (int k = 0; k < M; k++)
                {
                    if (k < j)
                    {
                        for (int n = 0; n < L; n++)
                        {
                            P3[i][j][n][k] = P3[i][k][n][j];
                        }
                    }
                    else
                    {
                        for (int n = 0; n < L; n++)
                        {
                            P3[i][j][n][k] = (byte)restoreFq(pool, poolBits);
                        }
                    }
                }
            }
        }
    }

    void storeSignature(byte[] r, byte[][] s, byte[] pool)
    {
        long[] pb = new long[]{0L};
        storeSalt(r, pool, pb);
        for (int i = 0; i < N; i++)
        {
            for (int j = 0; j < L; j++)
            {
                storeFq(s[i][j] & 0xFF, pool, pb);
            }
        }
    }

    void restoreSignature(byte[] pool, byte[] rOut, byte[][] sOut)
    {
        long[] pb = new long[]{0L};
        restoreSalt(pool, pb, rOut);
        for (int i = 0; i < N; i++)
        {
            for (int j = 0; j < L; j++)
            {
                sOut[i][j] = (byte)restoreFq(pool, pb);
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Matrix / vector primitives
    // -----------------------------------------------------------------------

    private void vectorMSub(byte[][] A, byte[][] B, byte[][] C)
    {
        for (int k = 0; k < L; k++)
        {
            for (int i = 0; i < M; i++)
            {
                C[k][i] = (byte)fqSub(A[k][i] & 0xFF, B[k][i] & 0xFF);
            }
        }
    }

    private void vectorVdotVectorV(byte[][] A, byte[][] B, byte[] C)
    {
        long[] T = dotScratchV;
        Arrays.fill(T, 0L);
        for (int i = 0; i < L; i++)
        {
            byte[] ai = A[i];
            for (int j = 0; j < L; j++)
            {
                byte[] bj = B[j];
                // acc <= V*(q-1)^2 <= 149*126^2 < 2^31, so int accumulation is
                // exact and lets C2 vectorise the byte->int widening multiply.
                int acc = 0;
                for (int k = 0; k < V; k++)
                {
                    acc += (ai[k] & 0xFF) * (bj[k] & 0xFF);
                }
                T[i + j] += acc;
            }
        }
        for (int i = 2 * L - 2; i >= L; i--)
        {
            long t = T[i];
            T[i - L] += (long)fc0 * t;
            T[i - L + fe] += (long)fc * t;
        }
        for (int i = 0; i < L; i++)
        {
            C[i] = (byte)(T[i] % q);
        }
    }

    private void vectorMdotVectorM(byte[][] A, byte[][] B, byte[] C)
    {
        long[] T = dotScratchM;
        Arrays.fill(T, 0L);
        for (int i = 0; i < L; i++)
        {
            byte[] ai = A[i];
            for (int j = 0; j < L; j++)
            {
                byte[] bj = B[j];
                // acc <= M*(q-1)^2 <= 38*126^2 < 2^31, so int accumulation is
                // exact and lets C2 vectorise the byte->int widening multiply.
                int acc = 0;
                for (int k = 0; k < M; k++)
                {
                    acc += (ai[k] & 0xFF) * (bj[k] & 0xFF);
                }
                T[i + j] += acc;
            }
        }
        for (int i = 2 * L - 2; i >= L; i--)
        {
            long t = T[i];
            T[i - L] += (long)fc0 * t;
            T[i - L + fe] += (long)fc * t;
        }
        for (int i = 0; i < L; i++)
        {
            C[i] = (byte)(T[i] % q);
        }
    }

    private void vectorVmulSymmetricMatrixVxV(byte[][] A, byte[][][] B, byte[][] C)
    {
        byte[] tmp = new byte[L];
        for (int i = 0; i < V; i++)
        {
            vectorVdotVectorV(A, B[i], tmp);
            for (int k = 0; k < L; k++)
            {
                C[k][i] = tmp[k];
            }
        }
    }

    private void matrixTransposeVxM(byte[][][] A, byte[][][] C)
    {
        // A is [V][L][M], C is [M][L][V]
        for (int i = 0; i < V; i++)
        {
            for (int k = 0; k < L; k++)
            {
                for (int j = 0; j < M; j++)
                {
                    C[j][k][i] = A[i][k][j];
                }
            }
        }
    }

    private void vectorVmulMatrixVxM(byte[][] A, byte[][][] B, byte[][] C)
    {
        matrixTransposeVxM(B, tmpMLV);
        vectorVmulMatrixVxMTransposed(A, tmpMLV, C);
    }

    // BT is B already transposed to [M][L][V]; hoisting the transpose to the
    // caller avoids recomputing it for every row when B is loop-invariant.
    private void vectorVmulMatrixVxMTransposed(byte[][] A, byte[][][] BT, byte[][] C)
    {
        byte[] tmp = new byte[L];
        for (int i = 0; i < M; i++)
        {
            vectorVdotVectorV(A, BT[i], tmp);
            for (int k = 0; k < L; k++)
            {
                C[k][i] = tmp[k];
            }
        }
    }

    private void matrixMxVmulSymmetricMatrixVxV(byte[][][] A, byte[][][] B, byte[][][] C)
    {
        for (int i = 0; i < M; i++)
        {
            vectorVmulSymmetricMatrixVxV(A[i], B, C[i]);
        }
    }

    private void matrixMulMxVVxM(byte[][][] A, byte[][][] B, byte[][][] C)
    {
        // B is constant across the M rows, so transpose it once here (into the
        // reusable scratch) rather than re-transposing inside each row's multiply.
        matrixTransposeVxM(B, tmpMLV);
        matrixMulMxVVxMTransposed(A, tmpMLV, C);
    }

    // BT is B already transposed to [M][L][V]; lets a caller holding a
    // loop-invariant transpose (e.g. SdT) skip the per-call transpose+allocation.
    private void matrixMulMxVVxMTransposed(byte[][][] A, byte[][][] BT, byte[][][] C)
    {
        for (int i = 0; i < M; i++)
        {
            vectorVmulMatrixVxMTransposed(A[i], BT, C[i]);
        }
    }

    private void matrixAddMxM(byte[][][] A, byte[][][] B, byte[][][] C)
    {
        for (int i = 0; i < M; i++)
        {
            for (int k = 0; k < L; k++)
            {
                for (int j = 0; j < M; j++)
                {
                    C[i][k][j] = (byte)fqAdd(A[i][k][j] & 0xFF, B[i][k][j] & 0xFF);
                }
            }
        }
    }

    private void matrixMulAddMxVVxM(byte[][][] A, byte[][][] B, byte[][][] C)
    {
        // tmpMLM is fully written by the multiply before matrixAddMxM reads it;
        // tmpMLV (used inside matrixMulMxVVxM) is a distinct buffer.
        matrixMulMxVVxM(A, B, tmpMLM);
        matrixAddMxM(C, tmpMLM, C);
    }

    private void matrixSubMxV(byte[][][] A, byte[][][] B, byte[][][] C)
    {
        for (int i = 0; i < M; i++)
        {
            for (int k = 0; k < L; k++)
            {
                for (int j = 0; j < V; j++)
                {
                    C[i][k][j] = (byte)fqSub(A[i][k][j] & 0xFF, B[i][k][j] & 0xFF);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Expand_mu / Hash
    // -----------------------------------------------------------------------

    private void expandMu(byte[] seedPk, byte[] message, byte[] muOut)
    {
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seedPk, 0, seedLen);
        shake.update(message, 0, message.length);
        shake.doFinal(muOut, 0, muLen);
    }

    private void hashToM(byte[] mu, byte[] salt, byte[] msgOut)
    {
        byte[] tmp = new byte[tau4];
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(mu, 0, muLen);
        shake.update(salt, 0, saltLen);
        shake.doFinal(tmp, 0, tau4);
        rejSampPostProcess(m, tau4, tmp, 0);
        System.arraycopy(tmp, 0, msgOut, 0, m);
    }

    // -----------------------------------------------------------------------
    //  Echelon form / linear-algebra helpers
    // -----------------------------------------------------------------------

    private static final class EchelonForm
    {
        final byte[][] rowCol;
        final int[] rowOrig;
        int[] eqnIdx;
        int rank;
        int[] index;

        EchelonForm(int m)
        {
            rowCol = new byte[m][];
            rowOrig = new int[m];
            eqnIdx = new int[m];
            index = new int[m];
        }
    }

    private void echelonFormInit(byte[][] mat, EchelonForm ef)
    {
        for (int i = 0; i < m; i++)
        {
            ef.rowCol[i] = mat[i];
            ef.rowOrig[i] = i;
            ef.eqnIdx[i] = i;
        }
        ef.rank = 0;
        Arrays.fill(ef.index, -1);
    }

    private static void rowSwap(int[] eqn, int i, int j)
    {
        int tmp = eqn[i];
        eqn[i] = eqn[j];
        eqn[j] = tmp;
    }

    private int eqnVal(byte[][] rowCol, int[] eqn, int i, int j)
    {
        return rowCol[eqn[i]][j] & 0xFF;
    }

    private void setEqn(byte[][] rowCol, int[] eqn, int i, int j, int val)
    {
        rowCol[eqn[i]][j] = (byte)val;
    }

    private void luDecompose(byte[][] A, EchelonForm ef)
    {
        echelonFormInit(A, ef);
        int[] eqn = ef.eqnIdx;
        byte[][] rc = ef.rowCol;

        int c = -1;
        for (int i = 0; i < m; i++)
        {
            c++;
            if (c >= m)
            {
                return;
            }
            int j = i;
            while (eqnVal(rc, eqn, j, c) == 0)
            {
                j++;
                if (j >= m)
                {
                    c++;
                    if (c >= m)
                    {
                        return;
                    }
                    j = i;
                }
            }
            rowSwap(eqn, i, j);
            ef.index[ef.rank++] = c;

            int pivot = eqnVal(rc, eqn, i, c);
            int inv = fqInv(pivot);
            setEqn(rc, eqn, i, i, pivot);
            for (int k = c + 1; k < m; k++)
            {
                setEqn(rc, eqn, i, k, fqMul(inv, eqnVal(rc, eqn, i, k)));
            }
            for (j = i + 1; j < m; j++)
            {
                int mul = eqnVal(rc, eqn, j, c);
                setEqn(rc, eqn, j, i, mul);
                for (int k = c + 1; k < m; k++)
                {
                    setEqn(rc, eqn, j, k, fqSub(eqnVal(rc, eqn, j, k), fqMul(mul, eqnVal(rc, eqn, i, k))));
                }
            }
        }
    }

    private void fqMatrixIdentity(byte[][] A)
    {
        for (int i = 0; i < m; i++)
        {
            Arrays.fill(A[i], (byte)0);
            A[i][i] = 1;
        }
    }

    private void lInverse(EchelonForm ef, byte[][] R)
    {
        int[] eqn = ef.eqnIdx;
        byte[][] rc = ef.rowCol;
        int rank = ef.rank;
        fqMatrixIdentity(R);
        for (int i = 0; i < rank; i++)
        {
            int pivot = eqnVal(rc, eqn, i, i);
            int inv = fqInv(pivot);
            for (int k = 0; k <= i; k++)
            {
                R[i][k] = (byte)fqMul(R[i][k] & 0xFF, inv);
            }
            for (int j = i + 1; j < m; j++)
            {
                int factor = eqnVal(rc, eqn, j, i);
                for (int k = 0; k <= i; k++)
                {
                    R[j][k] = (byte)fqSub(R[j][k] & 0xFF, fqMul(factor, R[i][k] & 0xFF));
                }
            }
        }
    }

    private boolean consistent(EchelonForm ef, byte[] b, boolean[] cacheR, byte[][] R)
    {
        int rank = ef.rank;
        if (rank == m)
        {
            return true;
        }
        if (!cacheR[0])
        {
            lInverse(ef, R);
            cacheR[0] = true;
        }
        int[] eqn = ef.eqnIdx;
        byte[][] rc = ef.rowCol;
        for (int i = rank; i < m; i++)
        {
            long t = 0;
            for (int j = 0; j < rank; j++)
            {
                int k = ef.rowOrig[eqn[j]];
                t += (long)(R[i][j] & 0xFF) * (long)(b[k] & 0xFF);
            }
            int k = ef.rowOrig[eqn[i]];
            t += (long)(R[i][i] & 0xFF) * (long)(b[k] & 0xFF);
            t %= q;
            if (t != 0)
            {
                return false;
            }
        }
        return true;
    }

    private void sampleASolution(byte[] seedSol, EchelonForm ef, byte[] b, byte[] x, byte[] b2)
    {
        int rank = ef.rank;
        int[] index = ef.index;
        int[] eqn = ef.eqnIdx;
        byte[][] rc = ef.rowCol;

        byte[] randomBuff = new byte[m];
        int randomIdx = 0;
        if (rank < m)
        {
            expandSol(seedSol, randomBuff);
        }

        for (int i = 0; i < rank; i++)
        {
            long t = 0;
            for (int j = 0; j < i; j++)
            {
                t += (long)eqnVal(rc, eqn, i, j) * (long)(b2[j] & 0xFF);
            }
            int tmp = (int)(t % q);
            int k = ef.rowOrig[eqn[i]];
            tmp = fqSub(b[k] & 0xFF, tmp);
            b2[i] = (byte)fqMul(tmp, fqInv(eqnVal(rc, eqn, i, i)));
        }

        int i = m - 1;
        for (int j = rank - 1; j >= 0; j--)
        {
            int k = index[j];
            for (; i > k; i--)
            {
                x[i] = randomBuff[randomIdx++];
            }
            long t = 0;
            for (int kk = k + 1; kk < m; kk++)
            {
                t += (long)eqnVal(rc, eqn, j, kk) * (long)(x[kk] & 0xFF);
            }
            x[i] = (byte)fqSub(b2[j] & 0xFF, (int)(t % q));
            i--;
        }
        for (; i >= 0; i--)
        {
            x[i] = randomBuff[randomIdx++];
        }
    }

    private void pack0(byte[] oilU, byte[][] oil)
    {
        int s = 0;
        for (int i = 0; i < M; i++)
        {
            for (int k = 0; k < L; k++)
            {
                oil[k][i] = oilU[s++];
            }
        }
    }

    // -----------------------------------------------------------------------
    //  KeyGen, Sign, Verify
    // -----------------------------------------------------------------------

    void keyGen(byte[] seedSk, byte[] seedPk, byte[][][][] P3)
    {
        byte[][][] Sd = new byte[V][L][M];
        byte[][][] SdT = new byte[M][L][V];
        byte[][][] Pi1 = new byte[V][L][V];
        byte[][][] Pi2 = new byte[V][L][M];
        byte[][][] Pi2T = new byte[M][L][V];
        byte[][][] TMP = new byte[M][L][V];

        expandSk(seedSk, Sd, SdT);

        PRG ctx = initPkPrg(seedPk);
        for (int i = 0; i < m; i++)
        {
            expandPk(ctx, i, Pi1, Pi2);
            matrixTransposeVxM(Pi2, Pi2T);
            matrixMxVmulSymmetricMatrixVxV(SdT, Pi1, TMP);
            matrixSubMxV(Pi2T, TMP, TMP);
            // Sd is loop-invariant; SdT already holds its transpose.
            matrixMulMxVVxMTransposed(TMP, SdT, P3[i]);
            matrixMulAddMxVVxM(SdT, Pi2, P3[i]);
        }
    }

    void sign(byte[] seedSk, byte[] seedPk, byte[] seedY, byte[] seedR, byte[] seedSol,
              byte[] message, byte[] sigR, byte[][] sigS)
    {
        byte[][][] Sd = new byte[V][L][M];
        byte[][][] SdT = new byte[M][L][V];
        byte[][][] Pi1 = new byte[V][L][V];
        byte[][][] Pi2 = new byte[V][L][M];
        byte[][] y = new byte[L][V];
        byte[][] yTPi1 = new byte[L][V];
        byte[][] yTPi1Sd = new byte[L][M];
        byte[][] yTPi2 = new byte[L][M];
        byte[][] yTFi2 = new byte[L][M];

        byte[][] eqn = new byte[m][m];
        byte[][] R = new byte[m][m];
        byte[] c = new byte[m];

        expandSk(seedSk, Sd, SdT);
        expandY(seedY, y);

        byte[] yTFi1j = new byte[L];
        byte[] yj = new byte[L];
        byte[] prod = new byte[L];

        PRG ctxPk = initPkPrg(seedPk);
        for (int i = 0; i < m; i++)
        {
            expandPk(ctxPk, i, Pi1, Pi2);

            vectorVmulSymmetricMatrixVxV(y, Pi1, yTPi1);
            // Sd is loop-invariant; reuse the transpose expandSk already computed
            // into SdT rather than re-transposing (and re-allocating) it per row.
            vectorVmulMatrixVxMTransposed(yTPi1, SdT, yTPi1Sd);
            vectorVmulMatrixVxM(y, Pi2, yTPi2);
            vectorMSub(yTPi2, yTPi1Sd, yTFi2);

            for (int j = 0; j < M; j++)
            {
                for (int k = 0; k < L; k++)
                {
                    int u = yTFi2[params.perm(k)][j] & 0xFF;
                    eqn[i][L * j + k] = (byte)fqAdd(u, u);
                }
            }

            long ci = 0;
            for (int j = 0; j < V; j++)
            {
                for (int k = 0; k < L; k++)
                {
                    yTFi1j[k] = yTPi1[k][j];
                }
                for (int k = 0; k < L; k++)
                {
                    yj[k] = y[k][j];
                }
                fqlMul(yTFi1j, yj, prod);
                ci += prod[params.perm(0)] & 0xFF;
            }
            c[i] = (byte)(ci % q);
        }

        EchelonForm ef = new EchelonForm(m);
        luDecompose(eqn, ef);

        byte[] mu = new byte[muLen];
        expandMu(seedPk, message, mu);

        byte[] msgArr = new byte[m];
        byte[] b = new byte[m];
        byte[] b2 = new byte[m];
        boolean[] cacheR = new boolean[]{false};

        PRG ctxR = new PRG(seedR);
        do
        {
            ctxR.yield(saltLen, sigR, 0);
            hashToM(mu, sigR, msgArr);
            for (int i = 0; i < m; i++)
            {
                b[i] = (byte)fqSub(msgArr[i] & 0xFF, c[i] & 0xFF);
            }
        }
        while (!consistent(ef, b, cacheR, R));

        byte[] oilU = new byte[m];
        sampleASolution(seedSol, ef, b, oilU, b2);

        byte[][] oil = new byte[L][M];
        pack0(oilU, oil);

        // SIG_GEN
        byte[] u = new byte[L];
        byte[] t = new byte[L];
        byte[] usubt = new byte[L];
        for (int i = 0; i < V; i++)
        {
            for (int j = 0; j < L; j++)
            {
                u[j] = y[j][i];
            }
            vectorMdotVectorM(oil, Sd[i], t);
            fqlSub(u, t, usubt);
            System.arraycopy(usubt, 0, sigS[i], 0, L);
        }
        for (int i = V; i < N; i++)
        {
            for (int j = 0; j < L; j++)
            {
                u[j] = oil[j][i - V];
            }
            System.arraycopy(u, 0, sigS[i], 0, L);
        }
    }

    boolean verify(byte[] seedPk, byte[][][][] P3, byte[] message, byte[] sigR, byte[][] sigS)
    {
        byte[] mu = new byte[muLen];
        expandMu(seedPk, message, mu);
        byte[] msgArr = new byte[m];
        hashToM(mu, sigR, msgArr);

        byte[][][] Pi1 = new byte[V][L][V];
        byte[][][] Pi2 = new byte[V][L][M];

        byte[][] y = new byte[L][V];
        byte[][] oil = new byte[L][M];

        for (int i = 0; i < V; i++)
        {
            for (int k = 0; k < L; k++)
            {
                y[k][i] = sigS[i][k];
            }
        }
        for (int i = 0; i < M; i++)
        {
            for (int k = 0; k < L; k++)
            {
                oil[k][i] = sigS[i + V][k];
            }
        }

        boolean okay = true;
        PRG ctxPk = initPkPrg(seedPk);
        for (int i = 0; i < m && okay; i++)
        {
            expandPk(ctxPk, i, Pi1, Pi2);
            okay &= verifyI(Pi1, Pi2, P3[i], oil, y, msgArr[i]);
        }
        return okay;
    }

    private boolean verifyI(byte[][][] Pi1, byte[][][] Pi2, byte[][][] Pi3,
                            byte[][] oil, byte[][] vine, byte msgI)
    {
        byte[][] tmpV = new byte[L][V];
        byte[][] tmpO = new byte[L][M];
        byte[] t = new byte[L];
        byte[] u = new byte[L];

        for (int j = 0; j < V; j++)
        {
            vectorMdotVectorM(oil, Pi2[j], t);
            vectorVdotVectorV(vine, Pi1[j], u);
            for (int k = 0; k < L; k++)
            {
                int tt = fqAdd(t[k] & 0xFF, t[k] & 0xFF);
                tmpV[k][j] = (byte)fqAdd(tt, u[k] & 0xFF);
            }
        }

        for (int j = 0; j < M; j++)
        {
            vectorMdotVectorM(oil, Pi3[j], t);
            for (int k = 0; k < L; k++)
            {
                tmpO[k][j] = t[k];
            }
        }

        vectorVdotVectorV(vine, tmpV, t);
        vectorMdotVectorM(oil, tmpO, u);

        int actual = fqAdd(t[params.perm(0)] & 0xFF, u[params.perm(0)] & 0xFF);
        return (msgI & 0xFF) == actual;
    }
}
