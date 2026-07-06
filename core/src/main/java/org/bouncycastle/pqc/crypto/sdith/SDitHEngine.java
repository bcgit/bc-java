package org.bouncycastle.pqc.crypto.sdith;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.raw.GF256AES;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Stateful engine implementing the SDitH-Hypercube signature scheme.
 * <p>
 * Port of the reference C implementation under
 * {@code sdith/Reference_Implementation/Hypercube_Variant/sdith_hypercube_cat1_gf256/}.
 * Currently only the {@code sdith_hypercube_cat1_gf256} parameter set is wired
 * in; the engine is structured so other categories / fields can be added by
 * extending the parameter-table lookups and precomputed-table arrays without
 * touching the algorithm flow.
 */
final class SDitHEngine
{
    private final SDitHParameters params;
    private final SecureRandom random;

    // Cached parameter fields, all from params; copied for hot-path readability.
    private final int seedSize;
    private final int saltSize;
    private final int hashSize;
    private final int commitSize;
    private final int fpointSize;
    private final int paramK;
    private final int paramD;
    private final int paramT;
    private final int paramTau;
    private final int paramDimD;
    private final int paramWd;
    private final int paramMd;
    private final int paramYSize;
    private final int paramHaNSlice;
    private final int hashBits;
    private final int xofBits;

    /**
     * Layout of one MPC share (in bytes):
     * s_A[k] || q_poly[d * wd] || p_poly[d * wd] || a[d * t * 4] || b[d * t * 4] || c[t * 4]
     * Field element widths in the a/b/c blocks are always 4 bytes (uint32_t in the
     * reference), masked down to fpointSize bytes when interpreted.
     */
    private final int shareSize;
    private final int shareSA;
    private final int shareQ;
    private final int shareP;
    private final int shareA;
    private final int shareB;
    private final int shareC;

    /**
     * Auxiliary share layout written into the signature: s_A || q_poly || p_poly || c.
     */
    private final int auxSize;

    /**
     * Compressed-alpha / compressed-beta per-iteration size: d * t * fpointSize.
     */
    private final int alphaBetaBytes;

    public SDitHEngine(SDitHParameters params, SecureRandom random)
    {
        this.params = params;
        this.random = random;
        this.seedSize = params.getSeedSize();
        this.saltSize = params.getSaltSize();
        this.hashSize = params.getHashSize();
        this.commitSize = params.getCommitSize();
        this.fpointSize = params.getFpointSize();
        this.paramK = params.getK();
        this.paramD = params.getD();
        this.paramT = params.getT();
        this.paramTau = params.getTau();
        this.paramDimD = params.getDimD();
        this.paramWd = params.getWd();
        this.paramMd = params.getMd();
        this.paramYSize = params.getYSize();
        this.paramHaNSlice = params.getHaNSlice();
        this.hashBits = params.getHashBits();
        this.xofBits = params.getXofBits();

        // Share-block layout. The C reference's mpc_share_t struct is NOT packed,
        // so the compiler inserts padding between the byte arrays (s_A, q_poly, p_poly)
        // and the uint32_t arrays (a, b, c) so that the uint32_t arrays land on a
        // 4-byte boundary. For cat1/cat3 (k + 2*d*wd) is already a multiple of 4 —
        // no padding. For cat5 (k=282, d=2, wd=78 → 594) two bytes of padding are
        // inserted; the XOF squeeze, share XOR accumulation, and per-leaf hashing
        // all see those bytes, so the Java port must mirror the alignment exactly.
        this.shareSA = 0;
        this.shareQ = shareSA + paramK;
        this.shareP = shareQ + paramD * paramWd;
        int afterByteFields = shareP + paramD * paramWd;
        this.shareA = (afterByteFields + 3) & ~3;
        this.shareB = shareA + paramD * paramT * 4;
        this.shareC = shareB + paramD * paramT * 4;
        this.shareSize = shareC + paramT * 4;

        this.auxSize = paramK + 2 * paramD * paramWd + paramT * fpointSize;
        this.alphaBetaBytes = paramD * paramT * fpointSize;
    }

    public SDitHParameters getParameters()
    {
        return params;
    }

    // ----- byte-level helpers -----

    private static int readField32(byte[] buf, int off)
    {
        return Pack.littleEndianToInt(buf, off);
    }

    private static void writeField32(byte[] buf, int off, int v)
    {
        Pack.intToLittleEndian(v, buf, off);
    }

    private int fpointMask()
    {
        if (fpointSize >= 4)
        {
            return -1;
        }
        return (1 << (fpointSize * 8)) - 1;
    }

    /**
     * Pull a fresh XOF context seeded with the given byte array.
     */
    private SHAKEDigest newXof(byte[] seed, int off, int len)
    {
        SHAKEDigest x = new SHAKEDigest(xofBits);
        x.update(seed, off, len);
        // Reference squeezes after this, which Bouncy Castle's SHAKEDigest handles
        // implicitly via doOutput(...) / doFinal(...).
        return x;
    }

    private void squeeze(SHAKEDigest x, byte[] out, int off, int len)
    {
        x.doOutput(out, off, len);
    }

    /**
     * Squeeze {@code len} field-element bytes from the XOF. For GF(256) every
     * byte is valid; for GF(p251) the reference rejection-samples bytes &lt; 251
     * with ~1.03x oversampling — see {@code sdith_xof_next_bytes_mod251}.
     */
    private void squeezeFieldBytes(SHAKEDigest x, byte[] out, int off, int len)
    {
        if (!isP251())
        {
            squeeze(x, out, off, len);
            return;
        }
        int oversample = len + (len >> 5);
        byte[] buf = new byte[oversample];
        int written = 0;
        while (written < len)
        {
            squeeze(x, buf, 0, oversample);
            for (int i = 0; i < oversample && written < len; ++i)
            {
                int b = buf[i] & 0xff;
                if (b < 251)
                {
                    out[off + (written++)] = (byte) b;
                }
            }
        }
    }

    // ----- field-aware arithmetic -----

    private boolean isP251()
    {
        return params.getField() == SDitHParameters.FIELD_P251;
    }

    /**
     * SD-base-field byte add: XOR for GF(256), mod-251 add for GF(p251).
     */
    private int fieldByteAdd(int a, int b)
    {
        return isP251() ? SDitHP251.add(a, b) : ((a ^ b) & 0xff);
    }

    /**
     * SD-base-field byte sub: XOR for GF(256), mod-251 sub for GF(p251).
     */
    private int fieldByteSub(int a, int b)
    {
        return isP251() ? SDitHP251.sub(a, b) : ((a ^ b) & 0xff);
    }

    /**
     * SD-base-field byte mul: naive GF(256) mul or mod-251 mul.
     */
    private int fieldByteMul(int a, int b)
    {
        return isP251() ? SDitHP251.mulNaive(a, b) : GF256AES.mul(a, b);
    }

    /**
     * SD-base-field byte negate: identity for GF(256), 251-x for GF(p251).
     */
    private int fieldByteNeg(int a)
    {
        return isP251() ? SDitHP251.neg(a) : (a & 0xff);
    }

    /**
     * Extension-field (uint32_t) add.
     */
    private int fpointAdd(int a, int b)
    {
        return isP251() ? SDitHP251P4.add(a, b) : (a ^ b);
    }

    /**
     * Extension-field (uint32_t) sub.
     */
    private int fpointSub(int a, int b)
    {
        return isP251() ? SDitHP251P4.sub(a, b) : (a ^ b);
    }

    /**
     * Extension-field multiplication.
     */
    private int fpointMul(int a, int b)
    {
        return isP251() ? SDitHP251P4.mulNaive(a, b) : SDitHGF2P32.mulNaive(a, b);
    }

    private int fpointDlog(int a)
    {
        return isP251() ? SDitHP251P4.dlog(a) : SDitHGF2P32.dlog(a);
    }

    private int fpointDexp(int a)
    {
        return isP251() ? SDitHP251P4.dexp(a) : SDitHGF2P32.dexp(a);
    }

    private int fpointDlogPow(int logx, int p)
    {
        return isP251() ? SDitHP251P4.dlogPow(logx, p) : SDitHGF2P32.dlogPow(logx, p);
    }

    private int fpointDlogMul(int logx, int logy)
    {
        return isP251() ? SDitHP251P4.dlogMul(logx, logy) : SDitHGF2P32.dlogMul(logx, logy);
    }

    private void vecMat16ColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m)
    {
        if (isP251())
        {
            SDitHP251.vecMat16ColsMulAdd(vz, vzOff, vx, vxOff, my, myOff, m);
        }
        else
        {
            SDitHGF256.vecMat16ColsMulAdd(vz, vzOff, vx, vxOff, my, myOff, m);
        }
    }

    private void vecMatNColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m, int n)
    {
        if (isP251())
        {
            SDitHP251.vecMatNColsMulAdd(vz, vzOff, vx, vxOff, my, myOff, m, n);
        }
        else
        {
            SDitHGF256.vecMatNColsMulAdd(vz, vzOff, vx, vxOff, my, myOff, m, n);
        }
    }

    /**
     * Share accumulation: GF(256) XOR or mod-251 add over every byte of the share buffer.
     */
    private void shareAccumulate(byte[] dst, byte[] src)
    {
        if (!isP251())
        {
            for (int b = 0; b < shareSize; ++b)
            {
                dst[b] ^= src[b];
            }
        }
        else
        {
            for (int b = 0; b < shareSize; ++b)
            {
                int v = (dst[b] & 0xff) + (src[b] & 0xff);
                dst[b] = (byte) SDitHP251.reduce16(v);
            }
        }
    }

    // ----- key generation -----

    /**
     * Generate a fresh SDitH key pair. Returns {@code {pk, sk}} where:
     * <ul>
     *   <li>{@code pk} is {@code H_a_seed || y}.</li>
     *   <li>{@code sk} is the full expanded form
     *       {@code H_a_seed || y || s_A || q_poly || p_poly}.</li>
     * </ul>
     * The master seed {@code m_seed} is sampled from the configured RNG and
     * thrown away (the reference does not persist it in the PKCS-style
     * encoding — only the expanded sk and compressed pk).
     */
    public byte[][] generateKeyPair()
    {
        byte[] mSeed = new byte[seedSize];
        random.nextBytes(mSeed);

        IsdInstance inst = generateIsdInstance(mSeed);

        byte[] pk = Arrays.concatenate(inst.hASeed, inst.y);
        byte[] sk = Arrays.concatenate(new byte[][]{inst.hASeed, inst.y, inst.sA, inst.qPoly, inst.pPoly});
        return new byte[][]{pk, sk, mSeed};
    }

    static final class IsdInstance
    {
        byte[] hASeed;
        byte[] y;        // m-k bytes
        byte[] sA;       // k bytes
        byte[] qPoly;    // d * wd bytes
        byte[] pPoly;    // d * wd bytes

        // Internal: H_a matrix laid out as ha_nslice slices, each k rows × 128 cols (zero-padded).
        byte[][] hA;
    }

    /**
     * Threshold-variant keygen. Differs from the hypercube path in two ways:
     * <ol>
     *   <li>Position and value bytes are sampled one byte at a time from a
     *       single XOF, interleaved per chunk — matching the reference
     *       {@code expand_extended_witness} which calls {@code byte_sample} /
     *       {@code random_points} per accepted byte.</li>
     *   <li>For GF(p251), value sampling rejects bytes &ge; 251 one byte at a
     *       time (the hypercube bulk-mod251 tape would consume the XOF stream
     *       differently).</li>
     * </ol>
     */
    IsdInstance generateIsdInstanceForThreshold(byte[] mSeed)
    {
        IsdInstance inst = new IsdInstance();
        SHAKEDigest entropy = newXof(mSeed, 0, seedSize);
        byte[] one = new byte[1];

        byte[] x = new byte[paramD * paramMd];
        byte[] s = new byte[paramD * paramMd];
        byte[] qCoeffs = new byte[paramD * (paramWd + 1)];
        inst.pPoly = new byte[paramD * paramWd];

        for (int iD = 0; iD < paramD; ++iD)
        {
            int[] nonZeroPos = new int[paramWd];
            int[] nonZeroVal = new int[paramWd];

            // positions: single byte per attempt, reject if >= md or duplicate.
            int i = 0;
            while (i < paramWd)
            {
                squeeze(entropy, one, 0, 1);
                int p = one[0] & 0xff;
                if (p >= paramMd)
                {
                    continue;
                }
                boolean redundant = false;
                for (int jPos = 0; jPos < i; ++jPos)
                {
                    if (nonZeroPos[jPos] == p)
                    {
                        redundant = true;
                        break;
                    }
                }
                if (!redundant)
                {
                    nonZeroPos[i++] = p;
                }
            }

            // values: for p251, rejection-sample to < 251 per byte; for both
            // fields, reject 0 outer-loop (matches the reference's nested loops).
            i = 0;
            while (i < paramWd)
            {
                int v;
                while (true)
                {
                    squeeze(entropy, one, 0, 1);
                    v = one[0] & 0xff;
                    if (!isP251() || v < 251)
                    {
                        break;
                    }
                }
                if (v == 0)
                {
                    continue;
                }
                nonZeroVal[i++] = v;
            }

            for (int j = 0; j < paramWd; ++j)
            {
                x[iD * paramMd + nonZeroPos[j]] = (byte) nonZeroVal[j];
            }

            byte[] q = new byte[paramWd + 1];
            q[0] = 1;
            for (int ii = 0; ii < paramWd; ++ii)
            {
                int minusPos = fieldByteNeg(nonZeroPos[ii]);
                for (int jj = ii + 1; jj >= 1; --jj)
                {
                    q[jj] = (byte) fieldByteAdd(q[jj - 1] & 0xff, fieldByteMul(minusPos, q[jj] & 0xff));
                }
                q[0] = (byte) fieldByteMul(minusPos, q[0] & 0xff);
            }
            System.arraycopy(q, 0, qCoeffs, iD * (paramWd + 1), paramWd + 1);

            byte[] p = new byte[paramWd];
            byte[] tempF = new byte[paramMd];
            byte[] tempQ = new byte[paramWd];
            byte[] fPoly = getFPoly();
            byte[] ljS = getLeadingCoefficientsLjForS();

            for (int ii = 0; ii < paramMd; ++ii)
            {
                // No skip for zero positions: the zero/non-zero pattern of x IS
                // the SD secret (the non-zero support), so the Lagrange
                // accumulation must run uniformly over all md positions, as the
                // C reference does. A zero x_i yields scalar = 0 and the
                // multiply-accumulate contributes nothing.
                int xi = x[iD * paramMd + ii] & 0xff;
                int scalar = fieldByteMul(ljS[ii] & 0xff, xi);

                removeOneDegreeFactorFromMonic(tempF, fPoly, paramMd, ii);
                for (int jj = 0; jj < paramMd; ++jj)
                {
                    int sIdx = iD * paramMd + jj;
                    s[sIdx] = (byte) fieldByteAdd(s[sIdx] & 0xff, fieldByteMul(tempF[jj] & 0xff, scalar));
                }

                removeOneDegreeFactorFromMonic(tempQ, q, paramWd, ii);
                for (int jj = 0; jj < paramWd; ++jj)
                {
                    p[jj] = (byte) fieldByteAdd(p[jj] & 0xff, fieldByteMul(tempQ[jj] & 0xff, scalar));
                }
            }
            System.arraycopy(p, 0, inst.pPoly, iD * paramWd, paramWd);
        }

        // q_poly storage: non-leading coefficients only.
        inst.qPoly = new byte[paramD * paramWd];
        for (int iD = 0; iD < paramD; ++iD)
        {
            System.arraycopy(qCoeffs, iD * (paramWd + 1), inst.qPoly, iD * paramWd, paramWd);
        }

        // Split s into s_A || s_B.
        inst.sA = Arrays.copyOfRange(s, 0, paramK);
        byte[] sB = Arrays.copyOfRange(s, paramK, paramK + paramYSize);

        // H_a seed: raw bytes (no rejection sampling).
        byte[] hASeed = new byte[seedSize];
        squeeze(entropy, hASeed, 0, seedSize);
        inst.hASeed = hASeed;

        // H_a matrix derived from hASeed (fresh XOF, with rejection sampling for p251).
        byte[] hAFlat = new byte[paramK * paramYSize];
        SHAKEDigest hARng = newXof(hASeed, 0, seedSize);
        squeezeFieldBytes(hARng, hAFlat, 0, hAFlat.length);

        inst.hA = new byte[paramHaNSlice][];
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            inst.hA[slice] = new byte[paramK * 128];
        }
        for (int j = 0; j < paramK; ++j)
        {
            int rowOff = j * paramYSize;
            for (int slice = 0; slice < paramHaNSlice - 1; ++slice)
            {
                System.arraycopy(hAFlat, rowOff + slice * 128, inst.hA[slice], j * 128, 128);
            }
            int remaining = paramYSize - (paramHaNSlice - 1) * 128;
            System.arraycopy(hAFlat, rowOff + (paramHaNSlice - 1) * 128, inst.hA[paramHaNSlice - 1], j * 128, remaining);
        }

        // y = s_B + H s_A per slice. The threshold reference uses the standard SD
        // equation y - H s_A = s_B (i.e. y = s_B + H s_A), without negation of
        // s_A — different from the hypercube reference which uses y = s_B - H s_A
        // and therefore negates s_A in p251.
        byte[] yFlat = new byte[paramHaNSlice * 128];
        System.arraycopy(sB, 0, yFlat, 0, sB.length);
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            vecMatNColsMulAdd(yFlat, slice * 128, inst.sA, 0, inst.hA[slice], 0, paramK, 128);
        }
        inst.y = Arrays.copyOfRange(yFlat, 0, paramYSize);

        return inst;
    }

    /**
     * Variant-aware key pair generation. For threshold variants this delegates
     * to {@link #generateIsdInstanceForThreshold(byte[])} (per-byte interleaved
     * sampling) so the resulting bytes match the reference C signer.
     */
    public byte[][] generateKeyPairThreshold()
    {
        byte[] mSeed = new byte[seedSize];
        random.nextBytes(mSeed);
        IsdInstance inst = generateIsdInstanceForThreshold(mSeed);
        byte[] pk = Arrays.concatenate(inst.hASeed, inst.y);
        byte[] sk = Arrays.concatenate(new byte[][]{inst.hASeed, inst.y, inst.sA, inst.qPoly, inst.pPoly});
        return new byte[][]{pk, sk, mSeed};
    }

    IsdInstance generateIsdInstance(byte[] mSeed)
    {
        IsdInstance inst = new IsdInstance();
        // GF(256) keygen takes one 8192-byte regular-XOF tape and consumes it for
        // both positions and values. GF(p251) keygen splits into two 4096-byte tapes:
        // valueTape is rejection-sampled to bytes < 251, posTape is regular bytes used
        // for position sampling (mod m/d) and the H_a seed.
        SHAKEDigest rng = newXof(mSeed, 0, seedSize);
        byte[] valueTape;
        byte[] posTape;
        if (isP251())
        {
            valueTape = new byte[4096];
            squeezeFieldBytes(rng, valueTape, 0, 4096);
            posTape = new byte[4096];
            squeeze(rng, posTape, 0, 4096);
        }
        else
        {
            byte[] one = new byte[8192];
            squeeze(rng, one, 0, one.length);
            posTape = one;
            valueTape = one;  // shared — gf256 keygen uses one tape for both
        }
        int posIdx = 0;
        int valIdx = 0;
        // x[d][md], laid out row-major
        byte[] x = new byte[paramD * paramMd];
        // s[d][md]
        byte[] s = new byte[paramD * paramMd];
        // q[wd + 1] per twist (monic of degree wd)
        byte[] qCoeffs = new byte[paramD * (paramWd + 1)];
        inst.pPoly = new byte[paramD * paramWd];

        for (int iD = 0; iD < paramD; ++iD)
        {
            int[] nonZeroPos = new int[paramWd];
            int[] nonZeroVal = new int[paramWd];

            int i = 0;
            while (i < paramWd)
            {
                int p = posTape[posIdx++] & 0xff;
                if (p >= paramMd)
                {
                    continue;
                }
                boolean redundant = false;
                for (int jPos = 0; jPos < i; ++jPos)
                {
                    if (nonZeroPos[jPos] == p)
                    {
                        redundant = true;
                        break;
                    }
                }
                if (!redundant)
                {
                    nonZeroPos[i++] = p;
                }
            }

            // For GF(256) the value bytes follow the position bytes in the SAME tape;
            // sync the value cursor to the position cursor before reading values.
            if (!isP251())
            {
                valIdx = posIdx;
            }

            i = 0;
            while (i < paramWd)
            {
                int v = valueTape[valIdx++] & 0xff;
                if (v == 0)
                {
                    continue;
                }
                nonZeroVal[i++] = v;
            }

            // For GF(256), sync position cursor back so the next twist reads from
            // the byte just past this twist's last value sample.
            if (!isP251())
            {
                posIdx = valIdx;
            }

            // Reconstruct x: x[i_d][nonZeroPos[j]] = nonZeroVal[j]
            for (int j = 0; j < paramWd; ++j)
            {
                x[iD * paramMd + nonZeroPos[j]] = (byte) nonZeroVal[j];
            }

            // Build q polynomial: q(X) = prod_{j} (X - nonZeroPos[j]).
            // The "X - alpha" factor is implemented by multiplying coefficients by
            // (-alpha) — for GF(256) negation is the identity, but for GF(p251)
            // we must explicitly negate.
            byte[] q = new byte[paramWd + 1];
            q[0] = 1;
            for (int ii = 0; ii < paramWd; ++ii)
            {
                int minusPos = fieldByteNeg(nonZeroPos[ii]);
                for (int jj = ii + 1; jj >= 1; --jj)
                {
                    q[jj] = (byte) fieldByteAdd(q[jj - 1] & 0xff, fieldByteMul(minusPos, q[jj] & 0xff));
                }
                q[0] = (byte) fieldByteMul(minusPos, q[0] & 0xff);
            }
            System.arraycopy(q, 0, qCoeffs, iD * (paramWd + 1), paramWd + 1);

            // p polynomial accumulator (length wd; degree at most wd-1).
            byte[] p = new byte[paramWd];

            // For each position i in 0..md-1, accumulate L_i(0) * x_i * F(X)/(X - i) into s,
            // and L_i(0) * x_i * Q(X)/(X - i) into p.
            byte[] tempF = new byte[paramMd];
            byte[] tempQ = new byte[paramWd];
            byte[] fPoly = getFPoly();
            byte[] ljS = getLeadingCoefficientsLjForS();

            for (int ii = 0; ii < paramMd; ++ii)
            {
                // No skip for zero positions: the zero/non-zero pattern of x IS
                // the SD secret (the non-zero support), so the Lagrange
                // accumulation must run uniformly over all md positions, as the
                // C reference does. A zero x_i yields scalar = 0 and the
                // multiply-accumulate contributes nothing.
                int xi = x[iD * paramMd + ii] & 0xff;
                int scalar = fieldByteMul(ljS[ii] & 0xff, xi);

                removeOneDegreeFactorFromMonic(tempF, fPoly, paramMd, ii);
                for (int jj = 0; jj < paramMd; ++jj)
                {
                    int sIdx = iD * paramMd + jj;
                    s[sIdx] = (byte) fieldByteAdd(s[sIdx] & 0xff, fieldByteMul(tempF[jj] & 0xff, scalar));
                }

                removeOneDegreeFactorFromMonic(tempQ, q, paramWd, ii);
                for (int jj = 0; jj < paramWd; ++jj)
                {
                    p[jj] = (byte) fieldByteAdd(p[jj] & 0xff, fieldByteMul(tempQ[jj] & 0xff, scalar));
                }
            }
            System.arraycopy(p, 0, inst.pPoly, iD * paramWd, paramWd);
        }

        // q_poly storage in the secret key is the non-leading coefficients only — the C reference
        // memcpys [PAR_wd] bytes from a [PAR_wd+1]-byte buffer where the leading coefficient (q[wd]=1)
        // is implicit. Match that layout.
        inst.qPoly = new byte[paramD * paramWd];
        for (int iD = 0; iD < paramD; ++iD)
        {
            System.arraycopy(qCoeffs, iD * (paramWd + 1), inst.qPoly, iD * paramWd, paramWd);
        }

        // Split s into s_A (first k bytes) || s_B (last m-k bytes).
        inst.sA = Arrays.copyOfRange(s, 0, paramK);
        byte[] sB = Arrays.copyOfRange(s, paramK, paramK + paramYSize);

        // Read H_a_seed from the position tape (which is the only random source for gf256,
        // and the regular-bytes tape for p251), then expand H_a via a fresh XOF.
        byte[] hASeed = new byte[seedSize];
        System.arraycopy(posTape, posIdx, hASeed, 0, seedSize);
        inst.hASeed = hASeed;

        // H_a[k][m-k] flat — squeezed as field bytes (mod-251 sampling for p251).
        byte[] hAFlat = new byte[paramK * paramYSize];
        SHAKEDigest hARng = newXof(hASeed, 0, seedSize);
        squeezeFieldBytes(hARng, hAFlat, 0, hAFlat.length);

        // Slice H_a row-major as [ha_nslice][k][128], zero-padding the last slice.
        inst.hA = new byte[paramHaNSlice][];
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            inst.hA[slice] = new byte[paramK * 128];
        }
        for (int j = 0; j < paramK; ++j)
        {
            int rowOff = j * paramYSize;
            for (int slice = 0; slice < paramHaNSlice - 1; ++slice)
            {
                System.arraycopy(hAFlat, rowOff + slice * 128, inst.hA[slice], j * 128, 128);
            }
            int remaining = paramYSize - (paramHaNSlice - 1) * 128;
            System.arraycopy(hAFlat, rowOff + (paramHaNSlice - 1) * 128, inst.hA[paramHaNSlice - 1], j * 128, remaining);
        }

        // y = s_B + ε * s_A * H_a (per slice).
        // GF(256): ε = +1 (XOR is self-inverse, so addition = subtraction).
        // GF(p251): ε = -1 (compute -s_A first, since the SD equation rearranges as
        //                   y - s_A·H_a = s_B → y = s_B + (-s_A)·H_a).
        byte[] sAForY;
        if (isP251())
        {
            sAForY = new byte[paramK];
            for (int k = 0; k < paramK; ++k)
            {
                sAForY[k] = (byte) fieldByteNeg(inst.sA[k] & 0xff);
            }
        }
        else
        {
            sAForY = inst.sA;
        }

        byte[] yFlat = new byte[paramHaNSlice * 128];
        System.arraycopy(sB, 0, yFlat, 0, sB.length);
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            vecMatNColsMulAdd(yFlat, slice * 128, sAForY, 0, inst.hA[slice], 0, paramK, 128);
        }
        inst.y = Arrays.copyOfRange(yFlat, 0, paramYSize);

        return inst;
    }

    private byte[] getFPoly()
    {
        if (isP251())
        {
            switch (params.getCategory())
            {
                case 1:
                    return SDitHPrecomputed.F_POLY_P251_CAT1;
                case 3:
                    return SDitHPrecomputed.F_POLY_P251_CAT3;
                case 5:
                    return SDitHPrecomputed.F_POLY_P251_CAT5;
            }
        }
        else
        {
            switch (params.getCategory())
            {
                case 1:
                    return SDitHPrecomputed.F_POLY_CAT1;
                case 3:
                    return SDitHPrecomputed.F_POLY_CAT3;
                case 5:
                    return SDitHPrecomputed.F_POLY_CAT5;
            }
        }
        throw new IllegalStateException("unknown SDitH parameter set: " + params.getName());
    }

    private byte[] getLeadingCoefficientsLjForS()
    {
        if (isP251())
        {
            switch (params.getCategory())
            {
                case 1:
                    return SDitHPrecomputed.LEADING_COEFFICIENTS_OF_LJ_FOR_S_P251_CAT1;
                case 3:
                    return SDitHPrecomputed.LEADING_COEFFICIENTS_OF_LJ_FOR_S_P251_CAT3;
                case 5:
                    return SDitHPrecomputed.LEADING_COEFFICIENTS_OF_LJ_FOR_S_P251_CAT5;
            }
        }
        else
        {
            switch (params.getCategory())
            {
                case 1:
                    return SDitHPrecomputed.LEADING_COEFFICIENTS_OF_LJ_FOR_S_CAT1;
                case 3:
                    return SDitHPrecomputed.LEADING_COEFFICIENTS_OF_LJ_FOR_S_CAT3;
                case 5:
                    return SDitHPrecomputed.LEADING_COEFFICIENTS_OF_LJ_FOR_S_CAT5;
            }
        }
        throw new IllegalStateException("unknown SDitH parameter set: " + params.getName());
    }

    /**
     * Synthetic division by (X - alpha). If P_in is monic of degree {@code inDegree}
     * (so {@code in} has {@code inDegree+1} coefficients) and (X - alpha) divides P_in,
     * writes P_in / (X - alpha) into {@code out} — a monic polynomial of degree
     * {@code inDegree - 1}, taking {@code inDegree} slots. The last slot of {@code out}
     * holds the new leading coefficient (1).
     */
    private void removeOneDegreeFactorFromMonic(byte[] out, byte[] in, int inDegree, int alpha)
    {
        out[inDegree - 1] = 1;
        for (int i = inDegree - 2; i >= 0; --i)
        {
            out[i] = (byte) fieldByteAdd(in[i + 1] & 0xff, fieldByteMul(alpha, out[i + 1] & 0xff));
        }
    }

    /**
     * Expand the public key's compressed form back into a usable H_a matrix.
     */
    byte[][] expandHa(byte[] hASeed)
    {
        byte[] hAFlat = new byte[paramK * paramYSize];
        SHAKEDigest hARng = newXof(hASeed, 0, seedSize);
        squeezeFieldBytes(hARng, hAFlat, 0, hAFlat.length);
        byte[][] hA = new byte[paramHaNSlice][];
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            hA[slice] = new byte[paramK * 128];
        }
        for (int j = 0; j < paramK; ++j)
        {
            int rowOff = j * paramYSize;
            for (int slice = 0; slice < paramHaNSlice - 1; ++slice)
            {
                System.arraycopy(hAFlat, rowOff + slice * 128, hA[slice], j * 128, 128);
            }
            int remaining = paramYSize - (paramHaNSlice - 1) * 128;
            System.arraycopy(hAFlat, rowOff + (paramHaNSlice - 1) * 128, hA[paramHaNSlice - 1], j * 128, remaining);
        }
        return hA;
    }

    // ===== signing & verification =====
    // The hot-path of sign / verify is broken into helpers that mirror the C
    // reference closely so each section can be cross-checked against the source.

    /**
     * Holds the per-iteration sign-side state (aux share, sum share, full seeds /
     * commits, salt). Allocated once per sign call.
     */
    private final class SignCtx
    {
        byte[] salt = new byte[saltSize];
        SDitHHash h1Hash;
        byte[][] aux = new byte[paramTau][];
        byte[][] sumShares = new byte[paramTau][];
        byte[][][] mainPartyShares = new byte[paramTau][paramDimD][];
        byte[][] rootSeeds = new byte[paramTau][];
        byte[][][] allSeeds;        // [tau][2^(D+1)] seeds, layout: nodes 1..2^(D+1)-1 stored at index node-1
        byte[][][] allCommits;      // [tau][2^D] commitments
    }

    /**
     * Sign a message. Returns the raw signature bytes (no message appended).
     * <p>
     * The reference defines the signed-message format as {@code sig || msg};
     * the higher-level API in this module returns just the signature and lets
     * the caller decide whether to prepend/append the message.
     */
    public byte[] sign(SDitHPrivateKeyExpanded sk, byte[] msg, int msgOff, int msgLen)
    {
        SignCtx ctx = new SignCtx();
        signOffline(ctx, sk);
        return signOnline(ctx, sk, msg, msgOff, msgLen);
    }

    /**
     * Verify a signature against a message. Returns true iff valid.
     */
    public boolean verify(SDitHPublicKeyExpanded pk, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff, int sigLen)
    {
        if (sigLen != signatureSize())
        {
            return false;
        }
        return doVerify(pk, msg, msgOff, msgLen, sig, sigOff);
    }

    /**
     * Returns the fixed signature byte size for the current parameter set.
     */
    public int signatureSize()
    {
        int treeSeeds = paramTau * paramDimD * seedSize;
        int coms = paramTau * commitSize;
        int auxes = paramTau * auxSize;
        int alphas = paramTau * alphaBetaBytes;
        int betas = paramTau * alphaBetaBytes;
        return saltSize + hashSize + treeSeeds + coms + auxes + alphas + betas;
    }

    private void signOffline(SignCtx ctx, SDitHPrivateKeyExpanded sk)
    {
        random.nextBytes(ctx.salt);

        ctx.h1Hash = SDitHHash.sha3(hashBits, SDitHHash.HASH_H1);
        ctx.h1Hash.update(sk.hASeed, 0, seedSize);
        ctx.h1Hash.update(ctx.salt, 0, saltSize);

        // Allocate per-iteration arrays.
        for (int e = 0; e < paramTau; ++e)
        {
            ctx.aux[e] = new byte[shareSize];
            ctx.sumShares[e] = new byte[shareSize];
            for (int d = 0; d < paramDimD; ++d)
            {
                ctx.mainPartyShares[e][d] = new byte[shareSize];
            }
            ctx.rootSeeds[e] = new byte[seedSize];
            random.nextBytes(ctx.rootSeeds[e]);
        }

        // Full-tree storage (matches FULL_TREE feature define).
        int numNodes = (1 << (paramDimD + 1));
        int numLeafs = (1 << paramDimD);
        ctx.allSeeds = new byte[paramTau][numNodes][seedSize];
        ctx.allCommits = new byte[paramTau][numLeafs][commitSize];

        for (int e = 0; e < paramTau; ++e)
        {
            expandSeedTreeBfs(sk, ctx.rootSeeds[e], ctx.salt, ctx.h1Hash, e,
                    ctx.aux[e], ctx.sumShares[e], ctx.mainPartyShares[e],
                    ctx.allSeeds[e], ctx.allCommits[e]);
        }
    }

    private byte[] signOnline(SignCtx ctx, SDitHPrivateKeyExpanded sk, byte[] msg, int msgOff, int msgLen)
    {
        // IDS_3_ROUND defined: H1 does NOT absorb msg; only the H2 hash does.
        byte[] h1 = new byte[hashSize];
        ctx.h1Hash.doFinal(h1, 0);

        SDitHHash h2Hash = SDitHHash.sha3(hashBits, SDitHHash.HASH_H2);
        h2Hash.update(msg, msgOff, msgLen);
        h2Hash.update(ctx.salt, 0, saltSize);
        h2Hash.update(h1, 0, hashSize);

        // Sample r, eps from h1.
        int[][][] r = new int[paramTau][paramD][paramT];
        int[][][] eps = new int[paramTau][paramD][paramT];
        sampleChallenge(h1, r, eps);

        // Precompute MPC helpers.
        MpcHelper[][] helpers = buildHelpers(r, eps);

        int[][][] alpha = new int[paramTau][paramD][paramT];
        int[][][] beta = new int[paramTau][paramD][paramT];

        SDitHPublicKeyExpanded pk = new SDitHPublicKeyExpanded();
        pk.hASeed = sk.hASeed;
        pk.y = sk.y;
        pk.hA = sk.hA;

        for (int e = 0; e < paramTau; ++e)
        {
            mpcPlainBroadcasts(ctx.sumShares[e], helpers[e], pk, alpha[e], beta[e]);

            // Absorb full-precision alpha and beta (as uint32_t) into H2.
            byte[] tmp = new byte[paramD * paramT * 4];
            packIntsLE(alpha[e], tmp);
            h2Hash.update(tmp, 0, tmp.length);
            packIntsLE(beta[e], tmp);
            h2Hash.update(tmp, 0, tmp.length);

            for (int i = 0; i < paramDimD; ++i)
            {
                int[][] shA = new int[paramD][paramT];
                int[][] shB = new int[paramD][paramT];
                int[] shV = new int[paramT];
                mpcCommunications(ctx.mainPartyShares[e][i], false, helpers[e], pk,
                        alpha[e], beta[e], shA, shB, shV);

                // Absorb sh_alpha[0], sh_beta[0], sh_v[0].
                packIntsLE(shA, tmp);
                h2Hash.update(tmp, 0, tmp.length);
                packIntsLE(shB, tmp);
                h2Hash.update(tmp, 0, tmp.length);
                byte[] tmpv = new byte[paramT * 4];
                packIntsLE(shV, tmpv);
                h2Hash.update(tmpv, 0, tmpv.length);
            }
        }

        byte[] h2 = new byte[hashSize];
        h2Hash.doFinal(h2, 0);

        // Sample challenge from h2 — 8 bytes (uint64_t) per iteration in the reference.
        SHAKEDigest chalPrg = newXof(h2, 0, hashSize);
        byte[] chalBytes = new byte[paramTau * 8];
        squeeze(chalPrg, chalBytes, 0, chalBytes.length);
        int chalMask = (1 << paramDimD) - 1;

        // Layout the signature bytes.
        byte[] sig = new byte[signatureSize()];
        int sigOff = 0;
        System.arraycopy(ctx.salt, 0, sig, sigOff, saltSize);
        sigOff += saltSize;
        System.arraycopy(h2, 0, sig, sigOff, hashSize);
        sigOff += hashSize;

        int treePrgSeedsOff = sigOff;
        sigOff += paramTau * paramDimD * seedSize;
        int commitsOff = sigOff;
        sigOff += paramTau * commitSize;
        int auxOff = sigOff;
        sigOff += paramTau * auxSize;
        int alphaOff = sigOff;
        sigOff += paramTau * alphaBetaBytes;
        int betaOff = sigOff;

        for (int e = 0; e < paramTau; ++e)
        {
            // chal_party = chal[e] (uint64_t, little-endian) & chal_mask
            long chalE = readUint64LE(chalBytes, e * 8);
            int challenge = (int) (chalE & chalMask);

            if (challenge != chalMask)
            {
                writeAux(sig, auxOff + e * auxSize, ctx.aux[e]);
            }
            // else: aux for this iteration is left zero (no leak).

            walkFullTreePrgBfs(ctx.allSeeds[e], ctx.allCommits[e], challenge,
                    sig, treePrgSeedsOff + e * paramDimD * seedSize,
                    sig, commitsOff + e * commitSize);
        }

        // compressed_alpha[e][i_d][i_t]: take fpointSize lowest bytes of each uint32_t.
        compressedPack(alpha, sig, alphaOff);
        compressedPack(beta, sig, betaOff);

        return sig;
    }

    // ===== signing helpers =====

    private void expandSeedTreeBfs(SDitHPrivateKeyExpanded sk, byte[] rootSeed, byte[] salt,
                                   SDitHHash msgCommit, int iteration,
                                   byte[] aux, byte[] sumShare,
                                   byte[][] mainPartyShares,
                                   byte[][] seeds, byte[][] commits)
    {
        int numLeafs = 1 << paramDimD;
        // Layout: seeds[0] = root, seeds[1..2] = level 1, etc.; total 2*numLeafs entries used.
        System.arraycopy(rootSeed, 0, seeds[0], 0, seedSize);

        SDitHTreePrg tree = new SDitHTreePrg(hashBits, seedSize, salt);
        // Concatenate seeds into a flat buffer for the BFS expand. Each level lives at
        // contiguous indices starting at the level's first-tweak position.
        int prevOff = 0;
        int curOff = 1;
        int curN = 2;
        int firstTweak = 1;
        for (int d = 1; d <= paramDimD; ++d)
        {
            byte[] inFlat = new byte[(curN / 2) * seedSize];
            for (int i = 0; i < curN / 2; ++i)
            {
                System.arraycopy(seeds[prevOff + i], 0, inFlat, i * seedSize, seedSize);
            }
            byte[] outFlat = new byte[curN * seedSize];
            tree.seedExpand(outFlat, 0, inFlat, 0, firstTweak, iteration, curN);
            for (int i = 0; i < curN; ++i)
            {
                System.arraycopy(outFlat, i * seedSize, seeds[curOff + i], 0, seedSize);
            }
            prevOff = curOff;
            curOff = prevOff + curN;
            curN <<= 1;
            firstTweak <<= 1;
        }

        int leafLevelOff = prevOff;
        byte[] curShare = new byte[shareSize];
        for (int i = 0; i < numLeafs - 1; ++i)
        {
            byte[] leafSeed = seeds[leafLevelOff + i];
            commitLeaf(commits[i], leafSeed, salt, iteration, i);

            expandShareFromSeed(curShare, leafSeed);
            shareAccumulate(aux, curShare);
            // main_party_shares[j][0] gets each share where bit-(D-1-j) of i is 0.
            for (int j = 0; j < paramDimD; ++j)
            {
                if (((i >> (paramDimD - 1 - j)) & 1) == 0)
                {
                    shareAccumulate(mainPartyShares[j], curShare);
                }
            }
        }

        // Last leaf — special handling: only a/b/c are random; s_A/q/p are derived from sk.
        java.util.Arrays.fill(curShare, (byte) 0);
        byte[] leafLast = seeds[leafLevelOff + numLeafs - 1];
        expandLastShareFromSeed(curShare, leafLast);
        shareAccumulate(aux, curShare);
        // Build the sum_share = sk-style plaintext for s_A, q, p
        System.arraycopy(sk.sA, 0, sumShare, shareSA, paramK);
        System.arraycopy(sk.qPoly, 0, sumShare, shareQ, paramD * paramWd);
        System.arraycopy(sk.pPoly, 0, sumShare, shareP, paramD * paramWd);

        // cur_share.c[i] = (sum_{i_d} aux.a[i_d][i] * aux.b[i_d][i]) - aux.c[i]
        // (XOR for GF(256), mod-251 subtraction for GF(p251))
        for (int i = 0; i < paramT; ++i)
        {
            int dotAb = 0;
            for (int iD = 0; iD < paramD; ++iD)
            {
                int a = readField32(aux, shareA + (iD * paramT + i) * 4) & fpointMask();
                int b = readField32(aux, shareB + (iD * paramT + i) * 4) & fpointMask();
                writeField32(sumShare, shareA + (iD * paramT + i) * 4, a);
                writeField32(sumShare, shareB + (iD * paramT + i) * 4, b);
                dotAb = fpointAdd(dotAb, fpointMul(a, b));
            }
            int auxC = readField32(aux, shareC + i * 4) & fpointMask();
            writeField32(curShare, shareC + i * 4, fpointSub(dotAb, auxC));
        }

        // cur_share.s_A = sk.s_A - aux.s_A; cur_share.q = sk.q - aux.q; cur_share.p = sk.p - aux.p
        // (operand order matters for GF(p251) — XOR is order-agnostic for GF(256))
        for (int b = 0; b < paramK; ++b)
        {
            curShare[shareSA + b] = (byte) fieldByteSub(sk.sA[b] & 0xff, aux[shareSA + b] & 0xff);
        }
        int qpLen = paramD * paramWd;
        for (int b = 0; b < qpLen; ++b)
        {
            curShare[shareQ + b] = (byte) fieldByteSub(sk.qPoly[b] & 0xff, aux[shareQ + b] & 0xff);
            curShare[shareP + b] = (byte) fieldByteSub(sk.pPoly[b] & 0xff, aux[shareP + b] & 0xff);
        }
        // aux <- cur_share (the corrected last leaf becomes the published aux).
        System.arraycopy(curShare, 0, aux, 0, shareSize);

        commitLastLeaf(commits[numLeafs - 1], leafLast, aux, salt, iteration);

        // Absorb commits into H1.
        for (int i = 0; i < numLeafs; ++i)
        {
            msgCommit.update(commits[i], 0, commitSize);
        }
    }

    private void commitLeaf(byte[] outCommit, byte[] leafSeed, byte[] salt, int iteration, int leafIdx)
    {
        SDitHHash h = SDitHHash.sha3(hashBits, SDitHHash.HASH_COM);
        h.update(salt, 0, saltSize);
        h.update((byte) (iteration & 0xff));
        h.update((byte) ((iteration >> 8) & 0xff));
        h.update((byte) (leafIdx & 0xff));
        h.update((byte) ((leafIdx >> 8) & 0xff));
        h.update(leafSeed, 0, seedSize);
        h.doFinal(outCommit, 0);
    }

    private void commitLastLeaf(byte[] outCommit, byte[] leafSeed, byte[] aux, byte[] salt, int iteration)
    {
        SDitHHash h = SDitHHash.sha3(hashBits, SDitHHash.HASH_COM);
        h.update(salt, 0, saltSize);
        h.update((byte) (iteration & 0xff));
        h.update((byte) ((iteration >> 8) & 0xff));
        int leafIdx = (1 << paramDimD) - 1;
        h.update((byte) (leafIdx & 0xff));
        h.update((byte) ((leafIdx >> 8) & 0xff));
        h.update(leafSeed, 0, seedSize);
        // The reference absorbs (s_A || q_poly || p_poly) followed by c[t] of uint32_t.
        h.update(aux, shareSA, paramK + 2 * paramD * paramWd);
        h.update(aux, shareC, paramT * 4);
        h.doFinal(outCommit, 0);
    }

    private void expandShareFromSeed(byte[] outShare, byte[] seed)
    {
        SHAKEDigest x = newXof(seed, 0, seedSize);
        // For p251 every byte of the share struct — including the bytes that pack the
        // uint32_t a/b/c arrays — is rejection-sampled to be < 251; the field-element
        // mask is then applied to those packed words. GF(256) just takes raw XOF bytes.
        squeezeFieldBytes(x, outShare, 0, shareSize);
        // Mask a, b, c to fpointSize bytes (reference does the same after the squeeze).
        int mask = fpointMask();
        for (int iD = 0; iD < paramD; ++iD)
        {
            for (int i = 0; i < paramT; ++i)
            {
                int v = readField32(outShare, shareA + (iD * paramT + i) * 4) & mask;
                writeField32(outShare, shareA + (iD * paramT + i) * 4, v);
                v = readField32(outShare, shareB + (iD * paramT + i) * 4) & mask;
                writeField32(outShare, shareB + (iD * paramT + i) * 4, v);
            }
        }
        for (int i = 0; i < paramT; ++i)
        {
            int v = readField32(outShare, shareC + i * 4) & mask;
            writeField32(outShare, shareC + i * 4, v);
        }
    }

    /**
     * Only the a/b blocks come from the seed; s_A/q/p/c are derived in-place later.
     */
    private void expandLastShareFromSeed(byte[] outShare, byte[] seed)
    {
        SHAKEDigest x = newXof(seed, 0, seedSize);
        int abBytes = paramD * paramT * 2 * 4;
        byte[] tmp = new byte[abBytes];
        squeezeFieldBytes(x, tmp, 0, abBytes);
        System.arraycopy(tmp, 0, outShare, shareA, abBytes);
        int mask = fpointMask();
        for (int iD = 0; iD < paramD; ++iD)
        {
            for (int i = 0; i < paramT; ++i)
            {
                int v = readField32(outShare, shareA + (iD * paramT + i) * 4) & mask;
                writeField32(outShare, shareA + (iD * paramT + i) * 4, v);
                v = readField32(outShare, shareB + (iD * paramT + i) * 4) & mask;
                writeField32(outShare, shareB + (iD * paramT + i) * 4, v);
            }
        }
    }

    private void walkFullTreePrgBfs(byte[][] seeds, byte[][] commits, int path,
                                    byte[] sigSeeds, int sigSeedsOff,
                                    byte[] sigCom, int sigComOff)
    {
        int pp = path ^ 1;
        for (int j = 0; j < paramDimD; ++j)
        {
            int idx = (1 << (paramDimD - j)) - 1 + pp;
            System.arraycopy(seeds[idx], 0, sigSeeds, sigSeedsOff + (paramDimD - j - 1) * seedSize, seedSize);
            pp = (pp >> 1) ^ 1;
        }
        System.arraycopy(commits[path], 0, sigCom, sigComOff, commitSize);
    }

    // ===== MPC helpers =====

    private static final class MpcHelper
    {
        /**
         * compressed_pow_r[p][16] — for each evaluation point t, log(r^p) ⊕ packing.
         */
        byte[][] compressedPowR;
        byte[][] compressedEpsPowR;
        int[] epsFr;
    }

    private MpcHelper[][] buildHelpers(int[][][] r, int[][][] eps)
    {
        MpcHelper[][] out = new MpcHelper[paramTau][paramD];
        byte[] fPoly = getFPoly();
        for (int e = 0; e < paramTau; ++e)
        {
            for (int iD = 0; iD < paramD; ++iD)
            {
                MpcHelper h = new MpcHelper();
                h.compressedPowR = new byte[paramMd + 1][16];
                h.compressedEpsPowR = new byte[paramMd + 1][16];
                h.epsFr = new int[paramT];
                for (int iT = 0; iT < paramT; ++iT)
                {
                    int logEps = fpointDlog(eps[e][iD][iT]);
                    int logR = fpointDlog(r[e][iD][iT]);
                    for (int p = 0; p < paramMd + 1; ++p)
                    {
                        int logRp = fpointDlogPow(logR, p);
                        int epsRp = fpointDexp(fpointDlogMul(logEps, logRp));
                        int rp = fpointDexp(logRp);
                        // pack fpointSize bytes of rp at offset iT * fpointSize
                        for (int b = 0; b < fpointSize; ++b)
                        {
                            h.compressedPowR[p][iT * fpointSize + b] = (byte) ((rp >>> (b * 8)) & 0xff);
                            h.compressedEpsPowR[p][iT * fpointSize + b] = (byte) ((epsRp >>> (b * 8)) & 0xff);
                        }
                    }
                }
                // eps_f_r = f_poly · compressedEpsPowR — produces 16 bytes (4 fpoint ints).
                // The reference uses gf256_vec_mat16cols_muladd / p251_vec_mat16cols_muladd
                // (which folds the row-accumulator and the final reduction together).
                byte[] epsFrBytes = new byte[16];
                byte[] flat = new byte[(paramMd + 1) * 16];
                for (int p = 0; p < paramMd + 1; ++p)
                {
                    System.arraycopy(h.compressedEpsPowR[p], 0, flat, p * 16, 16);
                }
                vecMat16ColsMulAdd(epsFrBytes, 0, fPoly, 0, flat, 0, paramMd + 1);
                for (int iT = 0; iT < paramT; ++iT)
                {
                    int v = 0;
                    for (int b = 0; b < fpointSize; ++b)
                    {
                        v |= (epsFrBytes[iT * fpointSize + b] & 0xff) << (b * 8);
                    }
                    h.epsFr[iT] = v;
                }
                out[e][iD] = h;
            }
        }
        return out;
    }

    private void sampleChallenge(byte[] h1, int[][][] r, int[][][] eps)
    {
        SHAKEDigest x = newXof(h1, 0, hashSize);
        int rBytes = paramTau * paramD * paramT * 4;
        byte[] tmp = new byte[rBytes];
        // Sample r — GF(256) just raw squeeze, GF(p251) rejection-samples to bytes < 251.
        squeezeFieldBytes(x, tmp, 0, rBytes);
        int p = 0;
        for (int e = 0; e < paramTau; ++e)
        {
            for (int iD = 0; iD < paramD; ++iD)
            {
                for (int iT = 0; iT < paramT; ++iT)
                {
                    r[e][iD][iT] = readField32(tmp, p) & fpointMask();
                    p += 4;
                }
            }
        }
        squeezeFieldBytes(x, tmp, 0, rBytes);
        p = 0;
        for (int e = 0; e < paramTau; ++e)
        {
            for (int iD = 0; iD < paramD; ++iD)
            {
                for (int iT = 0; iT < paramT; ++iT)
                {
                    eps[e][iD][iT] = readField32(tmp, p) & fpointMask();
                    p += 4;
                }
            }
        }
    }

    private void mpcPlainBroadcasts(byte[] share, MpcHelper[] helper, SDitHPublicKeyExpanded pk,
                                    int[][] alpha, int[][] beta)
    {
        // Build x = s_A || s_B, where s_B = y XOR s_A·H_a (matches the C path).
        byte[] x = new byte[paramK + paramHaNSlice * 128];
        System.arraycopy(share, shareSA, x, 0, paramK);
        System.arraycopy(pk.y, 0, x, paramK, paramYSize);
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            vecMatNColsMulAdd(x, paramK + slice * 128, share, shareSA, pk.hA[slice], 0, paramK, 128);
        }

        for (int iD = 0; iD < paramD; ++iD)
        {
            // compressed_s_r = x[iD*md..] · helper.compressed_pow_r[0..md-1]
            byte[] flatPow = flattenCompressed(helper[iD].compressedPowR, paramMd);
            byte[] compSr = new byte[16];
            vecMat16ColsMulAdd(compSr, 0, x, iD * paramMd, flatPow, 0, paramMd);

            // compressed_alpha = helper.compressed_eps_pow_r[wd] XOR (share.q_poly[iD] · helper.compressed_eps_pow_r[0..wd-1])
            byte[] flatEps = flattenCompressed(helper[iD].compressedEpsPowR, paramWd);
            byte[] compAlpha = new byte[16];
            System.arraycopy(helper[iD].compressedEpsPowR[paramWd], 0, compAlpha, 0, 16);
            vecMat16ColsMulAdd(compAlpha, 0, share, shareQ + iD * paramWd, flatEps, 0, paramWd);

            int[] sr = unpackCompressedRow(compSr);
            int[] al = unpackCompressedRow(compAlpha);
            for (int iT = 0; iT < paramT; ++iT)
            {
                int aShare = readField32(share, shareA + (iD * paramT + iT) * 4) & fpointMask();
                int bShare = readField32(share, shareB + (iD * paramT + iT) * 4) & fpointMask();
                alpha[iD][iT] = fpointAdd(al[iT], aShare);
                beta[iD][iT] = fpointAdd(bShare, sr[iT]);
            }
        }
    }

    private void mpcCommunications(byte[] share, boolean withOffsets, MpcHelper[] helper, SDitHPublicKeyExpanded pk,
                                   int[][] alphas, int[][] betas,
                                   int[][] outAlpha, int[][] outBeta, int[] outV)
    {
        byte[] x = new byte[paramK + paramHaNSlice * 128];
        System.arraycopy(share, shareSA, x, 0, paramK);
        if (withOffsets)
        {
            System.arraycopy(pk.y, 0, x, paramK, paramYSize);
        }
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            vecMatNColsMulAdd(x, paramK + slice * 128, share, shareSA, pk.hA[slice], 0, paramK, 128);
        }

        for (int iT = 0; iT < paramT; ++iT)
        {
            outV[iT] = 0;
        }
        for (int iD = 0; iD < paramD; ++iD)
        {
            byte[] flatPow = flattenCompressed(helper[iD].compressedPowR, paramMd);
            byte[] compSr = new byte[16];
            vecMat16ColsMulAdd(compSr, 0, x, iD * paramMd, flatPow, 0, paramMd);
            int[] sr = unpackCompressedRow(compSr);

            byte[] compAlpha = new byte[16];
            if (withOffsets)
            {
                System.arraycopy(helper[iD].compressedEpsPowR[paramWd], 0, compAlpha, 0, 16);
            }
            byte[] flatEps = flattenCompressed(helper[iD].compressedEpsPowR, paramWd);
            vecMat16ColsMulAdd(compAlpha, 0, share, shareQ + iD * paramWd, flatEps, 0, paramWd);
            int[] al = unpackCompressedRow(compAlpha);

            // sh_p_r = share.p_poly[iD] · helper.compressed_pow_r[0..wd-1]
            byte[] compShPr = new byte[16];
            byte[] flatPowWd = flattenCompressed(helper[iD].compressedPowR, paramWd);
            vecMat16ColsMulAdd(compShPr, 0, share, shareP + iD * paramWd, flatPowWd, 0, paramWd);
            int[] shPr = unpackCompressedRow(compShPr);

            for (int iT = 0; iT < paramT; ++iT)
            {
                int aShare = readField32(share, shareA + (iD * paramT + iT) * 4) & fpointMask();
                int bShare = readField32(share, shareB + (iD * paramT + iT) * 4) & fpointMask();
                outAlpha[iD][iT] = fpointAdd(al[iT], aShare);
                outBeta[iD][iT] = fpointAdd(bShare, sr[iT]);

                int abc = fpointAdd(fpointAdd(fpointMul(shPr[iT], helper[iD].epsFr[iT]),
                                fpointMul(alphas[iD][iT], bShare)),
                        fpointMul(betas[iD][iT], aShare));
                int offset = withOffsets ? fpointMul(alphas[iD][iT], betas[iD][iT]) : 0;
                int v = fpointSub(abc, offset);
                outV[iT] = fpointAdd(outV[iT], v);
            }
        }
        for (int iT = 0; iT < paramT; ++iT)
        {
            int cShare = readField32(share, shareC + iT * 4) & fpointMask();
            outV[iT] = fpointSub(outV[iT], cShare);
        }
    }

    private byte[] flattenCompressed(byte[][] rows, int n)
    {
        byte[] out = new byte[n * 16];
        for (int i = 0; i < n; ++i)
        {
            System.arraycopy(rows[i], 0, out, i * 16, 16);
        }
        return out;
    }

    private int[] unpackCompressedRow(byte[] row)
    {
        int[] out = new int[paramT];
        for (int iT = 0; iT < paramT; ++iT)
        {
            int v = 0;
            for (int b = 0; b < fpointSize; ++b)
            {
                v |= (row[iT * fpointSize + b] & 0xff) << (b * 8);
            }
            out[iT] = v;
        }
        return out;
    }

    // ===== signature byte layout helpers =====

    private void writeAux(byte[] sig, int off, byte[] share)
    {
        // s_A || q_poly || p_poly || c[t] (c is t * fpointSize bytes in the on-wire form, packed)
        System.arraycopy(share, shareSA, sig, off, paramK + 2 * paramD * paramWd);
        int p = off + paramK + 2 * paramD * paramWd;
        for (int iT = 0; iT < paramT; ++iT)
        {
            int v = readField32(share, shareC + iT * 4) & fpointMask();
            for (int b = 0; b < fpointSize; ++b)
            {
                sig[p + b] = (byte) ((v >>> (b * 8)) & 0xff);
            }
            p += fpointSize;
        }
    }

    private void compressedPack(int[][][] values, byte[] sig, int off)
    {
        for (int e = 0; e < paramTau; ++e)
        {
            for (int iD = 0; iD < paramD; ++iD)
            {
                for (int iT = 0; iT < paramT; ++iT)
                {
                    int v = values[e][iD][iT];
                    for (int b = 0; b < fpointSize; ++b)
                    {
                        sig[off++] = (byte) ((v >>> (b * 8)) & 0xff);
                    }
                }
            }
        }
    }

    private void packIntsLE(int[][] src, byte[] dst)
    {
        int p = 0;
        for (int i = 0; i < src.length; ++i)
        {
            for (int j = 0; j < src[i].length; ++j)
            {
                writeField32(dst, p, src[i][j]);
                p += 4;
            }
        }
    }

    private void packIntsLE(int[] src, byte[] dst)
    {
        for (int i = 0; i < src.length; ++i)
        {
            writeField32(dst, i * 4, src[i]);
        }
    }

    private static long readUint64LE(byte[] buf, int off)
    {
        return Pack.littleEndianToLong(buf, off);
    }

    // ===== verify =====

    private boolean doVerify(SDitHPublicKeyExpanded pk, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
    {
        int saltOff = sigOff;
        int h2Off = saltOff + saltSize;
        int treeSeedsOff = h2Off + hashSize;
        int comsOff = treeSeedsOff + paramTau * paramDimD * seedSize;
        int auxesOff = comsOff + paramTau * commitSize;
        int alphasOff = auxesOff + paramTau * auxSize;
        int betasOff = alphasOff + paramTau * alphaBetaBytes;

        byte[] salt = Arrays.copyOfRange(sig, saltOff, saltOff + saltSize);
        byte[] h2Sig = Arrays.copyOfRange(sig, h2Off, h2Off + hashSize);

        SHAKEDigest chalPrg = newXof(h2Sig, 0, hashSize);
        byte[] chalBytes = new byte[paramTau * 8];
        squeeze(chalPrg, chalBytes, 0, chalBytes.length);
        int chalMask = (1 << paramDimD) - 1;

        SDitHHash h1Hash = SDitHHash.sha3(hashBits, SDitHHash.HASH_H1);
        h1Hash.update(pk.hASeed, 0, seedSize);
        h1Hash.update(salt, 0, saltSize);

        byte[][][] mainPartyShares = new byte[paramTau][paramDimD][];
        for (int e = 0; e < paramTau; ++e)
        {
            for (int d = 0; d < paramDimD; ++d)
            {
                mainPartyShares[e][d] = new byte[shareSize];
            }
        }

        for (int e = 0; e < paramTau; ++e)
        {
            long chalE = readUint64LE(chalBytes, e * 8);
            int challenge = (int) (chalE & chalMask);

            if (challenge == chalMask)
            {
                // aux must be all-zero; otherwise reject.
                int aOff = auxesOff + e * auxSize;
                for (int b = 0; b < auxSize; ++b)
                {
                    if (sig[aOff + b] != 0)
                    {
                        return false;
                    }
                }
            }

            expandSeedTreeWithHintBfs(sig, treeSeedsOff + e * paramDimD * seedSize,
                    challenge, salt, h1Hash, e,
                    sig, comsOff + e * commitSize,
                    sig, auxesOff + e * auxSize,
                    mainPartyShares[e]);
        }

        byte[] h1 = new byte[hashSize];
        h1Hash.doFinal(h1, 0);

        int[][][] r = new int[paramTau][paramD][paramT];
        int[][][] eps = new int[paramTau][paramD][paramT];
        sampleChallenge(h1, r, eps);

        SDitHHash h2Hash = SDitHHash.sha3(hashBits, SDitHHash.HASH_H2);
        h2Hash.update(msg, msgOff, msgLen);
        h2Hash.update(salt, 0, saltSize);
        h2Hash.update(h1, 0, hashSize);

        MpcHelper[][] helpers = buildHelpers(r, eps);

        // Unpack alpha, beta.
        int[][][] alpha = new int[paramTau][paramD][paramT];
        int[][][] beta = new int[paramTau][paramD][paramT];
        unpackCompressed(alpha, sig, alphasOff);
        unpackCompressed(beta, sig, betasOff);

        for (int e = 0; e < paramTau; ++e)
        {
            long chalE = readUint64LE(chalBytes, e * 8);
            int challenge = (int) (chalE & chalMask);

            byte[] tmp = new byte[paramD * paramT * 4];
            packIntsLE(alpha[e], tmp);
            h2Hash.update(tmp, 0, tmp.length);
            packIntsLE(beta[e], tmp);
            h2Hash.update(tmp, 0, tmp.length);

            for (int i = 0; i < paramDimD; ++i)
            {
                int chalParty = (challenge >> (paramDimD - 1 - i)) & 1;
                int[][] shA = new int[paramD][paramT];
                int[][] shB = new int[paramD][paramT];
                int[] shV = new int[paramT];
                int[][] shAa = new int[paramD][paramT];
                int[][] shBb = new int[paramD][paramT];
                int[] shVv = new int[paramT];
                if (chalParty == 1)
                {
                    mpcCommunications(mainPartyShares[e][i], /* withOffsets=chalParty != 1 = */ false,
                            helpers[e], pk, alpha[e], beta[e], shA, shB, shV);
                    // sh_alpha[0] / sh_beta[0] / sh_v[0] are the computed party (= party 0).
                    packIntsLE(shA, tmp);
                    h2Hash.update(tmp, 0, tmp.length);
                    packIntsLE(shB, tmp);
                    h2Hash.update(tmp, 0, tmp.length);
                    byte[] tmpv = new byte[paramT * 4];
                    packIntsLE(shV, tmpv);
                    h2Hash.update(tmpv, 0, tmpv.length);
                }
                else
                {
                    mpcCommunications(mainPartyShares[e][i], /* withOffsets= */ true,
                            helpers[e], pk, alpha[e], beta[e], shA, shB, shV);
                    // sh_alpha[0] = alpha - sh_alpha[1]  (the computed party).
                    // GF(256): subtraction is XOR; GF(p251): true subtraction.
                    // sh_v[0] = -sh_v[1] for GF(p251); = sh_v[1] for GF(256) (XOR-self-inverse).
                    for (int iD = 0; iD < paramD; ++iD)
                    {
                        for (int iT = 0; iT < paramT; ++iT)
                        {
                            shAa[iD][iT] = fpointSub(alpha[e][iD][iT], shA[iD][iT]);
                            shBb[iD][iT] = fpointSub(beta[e][iD][iT], shB[iD][iT]);
                        }
                    }
                    for (int iT = 0; iT < paramT; ++iT)
                    {
                        shVv[iT] = fpointSub(0, shV[iT]);
                    }
                    packIntsLE(shAa, tmp);
                    h2Hash.update(tmp, 0, tmp.length);
                    packIntsLE(shBb, tmp);
                    h2Hash.update(tmp, 0, tmp.length);
                    byte[] tmpv = new byte[paramT * 4];
                    packIntsLE(shVv, tmpv);
                    h2Hash.update(tmpv, 0, tmpv.length);
                }
            }
        }

        byte[] h2Computed = new byte[hashSize];
        h2Hash.doFinal(h2Computed, 0);
        return Arrays.constantTimeAreEqual(h2Computed, h2Sig);
    }

    private void unpackCompressed(int[][][] dst, byte[] sig, int off)
    {
        for (int e = 0; e < paramTau; ++e)
        {
            for (int iD = 0; iD < paramD; ++iD)
            {
                for (int iT = 0; iT < paramT; ++iT)
                {
                    int v = 0;
                    for (int b = 0; b < fpointSize; ++b)
                    {
                        v |= (sig[off++] & 0xff) << (b * 8);
                    }
                    dst[e][iD][iT] = v;
                }
            }
        }
    }

    private void expandSeedTreeWithHintBfs(byte[] seedHints, int seedHintsOff, int hint,
                                           byte[] salt, SDitHHash msgCommit, int iteration,
                                           byte[] sigCom, int sigComOff,
                                           byte[] sigAux, int sigAuxOff,
                                           byte[][] mainPartyShares)
    {
        int numLeafs = 1 << paramDimD;
        byte[][] seeds = new byte[numLeafs * 2][seedSize];
        byte[][] commits = new byte[numLeafs][commitSize];

        SDitHTreePrg tree = new SDitHTreePrg(hashBits, seedSize, salt);
        int prevOff = 0;
        int curOff = 1;
        int curN = 2;
        int currentTweak = 1;
        for (int d = 1; d <= paramDimD; ++d)
        {
            byte[] inFlat = new byte[(curN / 2) * seedSize];
            for (int i = 0; i < curN / 2; ++i)
            {
                System.arraycopy(seeds[prevOff + i], 0, inFlat, i * seedSize, seedSize);
            }
            byte[] outFlat = new byte[curN * seedSize];
            tree.seedExpand(outFlat, 0, inFlat, 0, currentTweak, iteration, curN);
            for (int i = 0; i < curN; ++i)
            {
                System.arraycopy(outFlat, i * seedSize, seeds[curOff + i], 0, seedSize);
            }
            int idxSibling = ((hint >> (paramDimD - d)) ^ 1);
            System.arraycopy(seedHints, seedHintsOff + (d - 1) * seedSize, seeds[curOff + idxSibling], 0, seedSize);
            prevOff = curOff;
            curOff = prevOff + curN;
            curN <<= 1;
            currentTweak <<= 1;
        }

        int leafLevelOff = prevOff;
        byte[] curShare = new byte[shareSize];
        for (int i = 0; i < numLeafs - 1; ++i)
        {
            commitLeaf(commits[i], seeds[leafLevelOff + i], salt, iteration, i);

            if (i == hint)
            {
                continue;
            }
            expandShareFromSeed(curShare, seeds[leafLevelOff + i]);
            // For each tree-bit j: when leaf i differs from hint at bit (D-1-j), it lies on
            // the available (= 1 - h_j) side and must be accumulated into the single
            // mainPartyShares[j] slot we keep (which represents that side).
            for (int j = 0; j < paramDimD; ++j)
            {
                if ((((i ^ hint) >> (paramDimD - 1 - j)) & 1) == 1)
                {
                    shareAccumulate(mainPartyShares[j], curShare);
                }
            }
        }
        // Replace hidden-leaf commit with the on-wire commitment.
        System.arraycopy(sigCom, sigComOff, commits[hint], 0, commitSize);

        if (hint != numLeafs - 1)
        {
            commitLastLeafFromSig(commits[numLeafs - 1], seeds[leafLevelOff + numLeafs - 1], sigAux, sigAuxOff, salt, iteration);

            // Last leaf cur_share: a/b from seed, s_A/q/p/c from aux.
            byte[] last = new byte[shareSize];
            expandLastShareFromSeed(last, seeds[leafLevelOff + numLeafs - 1]);
            System.arraycopy(sigAux, sigAuxOff, last, shareSA, paramK + 2 * paramD * paramWd);
            int cOff = sigAuxOff + paramK + 2 * paramD * paramWd;
            for (int iT = 0; iT < paramT; ++iT)
            {
                int v = 0;
                for (int b = 0; b < fpointSize; ++b)
                {
                    v |= (sigAux[cOff + iT * fpointSize + b] & 0xff) << (b * 8);
                }
                writeField32(last, shareC + iT * 4, v);
            }
            int leafIdx = numLeafs - 1;
            for (int j = 0; j < paramDimD; ++j)
            {
                if ((((leafIdx ^ hint) >> (paramDimD - 1 - j)) & 1) == 1)
                {
                    shareAccumulate(mainPartyShares[j], last);
                }
            }
        }

        for (int i = 0; i < numLeafs; ++i)
        {
            msgCommit.update(commits[i], 0, commitSize);
        }
    }

    private void commitLastLeafFromSig(byte[] outCommit, byte[] leafSeed, byte[] sigAux, int sigAuxOff,
                                       byte[] salt, int iteration)
    {
        SDitHHash h = SDitHHash.sha3(hashBits, SDitHHash.HASH_COM);
        h.update(salt, 0, saltSize);
        h.update((byte) (iteration & 0xff));
        h.update((byte) ((iteration >> 8) & 0xff));
        int leafIdx = (1 << paramDimD) - 1;
        h.update((byte) (leafIdx & 0xff));
        h.update((byte) ((leafIdx >> 8) & 0xff));
        h.update(leafSeed, 0, seedSize);
        h.update(sigAux, sigAuxOff, paramK + 2 * paramD * paramWd);
        // The c block in the sig is fpointSize bytes per entry; the commit hash absorbs 4 bytes per
        // entry (matching the in-memory aux_share_t which carries c as uint32_t). Pad as needed.
        for (int iT = 0; iT < paramT; ++iT)
        {
            int v = 0;
            for (int b = 0; b < fpointSize; ++b)
            {
                v |= (sigAux[sigAuxOff + paramK + 2 * paramD * paramWd + iT * fpointSize + b] & 0xff) << (b * 8);
            }
            byte[] le = new byte[4];
            writeField32(le, 0, v);
            h.update(le, 0, 4);
        }
        h.doFinal(outCommit, 0);
    }

    // ===== expanded-key helpers exposed to the higher-level signer =====

    /**
     * Bag of pre-expanded private-key fields, including H_a matrix.
     */
    public static final class SDitHPrivateKeyExpanded
    {
        public byte[] hASeed;
        public byte[] y;
        public byte[] sA;
        public byte[] qPoly;
        public byte[] pPoly;
        public byte[][] hA;
    }

    /**
     * Bag of pre-expanded public-key fields, including H_a matrix.
     */
    public static final class SDitHPublicKeyExpanded
    {
        public byte[] hASeed;
        public byte[] y;
        public byte[][] hA;
    }

    public SDitHPrivateKeyExpanded expandPrivateKey(byte[] hASeed, byte[] y, byte[] sA, byte[] qPoly, byte[] pPoly)
    {
        SDitHPrivateKeyExpanded out = new SDitHPrivateKeyExpanded();
        out.hASeed = hASeed;
        out.y = y;
        out.sA = sA;
        out.qPoly = qPoly;
        out.pPoly = pPoly;
        out.hA = expandHa(hASeed);
        return out;
    }

    public SDitHPublicKeyExpanded expandPublicKey(byte[] hASeed, byte[] y)
    {
        SDitHPublicKeyExpanded out = new SDitHPublicKeyExpanded();
        out.hASeed = hASeed;
        out.y = y;
        out.hA = expandHa(hASeed);
        return out;
    }
}
