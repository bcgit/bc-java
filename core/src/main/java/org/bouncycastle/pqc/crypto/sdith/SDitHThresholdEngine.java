package org.bouncycastle.pqc.crypto.sdith;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.raw.GF256AES;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Stateful engine implementing the SDitH-Threshold (nfpr, non-FPR) signature scheme.
 * <p>
 * Port of the reference C implementation under
 * {@code sdith/Reference_Implementation/Threshold_Variant/sdith_threshold_cat*_*}.
 * The threshold variant differs from the hypercube variant in that parties'
 * input shares are produced by linear secret sharing (Shamir-style over the
 * base field) rather than via a seed tree, and the protocol commits each
 * party-share into a Merkle tree per execution; only {@code PARAM_NB_REVEALED}
 * party indices per execution are then opened.
 * <p>
 * Key generation (the SD instance, witness, etc.) is identical to the hypercube
 * variant — the threshold engine delegates to
 * {@link SDitHEngine#generateIsdInstance(byte[])} for that part.
 */
final class SDitHThresholdEngine
{
    private final SDitHParameters params;
    private final SecureRandom random;

    // Cached parameter fields.
    private final int seedSize;
    private final int saltSize;
    private final int hashSize;
    private final int commitSize;
    private final int extDegree;
    private final int paramK;
    private final int paramD;
    private final int paramT;          // PARAM_NB_EVALS_PER_POLY
    private final int paramTau;        // PARAM_NB_EXECUTIONS
    private final int paramLogNbParties;
    private final int paramNbParties;
    private final int paramNbRevealed;
    private final int paramWd;
    private final int paramMd;
    private final int paramYSize;
    private final int paramHaNSlice;
    private final int hashBits;
    private final int xofBits;

    // Sizes of share fragments.
    private final int witSize;     // = k + 2*d*wd
    private final int unifSize;    // = 2*d*t*ext
    private final int corrSize;    // = t*ext
    private final int shareSize;   // = wit + unif + corr  (no alignment padding for threshold)
    private final int brSize;      // = (2*d + 1) * t * ext  (alpha + beta + v)
    private final int compressedBrSize; // = sizeof(unif) = 2*d*t*ext
    private final int alphaBetaPerExecBytes;  // d*t*ext (per alpha and per beta block)

    // Offsets inside a share buffer.
    private final int shareSA;
    private final int shareQ;
    private final int shareP;
    private final int shareA;
    private final int shareB;
    private final int shareC;

    // Offsets inside a broadcast buffer.
    private final int brAlpha;
    private final int brBeta;
    private final int brV;

    public SDitHThresholdEngine(SDitHParameters params, SecureRandom random)
    {
        if (params.getVariant() != SDitHParameters.VARIANT_THRESHOLD)
        {
            throw new IllegalArgumentException("not a threshold parameter set: " + params.getName());
        }
        this.params = params;
        this.random = random;
        this.seedSize = params.getSeedSize();
        this.saltSize = params.getSaltSize();
        this.hashSize = params.getHashSize();
        this.commitSize = params.getCommitSize();
        this.extDegree = params.getFpointSize();
        this.paramK = params.getK();
        this.paramD = params.getD();
        this.paramT = params.getT();
        this.paramTau = params.getTau();
        this.paramLogNbParties = params.getDimD();
        this.paramNbParties = params.getNbParties();
        this.paramNbRevealed = params.getNbRevealed();
        this.paramWd = params.getWd();
        this.paramMd = params.getMd();
        this.paramYSize = params.getYSize();
        this.paramHaNSlice = params.getHaNSlice();
        this.hashBits = params.getHashBits();
        this.xofBits = params.getXofBits();

        this.witSize = paramK + 2 * paramD * paramWd;
        this.unifSize = 2 * paramD * paramT * extDegree;
        this.corrSize = paramT * extDegree;
        this.shareSize = witSize + unifSize + corrSize;
        this.compressedBrSize = unifSize;
        this.brSize = 2 * paramD * paramT * extDegree + paramT * extDegree;
        this.alphaBetaPerExecBytes = paramD * paramT * extDegree;

        this.shareSA = 0;
        this.shareQ = shareSA + paramK;
        this.shareP = shareQ + paramD * paramWd;
        this.shareA = shareP + paramD * paramWd;       // no padding for threshold
        this.shareB = shareA + paramD * paramT * extDegree;
        this.shareC = shareB + paramD * paramT * extDegree;

        this.brAlpha = 0;
        this.brBeta = brAlpha + paramD * paramT * extDegree;
        this.brV = brBeta + paramD * paramT * extDegree;
    }

    public SDitHParameters getParameters()
    {
        return params;
    }

    // ----- field-aware byte helpers (duplicated from SDitHEngine to keep the engines independent) -----

    private boolean isP251()
    {
        return params.getField() == SDitHParameters.FIELD_P251;
    }

    private int fieldByteAdd(int a, int b)
    {
        return isP251() ? SDitHP251.add(a, b) : ((a ^ b) & 0xff);
    }

    private int fieldByteSub(int a, int b)
    {
        return isP251() ? SDitHP251.sub(a, b) : ((a ^ b) & 0xff);
    }

    private int fieldByteMul(int a, int b)
    {
        return isP251() ? SDitHP251.mulNaive(a, b) : GF256AES.mul(a, b);
    }

    private int fieldByteNeg(int a)
    {
        return isP251() ? SDitHP251.neg(a) : (a & 0xff);
    }

    /**
     * vz[i] ^= vx[i] (gf256) or vz[i] = (vz[i] + vx[i]) mod 251 — over a byte block.
     */
    private void addTabPoints(byte[] vz, int vzOff, byte[] vx, int vxOff, int size)
    {
        if (!isP251())
        {
            for (int i = 0; i < size; ++i)
            {
                vz[vzOff + i] ^= vx[vxOff + i];
            }
        }
        else
        {
            for (int i = 0; i < size; ++i)
            {
                int v = (vz[vzOff + i] & 0xff) + (vx[vxOff + i] & 0xff);
                vz[vzOff + i] = (byte) SDitHP251.reduce16(v);
            }
        }
    }

    /**
     * vz[i] -= vx[i] (gf256 = XOR) or vz[i] = (vz[i] - vx[i] + 251) mod 251.
     */
    private void subTabPoints(byte[] vz, int vzOff, byte[] vx, int vxOff, int size)
    {
        if (!isP251())
        {
            for (int i = 0; i < size; ++i)
            {
                vz[vzOff + i] ^= vx[vxOff + i];
            }
        }
        else
        {
            for (int i = 0; i < size; ++i)
            {
                int v = (vz[vzOff + i] & 0xff) + 251 - (vx[vxOff + i] & 0xff);
                vz[vzOff + i] = (byte) SDitHP251.reduce16(v);
            }
        }
    }

    /**
     * vz[i] = vz[i] * y + vx[i] over the base field, treating bytes as field elements.
     */
    private void mulAndAddTabPoints(byte[] vz, int vzOff, int y, byte[] vx, int vxOff, int size)
    {
        if (!isP251())
        {
            // vz = vz*y + vx over GF(256): word-parallel scalar-times-vector
            // multiply (mulFx8) per 8-byte block, scalar tail for the rest.
            int i = 0;
            for (; i + 8 <= size; i += 8)
            {
                long prod = GF256AES.mulFx8(y, Pack.littleEndianToLong(vz, vzOff + i));
                long vxb = Pack.littleEndianToLong(vx, vxOff + i);
                Pack.longToLittleEndian(prod ^ vxb, vz, vzOff + i);
            }
            for (; i < size; ++i)
            {
                int p = GF256AES.mul(vz[vzOff + i] & 0xff, y);
                vz[vzOff + i] = (byte) (p ^ (vx[vxOff + i] & 0xff));
            }
        }
        else
        {
            for (int i = 0; i < size; ++i)
            {
                int p = (vz[vzOff + i] & 0xff) * y + (vx[vxOff + i] & 0xff);
                vz[vzOff + i] = (byte) SDitHP251.reduce32(p);
            }
        }
    }

    /**
     * vz[i] = -vz[i] (no-op for gf256, mod-251 negation otherwise).
     */
    private void negTabPoints(byte[] vz, int vzOff, int size)
    {
        if (!isP251())
        {
            return;
        }
        for (int i = 0; i < size; ++i)
        {
            int v = vz[vzOff + i] & 0xff;
            vz[vzOff + i] = (byte) ((v != 0) ? (251 - v) : 0);
        }
    }

    /**
     * vecMat-cols-muladd over the sliced H_A representation (GF(256)/p251).
     */
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

    // ----- extension-field byte-array helpers -----

    private void fpointAddBytes(byte[] dst, int dstOff, byte[] a, int aOff, byte[] b, int bOff)
    {
        if (!isP251())
        {
            for (int i = 0; i < extDegree; ++i)
            {
                dst[dstOff + i] = (byte) ((a[aOff + i] ^ b[bOff + i]) & 0xff);
            }
        }
        else
        {
            for (int i = 0; i < extDegree; ++i)
            {
                int v = (a[aOff + i] & 0xff) + (b[bOff + i] & 0xff);
                dst[dstOff + i] = (byte) (v >= 251 ? v - 251 : v);
            }
        }
    }

    private void fpointSubBytes(byte[] dst, int dstOff, byte[] a, int aOff, byte[] b, int bOff)
    {
        if (!isP251())
        {
            for (int i = 0; i < extDegree; ++i)
            {
                dst[dstOff + i] = (byte) ((a[aOff + i] ^ b[bOff + i]) & 0xff);
            }
        }
        else
        {
            for (int i = 0; i < extDegree; ++i)
            {
                int v = (a[aOff + i] & 0xff) + 251 - (b[bOff + i] & 0xff);
                dst[dstOff + i] = (byte) (v >= 251 ? v - 251 : v);
            }
        }
    }

    private void fpointMulBytes(byte[] dst, int dstOff, byte[] a, int aOff, byte[] b, int bOff)
    {
        int av = Pack.littleEndianToInt(a, aOff);
        int bv = Pack.littleEndianToInt(b, bOff);
        int r = isP251() ? SDitHP251P4.mulNaive(av, bv) : SDitHGF2P32.mulNaive(av, bv);
        Pack.intToLittleEndian(r, dst, dstOff);
    }

    /**
     * Mixed (base × ext) multiplication: each byte of b multiplied by the base-field scalar a.
     */
    private void fpointMulMixedBytes(byte[] dst, int dstOff, int a, byte[] b, int bOff)
    {
        if (!isP251())
        {
            for (int i = 0; i < extDegree; ++i)
            {
                dst[dstOff + i] = (byte) GF256AES.mul(a, b[bOff + i] & 0xff);
            }
        }
        else
        {
            for (int i = 0; i < extDegree; ++i)
            {
                dst[dstOff + i] = (byte) SDitHP251.mulNaive(a, b[bOff + i] & 0xff);
            }
        }
    }

    // ----- XOF / hash helpers -----

    private SHAKEDigest newXof()
    {
        return new SHAKEDigest(xofBits);
    }

    private SHAKEDigest prgInit(byte[] seed, byte[] salt)
    {
        SHAKEDigest x = newXof();
        if (salt != null)
        {
            x.update(salt, 0, saltSize);
        }
        x.update(seed, 0, seedSize);
        return x;
    }

    private void squeeze(SHAKEDigest x, byte[] out, int off, int len)
    {
        x.doOutput(out, off, len);
    }

    /**
     * Threshold-variant p251 rejection sampling. Matches the reference
     * {@code gf251_random_elements} byte-for-byte: read {@code len-pos} bytes
     * per iteration, filter accepted (&lt; 251) bytes in place, repeat until
     * full. This differs from the hypercube engine's {@code sdith_xof_next_bytes_mod251}
     * which oversamples by ~1.03x in a single read.
     */
    private void squeezeFieldBytes(SHAKEDigest x, byte[] out, int off, int len)
    {
        if (!isP251())
        {
            squeeze(x, out, off, len);
            return;
        }
        int pos = 0;
        byte[] buf = new byte[len];
        while (pos < len)
        {
            int need = len - pos;
            squeeze(x, buf, 0, need);
            for (int i = 0; i < need; ++i)
            {
                int b = buf[i] & 0xff;
                if (b < 251)
                {
                    out[off + (pos++)] = (byte) b;
                }
            }
        }
    }

    // ----- key generation: identical instance generation as the hypercube engine -----

    public byte[][] generateKeyPair()
    {
        SDitHEngine helper = new SDitHEngine(params, random);
        return helper.generateKeyPairThreshold();
    }

    public SDitHEngine.SDitHPrivateKeyExpanded expandPrivateKey(byte[] hASeed, byte[] y, byte[] sA, byte[] qPoly, byte[] pPoly)
    {
        return new SDitHEngine(params, random).expandPrivateKey(hASeed, y, sA, qPoly, pPoly);
    }

    public SDitHEngine.SDitHPublicKeyExpanded expandPublicKey(byte[] hASeed, byte[] y)
    {
        return new SDitHEngine(params, random).expandPublicKey(hASeed, y);
    }

    // ----- precomputed tables -----

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

    // ----- share-build helpers (Shamir-style polynomial evaluation) -----

    /**
     * share = plain * eval^r + rnd[0]*eval^(r-1) + ... + rnd[r-1]
     * Operates over the share byte buffer. For eval = 0, share = rnd[r-1] (no
     * polynomial evaluation).
     */
    private void computeCompleteShare(byte[] out, byte[] plain, byte[][] rnd, int eval)
    {
        System.arraycopy(rnd[paramNbRevealed - 1], 0, out, 0, shareSize);
        if (eval != 0)
        {
            for (int k = paramNbRevealed - 2; k >= 0; --k)
            {
                mulAndAddTabPoints(out, 0, eval, rnd[k], 0, shareSize);
            }
            mulAndAddTabPoints(out, 0, eval, plain, 0, shareSize);
        }
    }

    private void computeShareWit(byte[] outWit, byte[] plain, byte[][] rnd, int eval)
    {
        System.arraycopy(rnd[paramNbRevealed - 1], 0, outWit, 0, witSize);
        if (eval != 0)
        {
            for (int k = paramNbRevealed - 2; k >= 0; --k)
            {
                mulAndAddTabPoints(outWit, 0, eval, rnd[k], 0, witSize);
            }
            mulAndAddTabPoints(outWit, 0, eval, plain, 0, witSize);
        }
    }

    private void computeShareBroadcast(byte[] outBr, byte[] plainBr, byte[][] rndBr, int eval)
    {
        System.arraycopy(rndBr[paramNbRevealed - 1], 0, outBr, 0, brSize);
        if (eval != 0)
        {
            for (int k = paramNbRevealed - 2; k >= 0; --k)
            {
                mulAndAddTabPoints(outBr, 0, eval, rndBr[k], 0, brSize);
            }
            mulAndAddTabPoints(outBr, 0, eval, plainBr, 0, brSize);
        }
    }

    // ----- MPC challenge expansion -----

    /**
     * Container for one MPC challenge instance.
     */
    private static final class MpcChallenge
    {
        byte[] eval;          // [t*ext]
        byte[] eps;           // [d*t*ext]
        byte[][] powersOfCh;  // [chunk_len+1][t*ext]
        byte[] fEval;         // [t*ext]
    }

    private MpcChallenge expandMpcChallenge(byte[] digest)
    {
        SHAKEDigest x = newXof();
        x.update(digest, 0, hashSize);

        MpcChallenge ch = new MpcChallenge();
        ch.eval = new byte[paramT * extDegree];
        ch.eps = new byte[paramD * paramT * extDegree];
        squeezeFieldBytes(x, ch.eval, 0, ch.eval.length);
        squeezeFieldBytes(x, ch.eps, 0, ch.eps.length);

        int chunkLen = paramMd;
        ch.powersOfCh = new byte[chunkLen + 1][paramT * extDegree];
        for (int j = 0; j < paramT; ++j)
        {
            int off = j * extDegree;
            // powers_of_ch[0][off..off+ext-1] = 1 in ext field, i.e. [1, 0, 0, 0]
            ch.powersOfCh[0][off] = 1;
            // powers_of_ch[1] = eval[j]
            System.arraycopy(ch.eval, off, ch.powersOfCh[1], off, extDegree);
            // powers_of_ch[i] = powers_of_ch[i-1] * eval[j] (ext field)
            for (int i = 2; i <= chunkLen; ++i)
            {
                fpointMulBytes(ch.powersOfCh[i], off, ch.powersOfCh[i - 1], off, ch.eval, off);
            }
        }

        // f_eval[j] = sum_i f_poly[i] * eval[j]^i in ext field, for i=0..chunk_len
        ch.fEval = new byte[paramT * extDegree];
        byte[] fPoly = getFPoly();
        getEvalsInAllPoints(ch.fEval, fPoly, 0, chunkLen + 1, ch.powersOfCh);
        return ch;
    }

    private void getEvalsInAllPoints(byte[] evals, byte[] poly, int polyOff, int nbCoefs, byte[][] powersOfCh)
    {
        int outLen = paramT * extDegree;
        java.util.Arrays.fill(evals, (byte) 0);
        // No zero-coefficient skip: the polynomial here is frequently secret
        // share data (Q / P / S — and on the plain-broadcast path the actual
        // witness polynomials), so work must not depend on coefficient values.
        // The C reference's matcols_muladd is likewise skip-free.
        if (!isP251())
        {
            for (int j = 0; j < nbCoefs; ++j)
            {
                int coef = poly[polyOff + j] & 0xff;
                byte[] row = powersOfCh[j];
                int i = 0;
                for (; i + 8 <= outLen; i += 8)
                {
                    long e = Pack.littleEndianToLong(evals, i)
                        ^ GF256AES.mulFx8(coef, Pack.littleEndianToLong(row, i));
                    Pack.longToLittleEndian(e, evals, i);
                }
                for (; i < outLen; ++i)
                {
                    evals[i] = (byte) ((evals[i] & 0xff) ^ GF256AES.mul(coef, row[i] & 0xff));
                }
            }
        }
        else
        {
            int[] acc = new int[outLen];
            for (int j = 0; j < nbCoefs; ++j)
            {
                int coef = poly[polyOff + j] & 0xff;
                byte[] row = powersOfCh[j];
                for (int i = 0; i < outLen; ++i)
                {
                    acc[i] += (row[i] & 0xff) * coef;
                }
            }
            for (int i = 0; i < outLen; ++i)
            {
                evals[i] = (byte) SDitHP251.reduce32(acc[i]);
            }
        }
    }

    // ----- MPC compute communications -----

    /**
     * Runs the simulated MPC protocol on the given share, producing the
     * broadcast output. Matches {@code run_multiparty_computation} in the
     * reference, with field-aware sub/neg semantics.
     *
     * @param outBr             broadcast output buffer (size {@link #brSize})
     * @param mpcCh             MPC challenge (eval/eps/powers/f_eval)
     * @param share             input share (size {@link #shareSize})
     * @param plainBr           plaintext broadcast (used in the v term)
     * @param hA                expanded SD matrix (slices)
     * @param y                 syndrome (only used when {@code hasSharingOffset})
     * @param hasSharingOffset  1 if this share carries the SD offset (s_B = y - H s_A), 0 otherwise
     * @param entireComputation if true compute the v term too; if false only alpha and beta are set
     */
    private void runMultipartyComputation(byte[] outBr, MpcChallenge mpcCh,
                                          byte[] share, byte[] plainBr,
                                          byte[][] hA, byte[] y,
                                          boolean hasSharingOffset, boolean entireComputation)
    {
        // s = s_A || s_B; size = paramD * paramMd = m bytes (codeword length).
        byte[] s = new byte[paramD * paramMd];
        System.arraycopy(share, shareSA, s, 0, paramK);
        // Compute syndrome in a paramHaNSlice*128 byte buffer (matches sliced H_A layout),
        // then copy the meaningful first paramYSize bytes into s[paramK..].
        byte[] syndromeBuf = new byte[paramHaNSlice * 128];
        if (hasSharingOffset)
        {
            System.arraycopy(y, 0, syndromeBuf, 0, paramYSize);
        }
        // s_B = y - H_A s_A
        negTabPoints(syndromeBuf, 0, paramYSize);
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            vecMatNColsMulAdd(syndromeBuf, slice * 128, share, shareSA, hA[slice], 0, paramK, 128);
        }
        negTabPoints(syndromeBuf, 0, paramYSize);
        System.arraycopy(syndromeBuf, 0, s, paramK, paramYSize);

        // Initialize broadcast alpha and beta to zero.
        java.util.Arrays.fill(outBr, brAlpha, brV, (byte) 0);

        // Q evaluations -> alpha
        byte[] alphaTmp = new byte[paramT * extDegree];
        for (int np = 0; np < paramD; ++np)
        {
            int qOff = shareQ + np * paramWd;
            // For q (monic of degree wd, stored as wd non-leading coeffs), we evaluate
            // a wd-degree monic polynomial. But the reference passes PARAM_CHUNK_WEIGHT
            // (= wd) coefficients to get_evals_in_all_points — which is wd coefficients
            // corresponding to the non-leading terms. The leading 1*r^w is added later
            // (the "add r^w" step inside the alpha update).
            getEvalsInAllPoints(alphaTmp, share, qOff, paramWd, mpcCh.powersOfCh);
            System.arraycopy(alphaTmp, 0, outBr, brAlpha + np * paramT * extDegree, paramT * extDegree);
        }

        // S evaluations -> beta
        for (int np = 0; np < paramD; ++np)
        {
            int sOff = np * paramMd;
            getEvalsInAllPoints(alphaTmp, s, sOff, paramMd, mpcCh.powersOfCh);
            System.arraycopy(alphaTmp, 0, outBr, brBeta + np * paramT * extDegree, paramT * extDegree);
        }

        // P evaluations (only for entire_computation)
        byte[][] pEvals = null;
        if (entireComputation)
        {
            pEvals = new byte[paramD][paramT * extDegree];
            for (int np = 0; np < paramD; ++np)
            {
                int pOff = shareP + np * paramWd;
                getEvalsInAllPoints(pEvals[np], share, pOff, paramWd, mpcCh.powersOfCh);
            }
        }

        // Per j: combine alpha, beta, v with shares of a,b,c.
        byte[] tmp = new byte[extDegree];
        for (int j = 0; j < paramT; ++j)
        {
            int jOff = j * extDegree;

            // v[j] init = 0; if entire_computation: v[j] -= corr.c[j]
            for (int b = 0; b < extDegree; ++b)
            {
                outBr[brV + jOff + b] = 0;
            }
            if (entireComputation)
            {
                fpointSubBytes(outBr, brV + jOff, outBr, brV + jOff, share, shareC + jOff);
            }

            for (int np = 0; np < paramD; ++np)
            {
                int alphaOff = brAlpha + (np * paramT + j) * extDegree;
                int betaOff = brBeta + (np * paramT + j) * extDegree;
                int aOff = shareA + (np * paramT + j) * extDegree;
                int bOff = shareB + (np * paramT + j) * extDegree;
                int epsOff = (np * paramT + j) * extDegree;

                // alpha = eps * (r^w + Q(r)) + a
                if (hasSharingOffset)
                {
                    fpointAddBytes(outBr, alphaOff, outBr, alphaOff, mpcCh.powersOfCh[paramWd], jOff);
                }
                fpointMulBytes(outBr, alphaOff, outBr, alphaOff, mpcCh.eps, epsOff);
                fpointAddBytes(outBr, alphaOff, outBr, alphaOff, share, aOff);

                // beta = S(r) + b
                fpointAddBytes(outBr, betaOff, outBr, betaOff, share, bOff);

                if (entireComputation)
                {
                    // v += eps * F(r) * P(r)
                    fpointMulBytes(tmp, 0, pEvals[np], jOff, mpcCh.eps, epsOff);
                    fpointMulBytes(tmp, 0, tmp, 0, mpcCh.fEval, jOff);
                    fpointAddBytes(outBr, brV + jOff, outBr, brV + jOff, tmp, 0);
                    // v += plain_alpha * b
                    fpointMulBytes(tmp, 0, plainBr, brAlpha + (np * paramT + j) * extDegree, share, bOff);
                    fpointAddBytes(outBr, brV + jOff, outBr, brV + jOff, tmp, 0);
                    // v += plain_beta * a
                    fpointMulBytes(tmp, 0, plainBr, brBeta + (np * paramT + j) * extDegree, share, aOff);
                    fpointAddBytes(outBr, brV + jOff, outBr, brV + jOff, tmp, 0);
                    // v -= plain_alpha * plain_beta (only when sharing offset)
                    if (hasSharingOffset)
                    {
                        fpointMulBytes(tmp, 0,
                                plainBr, brAlpha + (np * paramT + j) * extDegree,
                                plainBr, brBeta + (np * paramT + j) * extDegree);
                        fpointSubBytes(outBr, brV + jOff, outBr, brV + jOff, tmp, 0);
                    }
                }
            }
        }
    }

    /**
     * The plain broadcast = run MPC on plain share, hasSharingOffset=true,
     * entireComputation=false (the v term is zero by construction so we skip it).
     */
    private void mpcComputePlainBroadcast(byte[] outBr, MpcChallenge mpcCh, byte[] plain, byte[][] hA, byte[] y)
    {
        runMultipartyComputation(outBr, mpcCh, plain, outBr, hA, y, true, false);
    }

    /**
     * Per-rnd-share broadcast = run MPC on a random share, hasSharingOffset=false,
     * entireComputation=true (full v term).
     */
    private void mpcComputeCommunications(byte[] outBr, MpcChallenge mpcCh, byte[] share, byte[] plainBr,
                                          byte[][] hA, byte[] y, boolean hasSharingOffset)
    {
        runMultipartyComputation(outBr, mpcCh, share, plainBr, hA, y, hasSharingOffset, true);
    }

    /**
     * Reverse: given a share's witness portion and a broadcast, recover the
     * (unif, corr) parts. Used in verification.
     */
    private void mpcComputeCommunicationsInverse(byte[] share, MpcChallenge mpcCh,
                                                 byte[] broadcast, byte[] plainBr,
                                                 byte[][] hA, byte[] y, boolean hasSharingOffset)
    {
        // Build s = s_A || s_B (same layout as forward) for the polynomial evaluations.
        byte[] s = new byte[paramD * paramMd];
        System.arraycopy(share, shareSA, s, 0, paramK);
        byte[] syndromeBuf = new byte[paramHaNSlice * 128];
        if (hasSharingOffset)
        {
            System.arraycopy(y, 0, syndromeBuf, 0, paramYSize);
        }
        negTabPoints(syndromeBuf, 0, paramYSize);
        for (int slice = 0; slice < paramHaNSlice; ++slice)
        {
            vecMatNColsMulAdd(syndromeBuf, slice * 128, share, shareSA, hA[slice], 0, paramK, 128);
        }
        negTabPoints(syndromeBuf, 0, paramYSize);
        System.arraycopy(syndromeBuf, 0, s, paramK, paramYSize);

        // share.unif.a[np][j] = Q evaluations
        byte[] tmpEvals = new byte[paramT * extDegree];
        for (int np = 0; np < paramD; ++np)
        {
            int qOff = shareQ + np * paramWd;
            getEvalsInAllPoints(tmpEvals, share, qOff, paramWd, mpcCh.powersOfCh);
            System.arraycopy(tmpEvals, 0, share, shareA + np * paramT * extDegree, paramT * extDegree);
        }

        // share.unif.b[np][j] = S evaluations
        for (int np = 0; np < paramD; ++np)
        {
            int sOff = np * paramMd;
            getEvalsInAllPoints(tmpEvals, s, sOff, paramMd, mpcCh.powersOfCh);
            System.arraycopy(tmpEvals, 0, share, shareB + np * paramT * extDegree, paramT * extDegree);
        }

        // P evals
        byte[][] pEvals = new byte[paramD][paramT * extDegree];
        for (int np = 0; np < paramD; ++np)
        {
            int pOff = shareP + np * paramWd;
            getEvalsInAllPoints(pEvals[np], share, pOff, paramWd, mpcCh.powersOfCh);
        }

        byte[] tmp = new byte[extDegree];
        for (int j = 0; j < paramT; ++j)
        {
            int jOff = j * extDegree;

            // corr.c[j] = -broadcast.v[j]
            for (int b = 0; b < extDegree; ++b)
            {
                share[shareC + jOff + b] = 0;
            }
            fpointSubBytes(share, shareC + jOff, share, shareC + jOff, broadcast, brV + jOff);

            for (int np = 0; np < paramD; ++np)
            {
                int aOff = shareA + (np * paramT + j) * extDegree;
                int bOff = shareB + (np * paramT + j) * extDegree;
                int alphaOff = brAlpha + (np * paramT + j) * extDegree;
                int betaOff = brBeta + (np * paramT + j) * extDegree;
                int epsOff = (np * paramT + j) * extDegree;

                // a = -eps*(r^w + Q(r)) + alpha
                if (hasSharingOffset)
                {
                    fpointAddBytes(share, aOff, share, aOff, mpcCh.powersOfCh[paramWd], jOff);
                }
                fpointMulBytes(share, aOff, share, aOff, mpcCh.eps, epsOff);
                negTabPoints(share, aOff, extDegree);
                // For GF(256), negation is identity, so the add becomes XOR
                fpointAddBytes(share, aOff, share, aOff, broadcast, alphaOff);

                // b = -S(r) + beta
                negTabPoints(share, bOff, extDegree);
                fpointAddBytes(share, bOff, share, bOff, broadcast, betaOff);

                // corr.c[j] += eps * f_eval * pEvals[np][j]
                fpointMulBytes(tmp, 0, pEvals[np], jOff, mpcCh.eps, epsOff);
                fpointMulBytes(tmp, 0, tmp, 0, mpcCh.fEval, jOff);
                fpointAddBytes(share, shareC + jOff, share, shareC + jOff, tmp, 0);
                // corr.c[j] += plain_alpha * b
                fpointMulBytes(tmp, 0, plainBr, alphaOff, share, bOff);
                fpointAddBytes(share, shareC + jOff, share, shareC + jOff, tmp, 0);
                // corr.c[j] += plain_beta * a
                fpointMulBytes(tmp, 0, plainBr, betaOff, share, aOff);
                fpointAddBytes(share, shareC + jOff, share, shareC + jOff, tmp, 0);
                // corr.c[j] -= plain_alpha * plain_beta (if sharing offset)
                if (hasSharingOffset)
                {
                    fpointMulBytes(tmp, 0, plainBr, alphaOff, plainBr, betaOff);
                    fpointSubBytes(share, shareC + jOff, share, shareC + jOff, tmp, 0);
                }
            }
        }
    }

    // ----- commit / merkle tree -----

    private void commitShare(byte[] outCommit, byte[] share, byte[] salt, int e, int i)
    {
        SDitHHash h = SDitHHash.sha3(hashBits, SDitHHash.HASH_COM);
        h.update(salt, 0, saltSize);
        h.update((byte) (e & 0xff));
        h.update((byte) ((e >>> 8) & 0xff));
        h.update((byte) (i & 0xff));
        h.update((byte) ((i >>> 8) & 0xff));
        h.update(share, 0, shareSize);
        h.doFinal(outCommit, 0);
    }

    /**
     * Build a Merkle tree over an array of leaf commitments and return the
     * root. The tree height = ceilLog2(nbLeaves).
     */
    private static int ceilLog2(int x)
    {
        if (x <= 1)
        {
            return 0;
        }
        int n = 0;
        int v = x - 1;
        while (v > 0)
        {
            v >>>= 1;
            n++;
        }
        return n;
    }

    /**
     * Per-execution Merkle tree. Stored as a flat node array (1-based: nodes[index-1]).
     * Build via build_merkle_tree, open via open_merkle_tree.
     */
    private final class MerkleTree
    {
        final int nbLeaves;
        final int height;
        final int nbNodes;
        final byte[][] nodes;

        MerkleTree(int nbLeaves)
        {
            this.nbLeaves = nbLeaves;
            this.height = ceilLog2(nbLeaves);
            this.nbNodes = (1 << height) + nbLeaves - 1;
            this.nodes = new byte[nbNodes][hashSize];
        }

        void build(byte[][] leafData)
        {
            int firstIndex = nbNodes - nbLeaves + 1;
            int lastIndex = nbNodes;
            for (int i = 0; i < nbLeaves; ++i)
            {
                System.arraycopy(leafData[i], 0, nodes[firstIndex - 1 + i], 0, hashSize);
            }
            for (int h = height - 1; h >= 0; --h)
            {
                int lastIsIsolated = 1 - (lastIndex & 1);
                firstIndex >>>= 1;
                lastIndex >>>= 1;
                for (int parent = firstIndex; parent <= lastIndex; ++parent)
                {
                    SDitHHash ctx = SDitHHash.sha3(hashBits, SDitHHash.HASH_TREE);
                    // salt is null for threshold merkle tree
                    ctx.update((byte) (parent & 0xff));
                    ctx.update((byte) ((parent >>> 8) & 0xff));
                    ctx.update(nodes[2 * parent - 1], 0, hashSize);
                    if ((parent < lastIndex) || (lastIsIsolated == 0))
                    {
                        ctx.update(nodes[2 * parent], 0, hashSize);
                    }
                    ctx.doFinal(nodes[parent - 1], 0);
                }
            }
        }

        byte[] getRoot()
        {
            return nodes[0];
        }
    }

    /**
     * Compute the indices of internal nodes that need to be revealed for
     * authenticating the given leaves. Returns the list of node indices (each
     * relative to a 1-based tree numbering). The list is in BFS/parent order
     * as the C reference walks them.
     */
    private int[] getRevealedNodes(int treeDepth, int nbLeaves, int[] leavesIndexes)
    {
        int nbRevealedLeaves = leavesIndexes.length;
        int[] queue = new int[nbRevealedLeaves];
        int firstIndex = 1 << treeDepth;
        int lastIndex = firstIndex + nbLeaves - 1;
        for (int i = 0; i < nbRevealedLeaves; ++i)
        {
            queue[i] = firstIndex + leavesIndexes[i];
        }
        int queueStart = 0;
        int queueStop = 0;
        int[] revealed = new int[treeDepth * nbRevealedLeaves];
        int nbRevealedNodes = 0;

        while (queue[queueStart] != 1)
        {
            int index = queue[queueStart];
            queueStart++;
            if (queueStart == nbRevealedLeaves)
            {
                queueStart = 0;
            }
            if (index < firstIndex)
            {
                firstIndex >>>= 1;
                lastIndex >>>= 1;
            }
            boolean isLeftChild = ((index & 1) == 0);
            if (isLeftChild && index == lastIndex)
            {
                // isolated — no sibling
            }
            else
            {
                int candidateIndex = queue[queueStart];
                boolean queueIsEmpty = (queueStart == queueStop);
                if (isLeftChild && candidateIndex == index + 1 && !queueIsEmpty)
                {
                    queueStart++;
                    if (queueStart == nbRevealedLeaves)
                    {
                        queueStart = 0;
                    }
                }
                else
                {
                    revealed[nbRevealedNodes++] = isLeftChild ? (index + 1) : (index - 1);
                }
            }
            int parent = index >>> 1;
            queue[queueStop] = parent;
            queueStop++;
            if (queueStop == nbRevealedLeaves)
            {
                queueStop = 0;
            }
        }

        int[] out = new int[nbRevealedNodes];
        System.arraycopy(revealed, 0, out, 0, nbRevealedNodes);
        return out;
    }

    /**
     * Returns the bytes (concatenated digests) of the revealed nodes for
     * authenticating {@code openLeaves} in the tree.
     */
    private byte[] openMerkleTree(MerkleTree tree, int[] openLeaves)
    {
        int[] revealed = getRevealedNodes(tree.height, tree.nbLeaves, openLeaves);
        byte[] auth = new byte[revealed.length * hashSize];
        for (int i = 0; i < revealed.length; ++i)
        {
            System.arraycopy(tree.nodes[revealed[i] - 1], 0, auth, i * hashSize, hashSize);
        }
        return auth;
    }

    private int getAuthSize(int treeDepth, int nbLeaves, int[] openLeaves)
    {
        return getRevealedNodes(treeDepth, nbLeaves, openLeaves).length * hashSize;
    }

    /**
     * Recompute Merkle root from authentication path. Modifies the leaves
     * buffer (treated as a circular queue). Returns the root or null on error.
     */
    private byte[] getMerkleRootFromAuth(int treeDepth, int nbLeaves, int[] openLeaves,
                                         byte[] leavesQueue, int leavesQueueOff,
                                         byte[] auth, int authOff, int authSize)
    {
        int nbRevealedLeaves = openLeaves.length;
        int firstIndex = 1 << treeDepth;
        int lastIndex = firstIndex + nbLeaves - 1;
        int[] queueIndexes = new int[nbRevealedLeaves];
        for (int i = 0; i < nbRevealedLeaves; ++i)
        {
            queueIndexes[i] = firstIndex + openLeaves[i];
        }
        int queueStart = 0;
        int queueStop = 0;
        byte[] root = new byte[hashSize];

        while (queueIndexes[queueStart] != 1)
        {
            int index = queueIndexes[queueStart];
            int nodeOff = leavesQueueOff + queueStart * hashSize;

            queueStart++;
            if (queueStart == nbRevealedLeaves)
            {
                queueStart = 0;
            }
            if (index < firstIndex)
            {
                firstIndex >>>= 1;
                lastIndex >>>= 1;
            }
            boolean isLeftChild = ((index & 1) == 0);
            byte[] siblingNode = null;
            int siblingOff = 0;
            int leftNodeOff = nodeOff;
            int rightNodeOff = 0;
            boolean rightFromAuth = false;
            byte[] leftHost = leavesQueue;
            byte[] rightHost = leavesQueue;

            if (isLeftChild && index == lastIndex)
            {
                // isolated — only one child
                siblingNode = null;
            }
            else
            {
                int candidateIndex = queueIndexes[queueStart];
                boolean queueIsEmpty = (queueStart == queueStop);
                if (isLeftChild && candidateIndex == index + 1 && !queueIsEmpty)
                {
                    siblingNode = leavesQueue;
                    siblingOff = leavesQueueOff + queueStart * hashSize;
                    queueStart++;
                    if (queueStart == nbRevealedLeaves)
                    {
                        queueStart = 0;
                    }
                    rightHost = leavesQueue;
                    rightNodeOff = siblingOff;
                }
                else
                {
                    if (authSize >= hashSize)
                    {
                        siblingNode = auth;
                        siblingOff = authOff;
                        authOff += hashSize;
                        authSize -= hashSize;
                    }
                    else
                    {
                        return null;
                    }
                    if (!isLeftChild)
                    {
                        // swap
                        leftHost = siblingNode;
                        leftNodeOff = siblingOff;
                        rightHost = leavesQueue;
                        rightNodeOff = nodeOff;
                    }
                    else
                    {
                        rightHost = siblingNode;
                        rightNodeOff = siblingOff;
                    }
                    rightFromAuth = true;
                }
            }

            int parent = index >>> 1;
            SDitHHash ctx = SDitHHash.sha3(hashBits, SDitHHash.HASH_TREE);
            ctx.update((byte) (parent & 0xff));
            ctx.update((byte) ((parent >>> 8) & 0xff));
            ctx.update(leftHost, leftNodeOff, hashSize);
            if (siblingNode != null || !isLeftChild || (rightFromAuth))
            {
                if (siblingNode != null)
                {
                    ctx.update(rightHost, rightNodeOff, hashSize);
                }
            }
            ctx.doFinal(leavesQueue, leavesQueueOff + queueStop * hashSize);

            queueIndexes[queueStop] = parent;
            queueStop++;
            if (queueStop == nbRevealedLeaves)
            {
                queueStop = 0;
            }
        }

        System.arraycopy(leavesQueue, leavesQueueOff + queueStart * hashSize, root, 0, hashSize);
        if (authSize != 0)
        {
            return null;
        }
        return root;
    }

    // ----- view-challenge expansion -----

    /**
     * Raw-Keccak XOF wrapper. The reference implementation's
     * {@code expand_view_challenge_hash} calls {@code xof_squeeze} without a
     * preceding {@code xof_final}, which the XKCP Keccak handles by padding
     * with the raw {@code 0x01} suffix (i.e. no NIST domain separator). To
     * match this byte-for-byte, the Java port uses Keccak[1600] directly via
     * a {@link KeccakDigest} subclass that skips the SHAKE 4-bit {@code 0x0F}
     * absorbBits step. The {@code xof_init/xof_update} and {@code xof_final}
     * paths (used by {@code expand_mpc_challenge_hash} and {@code prg_init})
     * remain standard SHAKE.
     */
    private static final class RawKeccakXof extends KeccakDigest
    {
        RawKeccakXof(int bitLength)
        {
            super(bitLength);
        }

        void output(byte[] out, int off, int len)
        {
            squeeze(out, off, ((long) len) * 8);
        }
    }

    private int[][] expandViewChallenge(byte[] digest)
    {
        RawKeccakXof x = new RawKeccakXof(xofBits);
        x.update(digest, 0, hashSize);

        int[][] views = new int[paramTau][paramNbRevealed];
        int mask = (1 << paramLogNbParties) - 1;
        byte[] tmp = new byte[2];
        for (int e = 0; e < paramTau; ++e)
        {
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                int value;
                while (true)
                {
                    while (true)
                    {
                        x.output(tmp, 0, 2);
                        value = (tmp[0] & 0xff) | ((tmp[1] & 0xff) << 8);
                        value &= mask;
                        if (value < paramNbParties)
                        {
                            break;
                        }
                    }
                    boolean unique = true;
                    for (int j = 0; j < p; ++j)
                    {
                        if (views[e][j] == value)
                        {
                            unique = false;
                            break;
                        }
                    }
                    if (unique)
                    {
                        break;
                    }
                }
                views[e][p] = value;
            }
            // Sort views[e] ascending
            java.util.Arrays.sort(views[e]);
        }
        return views;
    }

    // ----- hash builders -----

    private byte[] hashForMpcChallenge(SDitHEngine.SDitHPublicKeyExpanded inst, byte[] salt, byte[][] merkleRoots)
    {
        SDitHHash h = SDitHHash.sha3(hashBits, SDitHHash.HASH_H1);
        h.update(inst.hASeed, 0, seedSize);
        h.update(inst.y, 0, paramYSize);
        h.update(salt, 0, saltSize);
        for (int e = 0; e < paramTau; ++e)
        {
            h.update(merkleRoots[e], 0, hashSize);
        }
        byte[] out = new byte[hashSize];
        h.doFinal(out, 0);
        return out;
    }

    private byte[] hashForViewChallenge(byte[] mpcChallengeHash, byte[][][] broadcasts,
                                        byte[] plainBroadcast, byte[] salt, byte[] msg, int msgOff, int msgLen)
    {
        SDitHHash h = SDitHHash.sha3(hashBits, SDitHHash.HASH_H2);
        if (msgLen > 0)
        {
            h.update(msg, msgOff, msgLen);
        }
        h.update(salt, 0, saltSize);
        h.update(mpcChallengeHash, 0, hashSize);
        // Absorb only the unif-sized prefix of plain_broadcast (alpha + beta). v is zero.
        h.update(plainBroadcast, 0, compressedBrSize);
        for (int e = 0; e < paramTau; ++e)
        {
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                h.update(broadcasts[e][p], 0, brSize);
            }
        }
        byte[] out = new byte[hashSize];
        h.doFinal(out, 0);
        return out;
    }

    // ----- signing top-level -----

    public byte[] sign(SDitHEngine.SDitHPrivateKeyExpanded sk, byte[] msg, int msgOff, int msgLen)
    {
        byte[] salt = new byte[saltSize];
        random.nextBytes(salt);
        byte[] seed = new byte[seedSize];
        random.nextBytes(seed);
        return signCore(sk, msg, msgOff, msgLen, salt, seed);
    }

    private byte[] signCore(SDitHEngine.SDitHPrivateKeyExpanded sk, byte[] msg, int msgOff, int msgLen,
                            byte[] salt, byte[] seed)
    {
        SHAKEDigest entropy = prgInit(seed, salt);

        // Build plain share: wit = (sA, qPoly, pPoly); unif = random; corr = computeCorrelated(unif).
        byte[] plain = new byte[shareSize];
        System.arraycopy(sk.sA, 0, plain, shareSA, paramK);
        System.arraycopy(sk.qPoly, 0, plain, shareQ, paramD * paramWd);
        System.arraycopy(sk.pPoly, 0, plain, shareP, paramD * paramWd);
        // a + b: random field bytes (unifSize)
        squeezeFieldBytes(entropy, plain, shareA, unifSize);
        // corr.c[j] = sum_np ext-mul(a[np][j], b[np][j])
        computeCorrelated(plain);

        // Sample rnd shares — NB_EXEC * NB_REVEALED * SHARE_SIZE bytes
        byte[][][] rndShares = new byte[paramTau][paramNbRevealed][shareSize];
        // The reference uses one big vec_rnd into a contiguous buffer
        byte[] rndBuf = new byte[paramTau * paramNbRevealed * shareSize];
        squeezeFieldBytes(entropy, rndBuf, 0, rndBuf.length);
        int idx = 0;
        for (int e = 0; e < paramTau; ++e)
        {
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                System.arraycopy(rndBuf, idx, rndShares[e][p], 0, shareSize);
                idx += shareSize;
            }
        }

        // Per-execution: compute share for each party, commit, build merkle tree.
        // The commitments buffer holds SHA3 outputs (public hashes), so it can
        // safely be reused across executions — every party slot is overwritten
        // before the merkle tree is built.
        byte[][] merkleRoots = new byte[paramTau][hashSize];
        MerkleTree[] merkleTrees = new MerkleTree[paramTau];
        byte[] curShare = new byte[shareSize];
        byte[][] commitments = new byte[paramNbParties][commitSize];
        for (int e = 0; e < paramTau; ++e)
        {
            for (int i = 0; i < paramNbParties; ++i)
            {
                computeCompleteShare(curShare, plain, rndShares[e], i);
                commitShare(commitments[i], curShare, salt, e, i);
            }
            merkleTrees[e] = new MerkleTree(paramNbParties);
            merkleTrees[e].build(commitments);
            System.arraycopy(merkleTrees[e].getRoot(), 0, merkleRoots[e], 0, hashSize);
        }

        // Construct an instance bag (for the H1 hash)
        SDitHEngine.SDitHPublicKeyExpanded instBag = new SDitHEngine.SDitHPublicKeyExpanded();
        instBag.hASeed = sk.hASeed;
        instBag.y = sk.y;
        instBag.hA = sk.hA;

        // Hash for MPC challenge
        byte[] mpcChallengeHash = hashForMpcChallenge(instBag, salt, merkleRoots);
        MpcChallenge mpcCh = expandMpcChallenge(mpcChallengeHash);

        // Compute plain broadcast
        byte[] plainBr = new byte[brSize];
        mpcComputePlainBroadcast(plainBr, mpcCh, plain, sk.hA, sk.y);

        // Compute broadcasts for each rnd share
        byte[][][] broadcasts = new byte[paramTau][paramNbRevealed][brSize];
        for (int e = 0; e < paramTau; ++e)
        {
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                mpcComputeCommunications(broadcasts[e][p], mpcCh, rndShares[e][p], plainBr, sk.hA, sk.y, false);
            }
        }

        // Hash for view challenge
        byte[] viewChalHash = hashForViewChallenge(mpcChallengeHash, broadcasts, plainBr, salt, msg, msgOff, msgLen);
        int[][] openViews = expandViewChallenge(viewChalHash);

        // Build cv_info (auth path) per execution and witness shares for opened parties
        byte[][] cvInfos = new byte[paramTau][];
        byte[][][] witShares = new byte[paramTau][paramNbRevealed][witSize];
        for (int e = 0; e < paramTau; ++e)
        {
            cvInfos[e] = openMerkleTree(merkleTrees[e], openViews[e]);
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                computeShareWit(witShares[e][p], plain, rndShares[e], openViews[e][p]);
            }
        }

        // Serialize signature
        int totalAuth = 0;
        for (int e = 0; e < paramTau; ++e)
        {
            totalAuth += cvInfos[e].length;
        }
        int sigSize = saltSize + hashSize + compressedBrSize
                + paramTau * paramNbRevealed * (brSize + witSize) + totalAuth;
        byte[] sig = new byte[sigSize];
        int off = 0;
        System.arraycopy(salt, 0, sig, off, saltSize);
        off += saltSize;
        System.arraycopy(mpcChallengeHash, 0, sig, off, hashSize);
        off += hashSize;
        System.arraycopy(plainBr, 0, sig, off, compressedBrSize);
        off += compressedBrSize;
        for (int e = 0; e < paramTau; ++e)
        {
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                System.arraycopy(broadcasts[e][p], 0, sig, off, brSize);
                off += brSize;
                System.arraycopy(witShares[e][p], 0, sig, off, witSize);
                off += witSize;
            }
        }
        for (int e = 0; e < paramTau; ++e)
        {
            System.arraycopy(cvInfos[e], 0, sig, off, cvInfos[e].length);
            off += cvInfos[e].length;
        }
        return sig;
    }

    private void computeCorrelated(byte[] share)
    {
        // c[j] = sum_np mul_ext(a[np][j], b[np][j])
        byte[] tmp = new byte[extDegree];
        for (int j = 0; j < paramT; ++j)
        {
            int jOff = j * extDegree;
            for (int b = 0; b < extDegree; ++b)
            {
                share[shareC + jOff + b] = 0;
            }
            for (int np = 0; np < paramD; ++np)
            {
                fpointMulBytes(tmp, 0, share, shareA + (np * paramT + j) * extDegree,
                        share, shareB + (np * paramT + j) * extDegree);
                fpointAddBytes(share, shareC + jOff, share, shareC + jOff, tmp, 0);
            }
        }
    }

    // ----- verification top-level -----

    public boolean verify(SDitHEngine.SDitHPublicKeyExpanded pk, byte[] msg, int msgOff, int msgLen,
                          byte[] sig, int sigOff, int sigLen)
    {
        return doVerify(pk, msg, msgOff, msgLen, sig, sigOff, sigLen);
    }

    private boolean doVerify(SDitHEngine.SDitHPublicKeyExpanded pk, byte[] msg, int msgOff, int msgLen,
                             byte[] sig, int sigOff, int sigLen)
    {
        int minSize = saltSize + hashSize + compressedBrSize
                + paramTau * paramNbRevealed * (brSize + witSize);
        if (sigLen < minSize)
        {
            return false;
        }

        int off = sigOff;
        byte[] salt = new byte[saltSize];
        System.arraycopy(sig, off, salt, 0, saltSize);
        off += saltSize;
        byte[] mpcChallengeHash = new byte[hashSize];
        System.arraycopy(sig, off, mpcChallengeHash, 0, hashSize);
        off += hashSize;
        byte[] plainBr = new byte[brSize];
        // Plain broadcast is stored compressed (no v term).
        System.arraycopy(sig, off, plainBr, 0, compressedBrSize);
        // v portion is implicitly zero.
        off += compressedBrSize;

        byte[][][] broadcasts = new byte[paramTau][paramNbRevealed][brSize];
        byte[][][] witShares = new byte[paramTau][paramNbRevealed][witSize];
        for (int e = 0; e < paramTau; ++e)
        {
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                System.arraycopy(sig, off, broadcasts[e][p], 0, brSize);
                off += brSize;
                System.arraycopy(sig, off, witShares[e][p], 0, witSize);
                off += witSize;
            }
        }

        // Recompute view challenge hash and expand to get open_views
        byte[] viewChalHash = hashForViewChallenge(mpcChallengeHash, broadcasts, plainBr, salt, msg, msgOff, msgLen);
        int[][] openViews = expandViewChallenge(viewChalHash);

        // Determine total cv_info size expected; the remaining bytes must match exactly.
        int expectedAuthTotal = 0;
        int[] perExecAuth = new int[paramTau];
        for (int e = 0; e < paramTau; ++e)
        {
            perExecAuth[e] = getAuthSize(paramLogNbParties, paramNbParties, openViews[e]);
            expectedAuthTotal += perExecAuth[e];
        }
        int expectedTotalSize = (off - sigOff) + expectedAuthTotal;
        if (sigLen != expectedTotalSize)
        {
            return false;
        }

        // Expand MPC challenge and reconstruct per-execution merkle roots.
        // leavesQueue and shareCommitments hold only public SHA3 commit outputs;
        // they are fully overwritten on each execution so reuse is safe.
        MpcChallenge mpcCh = expandMpcChallenge(mpcChallengeHash);
        byte[][] merkleRoots = new byte[paramTau][hashSize];
        byte[] share = new byte[shareSize];
        byte[] shBroadcast = new byte[brSize];
        byte[] leavesQueue = new byte[paramNbRevealed * hashSize];
        byte[] shareCommitments = new byte[paramNbRevealed * hashSize];
        for (int e = 0; e < paramTau; ++e)
        {
            for (int p = 0; p < paramNbRevealed; ++p)
            {
                int i = openViews[e][p];
                // sh_broadcast = compute_share_broadcast(plain_br, broadcasts[e][*], i)
                computeShareBroadcast(shBroadcast, plainBr, broadcasts[e], i);

                // Build share: copy wit, then derive unif and corr via inverse MPC
                java.util.Arrays.fill(share, (byte) 0);
                System.arraycopy(witShares[e][p], 0, share, shareSA, witSize);
                mpcComputeCommunicationsInverse(share, mpcCh, shBroadcast, plainBr, pk.hA, pk.y, i != 0);

                // Commit
                commitShare(shareCommitments, p * hashSize, share, salt, e, i);
            }
            // Recompute merkle root from auth path
            // The leavesQueue starts as the share commitments (in order)
            System.arraycopy(shareCommitments, 0, leavesQueue, 0, paramNbRevealed * hashSize);
            byte[] root = getMerkleRootFromAuth(paramLogNbParties, paramNbParties, openViews[e],
                    leavesQueue, 0, sig, off, perExecAuth[e]);
            if (root == null)
            {
                return false;
            }
            off += perExecAuth[e];
            System.arraycopy(root, 0, merkleRoots[e], 0, hashSize);
        }

        // Build the instance bag (just hASeed and y) for h1 recomputation
        SDitHEngine.SDitHPublicKeyExpanded instBag = new SDitHEngine.SDitHPublicKeyExpanded();
        instBag.hASeed = pk.hASeed;
        instBag.y = pk.y;
        instBag.hA = pk.hA;
        byte[] recomputed = hashForMpcChallenge(instBag, salt, merkleRoots);
        return Arrays.areEqual(recomputed, mpcChallengeHash);
    }

    // commit_share that writes into an offset within a buffer (for the verifier's leavesQueue assembly)
    private void commitShare(byte[] outBuf, int outOff, byte[] share, byte[] salt, int e, int i)
    {
        SDitHHash h = SDitHHash.sha3(hashBits, SDitHHash.HASH_COM);
        h.update(salt, 0, saltSize);
        h.update((byte) (e & 0xff));
        h.update((byte) ((e >>> 8) & 0xff));
        h.update((byte) (i & 0xff));
        h.update((byte) ((i >>> 8) & 0xff));
        h.update(share, 0, shareSize);
        h.doFinal(outBuf, outOff);
    }

    public int maxSignatureSize()
    {
        // Max possible signature size: bounded by treeMaxOpenLeaves authentication nodes per execution.
        return saltSize + hashSize + compressedBrSize
                + paramTau * paramNbRevealed * (brSize + witSize)
                + paramTau * params.getTreeMaxOpenLeaves() * hashSize;
    }
}
