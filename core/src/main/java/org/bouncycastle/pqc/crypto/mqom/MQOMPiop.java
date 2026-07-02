package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.raw.GF256AES;

/**
 * ComputePAlpha / RecomputePAlpha (spec algorithms 6-9). Supports both
 * r3 (Gamma = identity) and r5 variants (Gamma drawn via XOF8). The
 * field arithmetic dispatches on the (base, ext) field combination of
 * the parameter set.
 *
 * <p>Instances are not thread-safe — large scratch buffers (notably the
 * per-equation matrix A_hat, which can reach ~864&nbsp;KB on Cat5
 * short-r5 parameter sets) are reused across calls.
 */
final class MQOMPiop
{
    private final MQOMParameters params;
    private final MQOMSymmetric sym;
    private final MQOMExpand expand;
    private final int n;
    private final int m;
    private final int eta;
    private final int tau;
    private final int baseLog2;
    private final int extLog2;
    private final int extBytesPerElt;
    private final boolean batching;

    /*
     * Scratch — only buffers holding *public* derivatives are kept as instance
     * fields. aHat / bHat / gamma are deterministic from the public mseed_eq
     * (which lives in the public key), so they're effectively public knowledge
     * and safe to retain. The verify-side vt / tmp / vz buffers receive
     * derivatives of the public sig-derived xEval / y, also safe.
     *
     * Sign-side t0, t1, t1Cache, z0, z1 contain values linear in the witness
     * x (notably t1Cache[i] = A_i·x + b_i, which directly reveals x once m of
     * them are known) and are now allocated per call so they do not linger in
     * the engine's heap state.
     */
    private final byte[] scratchAHat;        // m*n*n*extBytes  (public, mseed_eq-derived)
    private final byte[] scratchBHat;        // m*n*extBytes    (public)
    private final byte[] scratchGamma;       // eta*m*extBytes  (public; null when not batching)
    private final byte[] scratchVt;          // n*extBytes      (verify-side, public)
    private final byte[] scratchTmp;         // n*extBytes      (verify-side, public)
    private final byte[] scratchVz;          // m*extBytes      (verify-side, public)

    MQOMPiop(MQOMSymmetric sym)
    {
        this.params = sym.getParameters();
        this.sym = sym;
        this.expand = new MQOMExpand(sym);
        this.n = params.getMqN();
        this.m = params.getMqM() / params.getMu();
        this.eta = params.getEta();
        this.tau = params.getTau();
        this.baseLog2 = params.getBaseFieldLog2();
        this.extLog2 = params.getExtFieldLog2();
        this.extBytesPerElt = extLog2 / 8;
        this.batching = params.getVariant() == MQOMParameters.VARIANT_R5;

        int nBytesExt = n * extBytesPerElt;
        int mBytesExt = m * extBytesPerElt;
        this.scratchAHat = new byte[m * n * n * extBytesPerElt];
        this.scratchBHat = new byte[m * n * extBytesPerElt];
        this.scratchGamma = batching ? new byte[eta * m * extBytesPerElt] : null;
        this.scratchVt = new byte[nBytesExt];
        this.scratchTmp = new byte[nBytesExt];
        this.scratchVz = new byte[mBytesExt];
    }

    void computePAlpha(byte[] com, byte[] mseedEq,
                       byte[] xPacked,
                       byte[][] x0,
                       byte[][] u0,
                       byte[][] u1,
                       byte[][] alpha0,
                       byte[][] alpha1)
    {
        byte[] aHat = scratchAHat;
        byte[] bHat = scratchBHat;
        expand.expand(mseedEq, aHat, bHat);

        // Optionally expand the Gamma batching matrix (eta * m elements in K).
        byte[] gamma = null;
        if (batching)
        {
            gamma = scratchGamma;
            SHAKEDigest xof = sym.newXof();
            sym.xofUpdateTag(xof, 8);
            xof.update(com, 0, params.getDigestSize());
            sym.xofSqueeze(xof, gamma, 0, gamma.length);
        }

        int nBytesExt = n * extBytesPerElt;
        int mBytesExt = m * extBytesPerElt;
        // Witness-derived scratch — per-call so it does not outlive this
        // computePAlpha() invocation. t1Cache[i] = A_i·x + b_i is linear in
        // the secret x; with m such rows and public A_i / b_i, an attacker
        // who can read process memory could recover x.
        byte[] t0 = new byte[nBytesExt];
        byte[] t1 = new byte[nBytesExt];
        byte[][] t1Cache = new byte[m][nBytesExt];
        boolean[] t1Cached = new boolean[m];

        byte[] z0 = new byte[mBytesExt];
        byte[] z1 = new byte[mBytesExt];

        for (int e = 0; e < tau; e++)
        {
            for (int i = 0; i < m; i++)
            {
                extMatMultTriInf(aHat, i * n * n * extBytesPerElt, x0[e], 0, t0, 0);
                if (!t1Cached[i])
                {
                    extBaseMatMultTriInf(aHat, i * n * n * extBytesPerElt, xPacked, 0, t1Cache[i], 0);
                    // t1Cache[i] ^= bHat[i*...]
                    for (int b = 0; b < nBytesExt; b++)
                    {
                        t1Cache[i][b] = (byte)((t1Cache[i][b] ^ bHat[i * nBytesExt + b]) & 0xFF);
                    }
                    t1Cached[i] = true;
                }
                System.arraycopy(t1Cache[i], 0, t1, 0, nBytesExt);

                int z0i = extVectMult(t0, 0, x0[e], 0, n);
                int t0x = extVectMult(t1, 0, x0[e], 0, n);
                int t1x0 = baseExtVectMult(xPacked, 0, t0, 0, n);
                int z1i = (t0x ^ t1x0) & maskExt();
                packExt(z0, i, z0i);
                packExt(z1, i, z1i);
            }

            if (!batching)
            {
                // alpha0[e] = u0[e] XOR z0; alpha1[e] = u1[e] XOR z1
                int len = eta * extBytesPerElt;
                for (int b = 0; b < len; b++)
                {
                    alpha0[e][b] = (byte)((u0[e][b] ^ z0[b]) & 0xFF);
                    alpha1[e][b] = (byte)((u1[e][b] ^ z1[b]) & 0xFF);
                }
            }
            else
            {
                // alpha0[e][i] = u0[e][i] + sum_j Gamma[i][j] * z0[j]
                // alpha1[e][i] = u1[e][i] + sum_j Gamma[i][j] * z1[j]
                for (int i = 0; i < eta; i++)
                {
                    int g0 = gammaDot(gamma, i, z0);
                    int g1 = gammaDot(gamma, i, z1);
                    int u0i = unpackExt(u0[e], i);
                    int u1i = unpackExt(u1[e], i);
                    packExt(alpha0[e], i, u0i ^ g0);
                    packExt(alpha1[e], i, u1i ^ g1);
                }
            }
        }
    }

    void recomputePAlpha(byte[] com, byte[] mseedEq,
                         byte[] y,
                         int[] iStar,
                         byte[][] xEval,
                         byte[][] uEval,
                         byte[][] alpha1,
                         byte[][] alpha0)
    {
        byte[] aHat = scratchAHat;
        byte[] bHat = scratchBHat;
        expand.expand(mseedEq, aHat, bHat);

        byte[] gamma = null;
        if (batching)
        {
            gamma = scratchGamma;
            SHAKEDigest xof = sym.newXof();
            sym.xofUpdateTag(xof, 8);
            xof.update(com, 0, params.getDigestSize());
            sym.xofSqueeze(xof, gamma, 0, gamma.length);
        }

        int nBytesExt = n * extBytesPerElt;

        byte[] vt = scratchVt;
        byte[] tmp = scratchTmp;
        byte[] vz = scratchVz;

        for (int e = 0; e < tau; e++)
        {
            int r = MQOMField.evaluationPoint(iStar[e], extLog2);
            int r2 = extMult(r, r);

            for (int i = 0; i < m; i++)
            {
                extMatMultTriInf(aHat, i * n * n * extBytesPerElt, xEval[e], 0, tmp, 0);
                extConstantVectMult(r, bHat, i * nBytesExt, vt, 0, n);
                for (int b = 0; b < nBytesExt; b++)
                {
                    vt[b] = (byte)((vt[b] ^ tmp[b]) & 0xFF);
                }
                int vzi = extVectMult(vt, 0, xEval[e], 0, n);
                int yi = unpackExt(y, i);
                vzi ^= extMult(yi, r2);
                packExt(vz, i, vzi);
            }

            if (!batching)
            {
                for (int i = 0; i < eta; i++)
                {
                    int vAlpha = unpackExt(uEval[e], i) ^ unpackExt(vz, i);
                    int alpha1r = extMult(unpackExt(alpha1[e], i), r);
                    packExt(alpha0[e], i, vAlpha ^ alpha1r);
                }
            }
            else
            {
                for (int i = 0; i < eta; i++)
                {
                    int vAlpha = unpackExt(uEval[e], i) ^ gammaDot(gamma, i, vz);
                    int alpha1r = extMult(unpackExt(alpha1[e], i), r);
                    packExt(alpha0[e], i, vAlpha ^ alpha1r);
                }
            }
        }
    }

    /* ----------------------- ext-field helpers ----------------------- */

    private int maskExt()
    {
        return (extLog2 == 8) ? 0xFF : 0xFFFF;
    }

    private int unpackExt(byte[] vec, int i)
    {
        if (extLog2 == 8) return vec[i] & 0xFF;
        return MQOMField.gf256to2GetElt(vec, 0, i);
    }

    private void packExt(byte[] vec, int i, int v)
    {
        if (extLog2 == 8) vec[i] = (byte)(v & 0xFF);
        else MQOMField.gf256to2PutElt(vec, 0, i, v);
    }

    private int extMult(int a, int b)
    {
        return (extLog2 == 8) ? GF256AES.mul(a, b) : MQOMField.gf256to2Mult(a, b);
    }

    private int extVectMult(byte[] a, int aOff, byte[] b, int bOff, int len)
    {
        return (extLog2 == 8)
            ? MQOMField.gf256VectMult(a, aOff, b, bOff, len)
            : MQOMField.gf256to2VectMult(a, aOff, b, bOff, len);
    }

    private void extConstantVectMult(int s, byte[] b, int bOff, byte[] c, int cOff, int n)
    {
        if (extLog2 == 8) MQOMField.gf256ConstantVectMult(s, b, bOff, c, cOff, n);
        else MQOMField.gf256to2ConstantVectMult(s, b, bOff, c, cOff, n);
    }

    private void extMatMultTriInf(byte[] a, int aOff, byte[] x, int xOff, byte[] y, int yOff)
    {
        if (extLog2 == 8) MQOMField.gf256MatMultTriInf(a, aOff, x, xOff, y, yOff, n);
        else MQOMField.gf256to2MatMultTriInf(a, aOff, x, xOff, y, yOff, n);
    }

    private void extBaseMatMultTriInf(byte[] a, int aOff, byte[] xBase, int xOff, byte[] y, int yOff)
    {
        if (extLog2 == 8) MQOMField.extBaseMatMultTriInf_gf256(baseLog2, a, aOff, xBase, xOff, y, yOff, n);
        else MQOMField.extBaseMatMultTriInf_gf256to2(baseLog2, a, aOff, xBase, xOff, y, yOff, n);
    }

    private int baseExtVectMult(byte[] aBase, int aOff, byte[] bExt, int bOff, int n)
    {
        return (extLog2 == 8)
            ? MQOMField.baseExtVectMult_baseToGf256(baseLog2, aBase, aOff, bExt, bOff, n)
            : MQOMField.baseExtVectMult_baseToGf256to2(baseLog2, aBase, aOff, bExt, bOff, n);
    }

    /** sum_j Gamma[i][j] * z[j] in K. */
    private int gammaDot(byte[] gamma, int i, byte[] z)
    {
        int rowOff = i * m * extBytesPerElt;
        return extVectMult(gamma, rowOff, z, 0, m);
    }
}
