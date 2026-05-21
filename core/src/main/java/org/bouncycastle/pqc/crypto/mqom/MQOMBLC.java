package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * BLC (Batched Line Commitment) for MQOM v2.1: Commit / Open / Eval.
 * Generic across all supported (base, ext) field combinations.
 *
 * <p>raw_i layout per leaf: <code>lseed[i] || PRG-bytes</code>, length
 * <code>byteSizeFieldBase(mqN) + byteSizeFieldExt(eta)</code>. The
 * Gray-code folding accumulator and the per-level folding planes operate on
 * the packed wire form of these bytes (addition over GF(p^k) is byte-wise
 * XOR irrespective of packing density).
 *
 * <p>Instances are not thread-safe — they share scratch buffers with their
 * owning {@link MQOMEngine}.
 */
final class MQOMBLC
{
    private final MQOMParameters params;
    private final MQOMSymmetric sym;
    private final MQOMTrees trees;

    private final int tau;
    private final int seedSize;
    private final int saltSize;
    private final int digestSize;
    private final int nbEvals;
    private final int nbEvalsLog;
    private final int mqN;
    private final int eta;

    private final int baseLog2;
    private final int extLog2;

    /** raw_i length in bytes (= byteSizeBase(n) + byteSizeExt(eta)). */
    private final int rawLen;
    /** Bytes from PRG per leaf = rawLen - seedSize. */
    private final int prgPerLeaf;
    /** Bytes carrying x part inside rawLen. */
    private final int xBytes;
    /** Partial-delta-x length = byteSizeBase(n) - seedSize. */
    private final int partialDeltaXLen;

    /** Length of one extension-field vector of mqN elements (mqN for K=GF(256), 2*mqN for K=GF(256^2)). */
    private final int nExtBytes;
    /** Length of one extension-field vector of eta elements. */
    private final int etaExtBytes;

    static final class Key
    {
        byte[][][] node;
        byte[][][] lsCom;
        byte[][] partialDeltaX;
    }

    /*
     * Scratch — kept as instance fields only where the contents are public
     * (salt-derived, sig-derived, or hash outputs visible in the opening).
     * All witness-derived buffers (raw / acc / folding / lseed / rseedBuf /
     * delta / extTmpN / extTmpEta / accBase) are now allocated per call so
     * secret material does not linger in the engine's heap state.
     */
    private final byte[] scratchTweakedSalt1;   // saltSize  (public salt-derived)
    private final byte[] scratchTweakedSalt2;   // saltSize  (public salt-derived)
    private final byte[] scratchTreePrgSalt;    // saltSize  (zero)
    private final byte[][] scratchHashLsCom;    // [tau][digestSize]  (Hash6 output, public)
    private final byte[][] scratchLsComE;       // [nbEvals][digestSize]  (leaf commitments, public)
    private final byte[][] scratchPath;         // [nbEvalsLog][seedSize]  (sig sibling path, public)
    private final byte[] scratchComputed;       // digestSize  (recomputed com1, verifier-side)

    MQOMBLC(MQOMSymmetric sym)
    {
        this.params = sym.getParameters();
        this.sym = sym;
        this.trees = new MQOMTrees(sym);

        this.tau = params.getTau();
        this.seedSize = params.getSeedSize();
        this.saltSize = params.getSaltSize();
        this.digestSize = params.getDigestSize();
        this.nbEvals = params.getNbEvals();
        this.nbEvalsLog = params.getNbEvalsLog();
        this.mqN = params.getMqN();
        this.eta = params.getEta();
        this.baseLog2 = params.getBaseFieldLog2();
        this.extLog2 = params.getExtFieldLog2();

        this.xBytes = params.getByteSizeFieldBase(mqN);
        int uBytes = params.getByteSizeFieldBase(eta * params.getMu()); // = byteSizeExt(eta)
        this.rawLen = xBytes + uBytes;
        this.prgPerLeaf = rawLen - seedSize;
        this.partialDeltaXLen = xBytes - seedSize;

        int extBytesPerElt = extLog2 / 8;
        this.nExtBytes = mqN * extBytesPerElt;
        this.etaExtBytes = eta * extBytesPerElt;

        this.scratchTweakedSalt1 = new byte[saltSize];
        this.scratchTweakedSalt2 = new byte[saltSize];
        this.scratchTreePrgSalt = new byte[saltSize];
        this.scratchHashLsCom = new byte[tau][digestSize];
        this.scratchLsComE = new byte[nbEvals][digestSize];
        this.scratchPath = new byte[nbEvalsLog][seedSize];
        this.scratchComputed = new byte[digestSize];
    }

    void commit(byte[] mseed,
                byte[] salt,
                byte[] xPacked,
                byte[] com1,
                Key key,
                byte[][] x0Ext,
                byte[][] u0Ext,
                byte[][] u1Ext)
    {
        int fullTreeSize = params.getFullTreeSize();

        // Sensitive scratch — per-call so witness-derived material does not
        // outlive this commit() invocation.
        byte[] rseedBuf = new byte[tau * seedSize];
        byte[] delta = new byte[seedSize];
        byte[] raw = new byte[rawLen];
        byte[] acc = new byte[rawLen];
        byte[][] dataFolding = new byte[nbEvalsLog][rawLen];
        byte[][] lseed = new byte[nbEvals][seedSize];
        byte[] extTmpN = new byte[nExtBytes];
        byte[] extTmpEta = new byte[etaExtBytes];

        sym.prg(scratchTreePrgSalt, 0, mseed, 0, tau * seedSize, rseedBuf, 0);
        System.arraycopy(xPacked, 0, delta, 0, seedSize);

        key.node = new byte[tau][fullTreeSize + 1][seedSize];
        key.lsCom = new byte[tau][nbEvals][digestSize];
        key.partialDeltaX = new byte[tau][partialDeltaXLen];

        byte[][] hashLsCom = scratchHashLsCom;

        for (int e = 0; e < tau; e++)
        {
            trees.expand(salt, rseedBuf, e * seedSize, delta, 0, e, key.node[e], lseed);

            sym.tweakSalt(salt, scratchTweakedSalt1, 0, e, 0);
            System.arraycopy(scratchTweakedSalt1, 0, scratchTweakedSalt2, 0, saltSize);
            scratchTweakedSalt2[0] ^= 0x01;
            Object commitCtx1 = sym.encKeySched(scratchTweakedSalt1, 0);
            Object commitCtx2 = sym.encKeySched(scratchTweakedSalt2, 0);

            zero(acc);
            for (int j = 0; j < nbEvalsLog; j++)
            {
                zero(dataFolding[j]);
            }

            for (int i = 0; i < nbEvals; i++)
            {
                sym.seedCommit(commitCtx1, commitCtx2, lseed[i], 0, key.lsCom[e][i], 0);

                // raw[i] = lseed[i] || PRG(...)
                System.arraycopy(lseed[i], 0, raw, 0, seedSize);
                sym.prg(salt, e, lseed[i], 0, prgPerLeaf, raw, seedSize);

                for (int b = 0; b < rawLen; b++)
                {
                    acc[b] ^= raw[b];
                }
                int gp = MQOMField.grayCodeBitPosition(i, nbEvals);
                for (int b = 0; b < rawLen; b++)
                {
                    dataFolding[gp][b] ^= acc[b];
                }
            }

            // u1[e] = u_Acc. The u-part of acc is already in the packed K layout
            // since the in-memory and wire forms coincide for both K = GF(256)
            // and K = GF(256^2).
            System.arraycopy(acc, xBytes, u1Ext[e], 0, etaExtBytes);

            // x0[e] (in K^n) = sum_j (1<<j) * lift_to_K(parsedFolding[j])
            zero(x0Ext[e]);
            for (int j = 0; j < nbEvalsLog; j++)
            {
                addBaseScaledIntoExt(1 << j, dataFolding[j], 0, x0Ext[e], extTmpN);
            }
            // u0[e] (in K^eta) = sum_j (1<<j) * data_folding[j][xBytes..]
            zero(u0Ext[e]);
            for (int j = 0; j < nbEvalsLog; j++)
            {
                addExtScaledIntoExt(1 << j, dataFolding[j], xBytes, u0Ext[e], extTmpEta);
            }

            for (int b = 0; b < partialDeltaXLen; b++)
            {
                key.partialDeltaX[e][b] = (byte)((xPacked[seedSize + b] ^ acc[seedSize + b]) & 0xFF);
            }

            SHAKEDigest xof = sym.newXof();
            sym.xofUpdateTag(xof, 6);
            for (int i = 0; i < nbEvals; i++)
            {
                xof.update(key.lsCom[e][i], 0, digestSize);
            }
            sym.xofSqueeze(xof, hashLsCom[e], 0, digestSize);
        }

        SHAKEDigest xof = sym.newXof();
        sym.xofUpdateTag(xof, 7);
        for (int e = 0; e < tau; e++)
        {
            xof.update(hashLsCom[e], 0, digestSize);
        }
        for (int e = 0; e < tau; e++)
        {
            xof.update(key.partialDeltaX[e], 0, partialDeltaXLen);
        }
        sym.xofSqueeze(xof, com1, 0, digestSize);
    }

    void open(Key key, int[] iStar, byte[] opening, int openingOff)
    {
        int pathBlockLen = nbEvalsLog * seedSize;
        int basePath = openingOff;
        int baseLsCom = openingOff + tau * pathBlockLen;
        int basePartial = baseLsCom + tau * digestSize;

        byte[][] path = scratchPath;
        for (int e = 0; e < tau; e++)
        {
            trees.open(key.node[e], iStar[e], path);
            int pathOff = basePath + e * pathBlockLen;
            for (int j = 0; j < nbEvalsLog; j++)
            {
                System.arraycopy(path[j], 0, opening, pathOff + j * seedSize, seedSize);
            }
            System.arraycopy(key.lsCom[e][iStar[e]], 0, opening, baseLsCom + e * digestSize, digestSize);
            System.arraycopy(key.partialDeltaX[e], 0, opening, basePartial + e * partialDeltaXLen, partialDeltaXLen);
        }
    }

    boolean eval(byte[] salt,
                 byte[] com1,
                 byte[] opening, int openingOff,
                 int[] iStar,
                 byte[][] xEvalExt,
                 byte[][] uEvalExt)
    {
        int pathBlockLen = nbEvalsLog * seedSize;
        int basePath = openingOff;
        int baseLsCom = openingOff + tau * pathBlockLen;
        int basePartial = baseLsCom + tau * digestSize;

        byte[][] hashLsCom = scratchHashLsCom;
        // Sensitive on the commit side; on this verifier side the same buffer
        // shape is derived from public sig + iStar (so the data here is
        // public). Allocating per-call anyway keeps the commit/verify code
        // symmetrical and avoids one path of memory-shape coupling.
        byte[][] lseed = new byte[nbEvals][seedSize];
        byte[] raw = new byte[rawLen];
        byte[] acc = new byte[rawLen];
        byte[][] dataFolding = new byte[nbEvalsLog][rawLen];
        byte[] accBase = new byte[xBytes];
        byte[] extTmpN = new byte[nExtBytes];
        byte[] extTmpEta = new byte[etaExtBytes];
        byte[][] lsComE = scratchLsComE;
        byte[][] path = scratchPath;

        for (int e = 0; e < tau; e++)
        {
            int pathOff = basePath + e * pathBlockLen;
            for (int j = 0; j < nbEvalsLog; j++)
            {
                System.arraycopy(opening, pathOff + j * seedSize, path[j], 0, seedSize);
            }
            trees.partiallyExpand(salt, path, e, iStar[e], lseed);

            sym.tweakSalt(salt, scratchTweakedSalt1, 0, e, 0);
            System.arraycopy(scratchTweakedSalt1, 0, scratchTweakedSalt2, 0, saltSize);
            scratchTweakedSalt2[0] ^= 0x01;
            Object commitCtx1 = sym.encKeySched(scratchTweakedSalt1, 0);
            Object commitCtx2 = sym.encKeySched(scratchTweakedSalt2, 0);

            zero(acc);
            for (int j = 0; j < nbEvalsLog; j++)
            {
                zero(dataFolding[j]);
            }

            for (int i = 0; i < nbEvals; i++)
            {
                sym.seedCommit(commitCtx1, commitCtx2, lseed[i], 0, lsComE[i], 0);

                if (i == iStar[e])
                {
                    // Hidden leaf: take the committed digest from the opening
                    // and treat raw as zero (lseed[i_star] = 0 already).
                    System.arraycopy(opening, baseLsCom + e * digestSize, lsComE[i], 0, digestSize);
                    zero(raw);
                }
                else
                {
                    System.arraycopy(lseed[i], 0, raw, 0, seedSize);
                    sym.prg(salt, e, lseed[i], 0, prgPerLeaf, raw, seedSize);
                }

                for (int b = 0; b < rawLen; b++)
                {
                    acc[b] ^= raw[b];
                }
                int gp = MQOMField.grayCodeBitPosition(i, nbEvals);
                for (int b = 0; b < rawLen; b++)
                {
                    dataFolding[gp][b] ^= acc[b];
                }
            }

            int r = MQOMField.evaluationPoint(iStar[e], extLog2);

            // x_eval[e] = sum_j (1<<j) * lift(data_folding[j]_x) + r * (acc_x XOR delta_x_verifier)
            zero(xEvalExt[e]);
            for (int j = 0; j < nbEvalsLog; j++)
            {
                addBaseScaledIntoExt(1 << j, dataFolding[j], 0, xEvalExt[e], extTmpN);
            }
            // accBase = acc_x XOR delta_x_verifier (first seedSize bytes zero, rest from partial_delta_x).
            for (int b = 0; b < seedSize; b++)
            {
                accBase[b] = acc[b];
            }
            for (int b = seedSize; b < xBytes; b++)
            {
                accBase[b] = (byte)((acc[b] ^ opening[basePartial + e * partialDeltaXLen + (b - seedSize)]) & 0xFF);
            }
            extBaseConstantVectMult(r, accBase, 0, extTmpN, 0, mqN);
            xorIntoExt(xEvalExt[e], extTmpN);

            // u_eval[e] = sum_j (1<<j) * data_folding[j]_u + r * acc_u
            zero(uEvalExt[e]);
            for (int j = 0; j < nbEvalsLog; j++)
            {
                addExtScaledIntoExt(1 << j, dataFolding[j], xBytes, uEvalExt[e], extTmpEta);
            }
            extConstantExtVectMult(r, acc, xBytes, extTmpEta, 0, eta);
            xorIntoExt(uEvalExt[e], extTmpEta);

            SHAKEDigest xof = sym.newXof();
            sym.xofUpdateTag(xof, 6);
            for (int i = 0; i < nbEvals; i++)
            {
                xof.update(lsComE[i], 0, digestSize);
            }
            sym.xofSqueeze(xof, hashLsCom[e], 0, digestSize);
        }

        SHAKEDigest xof = sym.newXof();
        sym.xofUpdateTag(xof, 7);
        for (int e = 0; e < tau; e++)
        {
            xof.update(hashLsCom[e], 0, digestSize);
        }
        for (int e = 0; e < tau; e++)
        {
            xof.update(opening, basePartial + e * partialDeltaXLen, partialDeltaXLen);
        }
        byte[] computed = scratchComputed;
        sym.xofSqueeze(xof, computed, 0, digestSize);
        for (int i = 0; i < digestSize; i++)
        {
            if (computed[i] != com1[i])
            {
                return false;
            }
        }
        return true;
    }

    /* ====================== helpers ====================== */

    private static void zero(byte[] b)
    {
        for (int i = 0; i < b.length; i++)
        {
            b[i] = 0;
        }
    }

    /** target ^= coef * lift(packedBase[off..]); writes through the caller-owned {@code tmp}. */
    private void addBaseScaledIntoExt(int coef, byte[] packed, int off, byte[] target, byte[] tmp)
    {
        if (extLog2 == 8)
        {
            MQOMField.extBaseConstantVectMult_gf256(baseLog2, coef, packed, off, tmp, 0, mqN);
        }
        else
        {
            MQOMField.extBaseConstantVectMult_gf256to2(baseLog2, coef, packed, off, tmp, 0, mqN);
        }
        for (int i = 0; i < nExtBytes; i++)
        {
            target[i] = (byte)((target[i] ^ tmp[i]) & 0xFF);
        }
    }

    /** target ^= coef * (extPacked from off, eta K-elements); writes through the caller-owned {@code tmp}. */
    private void addExtScaledIntoExt(int coef, byte[] extPacked, int off, byte[] target, byte[] tmp)
    {
        if (extLog2 == 8)
        {
            MQOMField.gf256ConstantVectMult(coef, extPacked, off, tmp, 0, eta);
        }
        else
        {
            MQOMField.gf256to2ConstantVectMult(coef, extPacked, off, tmp, 0, eta);
        }
        for (int i = 0; i < etaExtBytes; i++)
        {
            target[i] = (byte)((target[i] ^ tmp[i]) & 0xFF);
        }
    }

    private static void xorIntoExt(byte[] target, byte[] add)
    {
        for (int i = 0; i < target.length; i++)
        {
            target[i] = (byte)((target[i] ^ add[i]) & 0xFF);
        }
    }

    private void extBaseConstantVectMult(int r, byte[] base, int baseOff, byte[] out, int outOff, int n)
    {
        if (extLog2 == 8)
        {
            MQOMField.extBaseConstantVectMult_gf256(baseLog2, r, base, baseOff, out, outOff, n);
        }
        else
        {
            MQOMField.extBaseConstantVectMult_gf256to2(baseLog2, r, base, baseOff, out, outOff, n);
        }
    }

    private void extConstantExtVectMult(int r, byte[] extPacked, int off, byte[] out, int outOff, int n)
    {
        if (extLog2 == 8)
        {
            MQOMField.gf256ConstantVectMult(r, extPacked, off, out, outOff, n);
        }
        else
        {
            MQOMField.gf256to2ConstantVectMult(r, extPacked, off, out, outOff, n);
        }
    }
}
