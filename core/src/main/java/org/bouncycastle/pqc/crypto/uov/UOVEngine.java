package org.bouncycastle.pqc.crypto.uov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.raw.GF16;
import org.bouncycastle.math.raw.GF256AES;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Reference-style engine for the classic UOV signature scheme, ported from the
 * pqov reference C implementation (src/ref/blas_matrix_ref.c, src/ov.c,
 * src/ov_keypair.c, src/parallel_matrix_op.c).
 * <p>
 * <strong>Variant:</strong> classic only — uncompressed public and secret keys.
 * The PKC and PKC-SKC compressed forms will be added in follow-up changes.
 * <p>
 * <strong>Public key layout (classic):</strong> P1 || P2 || P3, where P1 is a
 * batched upper-triangular V×V matrix, P2 is a V×O rectangular matrix and P3
 * is a batched upper-triangular O×O matrix. Each batched cell holds m=O
 * coefficients (one per equation) packed as either m bytes (GF256) or m/2
 * bytes (GF16).
 * <p>
 * <strong>Secret key layout (classic):</strong> sk_seed (32 bytes) || O
 * (V×O matrix, column-major) || P1 (same bytes as in pk) || S (= F2, the
 * linear-system matrix used during signing).
 */
final class UOVEngine
{
    private final UOVParameters params;
    private final boolean gf16;
    private final int v;
    private final int m;
    private final int n;
    private final int vByte;
    private final int oByte;
    private final int nByte;
    private final int mByte;
    private final int pkP1Bytes;
    private final int pkP2Bytes;
    private final int pkP3Bytes;
    private final int oMapBytes;

    public UOVEngine(UOVParameters params)
    {
        this.params = params;
        this.gf16 = params.isGF16();
        this.v = params.getV();
        this.m = params.getM();
        this.n = params.getN();
        this.vByte = params.getVByte();
        this.oByte = params.getOByte();
        this.nByte = params.getNByte();
        this.mByte = params.getMByte();
        this.pkP1Bytes = params.getPkP1Bytes();
        this.pkP2Bytes = params.getPkP2Bytes();
        this.pkP3Bytes = params.getPkP3Bytes();
        this.oMapBytes = params.getOMapBytes();
    }

    public UOVParameters getParameters()
    {
        return params;
    }

    public byte[][] generateKeyPair(SecureRandom random)
    {
        byte[] skSeed = new byte[UOVParameters.SK_SEED_BYTES];
        random.nextBytes(skSeed);
        return generateKeyPair(skSeed);
    }

    /**
     * UOV key generation from a fixed 32-byte seed. The returned pk/sk
     * encoding follows the parameter set's variant — classic emits the full
     * pk/sk; PKC emits (pk_seed||P3) and full sk; PKC-SKC emits (pk_seed||P3)
     * and seed-only sk. Returns {pk, sk}.
     */
    public byte[][] generateKeyPair(byte[] skSeed)
    {
        if (skSeed == null || skSeed.length != UOVParameters.SK_SEED_BYTES)
        {
            throw new IllegalArgumentException("sk_seed must be " + UOVParameters.SK_SEED_BYTES + " bytes");
        }

        // Always run the classic key-expansion path internally to obtain P1, P2,
        // P3 and F2 — variant only affects which subset is serialised.
        byte[] expanded = shake256(skSeed, UOVParameters.PK_SEED_BYTES + oMapBytes);
        byte[] classicSk = null;
        try
        {
            // pkSeed lives at expanded[0..PK_SEED_BYTES); oMap (secret) lives at
            // expanded[PK_SEED_BYTES..]. Read pkSeed in place from `expanded`
            // (16 bytes, public) and oMap in place too — avoids duplicating
            // the multi-MB secret buffer.
            int oMapInExp = UOVParameters.PK_SEED_BYTES;

            byte[] p1p2 = aesCtrPrng(expanded, 0, pkP1Bytes + pkP2Bytes);

            // Build full classic pk so we can compute P3 in place (all public).
            byte[] classicPk = new byte[pkP1Bytes + pkP2Bytes + pkP3Bytes];
            System.arraycopy(p1p2, 0, classicPk, 0, pkP1Bytes + pkP2Bytes);

            // Build full classic sk so we can compute F2 in place (SECRET).
            int classicSkBytes = UOVParameters.SK_SEED_BYTES + oMapBytes + pkP1Bytes + pkP2Bytes;
            classicSk = new byte[classicSkBytes];
            System.arraycopy(skSeed, 0, classicSk, 0, UOVParameters.SK_SEED_BYTES);
            System.arraycopy(expanded, oMapInExp, classicSk, UOVParameters.SK_SEED_BYTES, oMapBytes);
            System.arraycopy(p1p2, 0, classicSk, UOVParameters.SK_SEED_BYTES + oMapBytes, pkP1Bytes);

            int skSOff = UOVParameters.SK_SEED_BYTES + oMapBytes + pkP1Bytes;
            int pkP3Off = pkP1Bytes + pkP2Bytes;
            calculateF2P3(classicSk, skSOff, classicPk, pkP3Off, classicPk, 0, p1p2, pkP1Bytes, expanded, oMapInExp);

            byte[] pk;
            if (params.isCompressedPublicKey())
            {
                pk = new byte[UOVParameters.PK_SEED_BYTES + pkP3Bytes];
                System.arraycopy(expanded, 0, pk, 0, UOVParameters.PK_SEED_BYTES);
                System.arraycopy(classicPk, pkP3Off, pk, UOVParameters.PK_SEED_BYTES, pkP3Bytes);
            }
            else
            {
                pk = classicPk;
            }

            byte[] sk;
            if (params.isCompressedSecretKey())
            {
                sk = Arrays.clone(skSeed);
                // classicSk is discarded — let the finally scrub it.
            }
            else
            {
                sk = classicSk;
                classicSk = null; // ownership transferred to caller; do not scrub.
            }
            return new byte[][]{pk, sk};
        }
        finally
        {
            // expanded contains pk_seed (public) + O (secret); scrub the whole
            // thing for simplicity. classicSk only needs scrubbing in the
            // PKC-SKC path (where it isn't returned).
            java.util.Arrays.fill(expanded, (byte)0);
            if (classicSk != null)
            {
                java.util.Arrays.fill(classicSk, (byte)0);
            }
        }
    }

    /**
     * Re-derive the classic public-key encoding (P1 || P2 || P3) from a
     * compressed (pk_seed || P3) input.
     */
    public byte[] expandPublicKey(byte[] compressedPk)
    {
        if (compressedPk == null || compressedPk.length != UOVParameters.PK_SEED_BYTES + pkP3Bytes)
        {
            throw new IllegalArgumentException("compressed pk wrong length for " + params.getName());
        }
        // Read pk_seed in place from compressedPk (16 bytes, public).
        byte[] p1p2 = aesCtrPrng(compressedPk, 0, pkP1Bytes + pkP2Bytes);
        byte[] classicPk = new byte[pkP1Bytes + pkP2Bytes + pkP3Bytes];
        System.arraycopy(p1p2, 0, classicPk, 0, pkP1Bytes + pkP2Bytes);
        System.arraycopy(compressedPk, UOVParameters.PK_SEED_BYTES, classicPk, pkP1Bytes + pkP2Bytes, pkP3Bytes);
        return classicPk;
    }

    /**
     * Re-derive the full classic secret-key encoding from a 32-byte seed.
     */
    public byte[] expandSecretKey(byte[] skSeed)
    {
        if (skSeed == null || skSeed.length != UOVParameters.SK_SEED_BYTES)
        {
            throw new IllegalArgumentException("sk_seed must be " + UOVParameters.SK_SEED_BYTES + " bytes");
        }
        byte[] expanded = shake256(skSeed, UOVParameters.PK_SEED_BYTES + oMapBytes);
        // pk_seed lives at expanded[0..PK_SEED_BYTES) (public); oMap lives at
        // expanded[PK_SEED_BYTES..] (secret). Read pk_seed in place — no
        // copyOfRange needed.
        int oMapInExp = UOVParameters.PK_SEED_BYTES;

        byte[] p1p2 = aesCtrPrng(expanded, 0, pkP1Bytes + pkP2Bytes);

        int classicSkBytes = UOVParameters.SK_SEED_BYTES + oMapBytes + pkP1Bytes + pkP2Bytes;
        byte[] classicSk = new byte[classicSkBytes];
        System.arraycopy(skSeed, 0, classicSk, 0, UOVParameters.SK_SEED_BYTES);
        System.arraycopy(expanded, oMapInExp, classicSk, UOVParameters.SK_SEED_BYTES, oMapBytes);
        System.arraycopy(p1p2, 0, classicSk, UOVParameters.SK_SEED_BYTES + oMapBytes, pkP1Bytes);

        // calculate_F2 in reference: S = P2; S += (P1 + P1^T) * O.
        // (P1 + P1^T) has zero diagonal in char 2, so executing trimat and
        // trimat-transpose sequentially cancels the diagonal duplication
        // automatically (this is what batch_2trimat_madd_gf{16,256} encodes
        // explicitly via the diagonal-memset in the reference C).
        int sOff = UOVParameters.SK_SEED_BYTES + oMapBytes + pkP1Bytes;
        System.arraycopy(p1p2, pkP1Bytes, classicSk, sOff, pkP2Bytes);
        batchTrimatMadd(classicSk, sOff, p1p2, 0, expanded, oMapInExp, v, vByte, m, oByte);
        batchTrimatTrMadd(classicSk, sOff, p1p2, 0, expanded, oMapInExp, v, vByte, m, oByte);
        // expanded holds O (secret) — scrub before drop; pkSeed and p1p2 are
        // public so don't need scrubbing here.
        java.util.Arrays.fill(expanded, (byte)0);
        return classicSk;
    }

    /**
     * UOV sign: produces a signature of {@code params.getSignatureBytes()}
     * bytes (n bytes packed || 16-byte salt). If the parameter set is the
     * PKC-SKC variant (sk = sk_seed only), the full secret key is first
     * expanded internally.
     */
    public byte[] sign(byte[] sk, byte[] message, SecureRandom random)
    {
        if (sk == null)
        {
            throw new IllegalArgumentException("sk cannot be null");
        }
        byte[] owned = null;
        try
        {
            if (params.isCompressedSecretKey())
            {
                // expandSecretKey validates sk.length == SK_SEED_BYTES.
                owned = expandSecretKey(sk);
                sk = owned;
            }
            else if (sk.length != params.getClassicSecretKeyBytes())
            {
                throw new IllegalArgumentException("sk wrong length for " + params.getName());
            }
            return signInternal(sk, message, random);
        }
        finally
        {
            // If we expanded the seed, the expanded buffer is locally owned
            // and secret — scrub it. The caller's array stays untouched.
            if (owned != null)
            {
                java.util.Arrays.fill(owned, (byte)0);
            }
        }
    }

    /**
     * Variant of {@link #sign(byte[], byte[], SecureRandom)} that reads the
     * caller-supplied secret-key parameters' internal bytes directly without
     * cloning. Saves multi-MB allocations per sign for the classic / PKC
     * variants (where the full sk is held in the params object).
     */
    public byte[] sign(UOVPrivateKeyParameters privKey, byte[] message, SecureRandom random)
    {
        if (privKey == null)
        {
            throw new IllegalArgumentException("privKey cannot be null");
        }
        if (privKey.getParameters() != params && !privKey.getParameters().getName().equals(params.getName()))
        {
            throw new IllegalArgumentException("private key parameter set " + privKey.getParameters().getName()
                + " does not match engine " + params.getName());
        }
        byte[] sk = privKey.borrowEncoded();
        byte[] owned = null;
        try
        {
            if (params.isCompressedSecretKey())
            {
                // expandSecretKey allocates a fresh full sk from the borrowed
                // seed; no clone of the caller's array is needed.
                owned = expandSecretKey(sk);
                sk = owned;
            }
            // Length was already validated in the params constructor.
            return signInternal(sk, message, random);
        }
        finally
        {
            if (owned != null)
            {
                java.util.Arrays.fill(owned, (byte)0);
            }
        }
    }

    private byte[] signInternal(byte[] sk, byte[] message, SecureRandom random)
    {
        int skSeedOff = 0;
        int oMapOff = UOVParameters.SK_SEED_BYTES;
        int p1Off = oMapOff + oMapBytes;
        int sOff = p1Off + pkP1Bytes;

        byte[] salt = new byte[UOVParameters.SALT_BYTES];
        random.nextBytes(salt);

        SHAKEDigest msgSalt = new SHAKEDigest(256);
        msgSalt.update(message, 0, message.length);
        msgSalt.update(salt, 0, UOVParameters.SALT_BYTES);

        SHAKEDigest withSecret = new SHAKEDigest(msgSalt);
        withSecret.update(sk, skSeedOff, UOVParameters.SK_SEED_BYTES);

        byte[] y = new byte[mByte];
        msgSalt.doFinal(y, 0, mByte);

        // Secret intermediate buffers. y, salt, w, sig stay public (they end
        // up in or are derived from the signature itself).
        byte[] vinegar = new byte[vByte];
        byte[] xOil = new byte[oByte];
        byte[] matL1 = new byte[m * oByte];
        byte[] rhs = new byte[oByte];
        byte[] oTimesX = null;

        try
        {
            boolean solved = false;
            for (int attempt = 0; attempt < 256; attempt++)
            {
                SHAKEDigest h = new SHAKEDigest(withSecret);
                h.update((byte)(attempt & 0xff));
                h.doFinal(vinegar, 0, vByte);

                gfmatProd(matL1, sk, sOff, m * oByte, v, vinegar);

                batchQuadTrimatEval(rhs, sk, p1Off, vinegar, v, mByte);
                for (int i = 0; i < mByte; i++)
                {
                    rhs[i] ^= y[i];
                }

                int rank = gaussianElim(matL1, rhs, m);
                if (rank == 0)
                {
                    continue;
                }
                backSubstitute(rhs, matL1, m);
                System.arraycopy(rhs, 0, xOil, 0, oByte);
                solved = true;
                break;
            }

            if (!solved)
            {
                throw new IllegalStateException("UOV signing exhausted vinegar attempts");
            }

            // Write the signature directly — sig[0..vByte] = vinegar XOR
            // O*x_oil, sig[vByte..nByte] = x_oil, sig[nByte..] = salt. The
            // intermediate `w` buffer from the previous version was just an
            // alias for sig[0..nByte] before the salt was appended; folding
            // it into sig avoids one nByte allocation + copy per sign.
            byte[] sig = new byte[params.getSignatureBytes()];
            System.arraycopy(vinegar, 0, sig, 0, vByte);
            System.arraycopy(xOil, 0, sig, vByte, oByte);

            oTimesX = new byte[vByte];
            gfmatProd(oTimesX, sk, oMapOff, vByte, m, xOil);
            for (int i = 0; i < vByte; i++)
            {
                sig[i] ^= oTimesX[i];
            }

            System.arraycopy(salt, 0, sig, nByte, UOVParameters.SALT_BYTES);
            return sig;
        }
        finally
        {
            // Scrub all secret-correlated intermediates. The SHAKE state
            // `withSecret` (seeded with sk_seed) doesn't expose a zeroise
            // hook in BC's SHAKEDigest; rely on the local going out of scope
            // and GC clearing memory in due course.
            java.util.Arrays.fill(vinegar, (byte)0);
            java.util.Arrays.fill(xOil, (byte)0);
            java.util.Arrays.fill(matL1, (byte)0);
            java.util.Arrays.fill(rhs, (byte)0);
            if (oTimesX != null)
            {
                java.util.Arrays.fill(oTimesX, (byte)0);
            }
        }
    }

    /**
     * UOV verify. Accepts either the classic public key or the compressed
     * (pk_seed || P3) form, depending on the parameter set's variant — the
     * compressed form is expanded to classic before evaluation.
     */
    public boolean verify(byte[] pk, byte[] message, byte[] sig)
    {
        if (sig == null || sig.length != params.getSignatureBytes())
        {
            return false;
        }
        if (pk == null)
        {
            throw new IllegalArgumentException("pk cannot be null");
        }
        if (params.isCompressedPublicKey())
        {
            // expandPublicKey validates pk.length == PK_SEED_BYTES + pkP3Bytes.
            pk = expandPublicKey(pk);
        }
        else if (pk.length != params.getClassicPublicKeyBytes())
        {
            throw new IllegalArgumentException("pk wrong length for " + params.getName());
        }
        return verifyInternal(pk, message, sig);
    }

    /**
     * Variant of {@link #verify(byte[], byte[], byte[])} that reads the
     * caller-supplied public-key parameters' internal bytes directly without
     * cloning. Saves multi-MB allocations per verify for the classic
     * variant.
     */
    public boolean verify(UOVPublicKeyParameters pubKey, byte[] message, byte[] sig)
    {
        if (sig == null || sig.length != params.getSignatureBytes())
        {
            return false;
        }
        if (pubKey == null)
        {
            throw new IllegalArgumentException("pubKey cannot be null");
        }
        if (pubKey.getParameters() != params && !pubKey.getParameters().getName().equals(params.getName()))
        {
            throw new IllegalArgumentException("public key parameter set " + pubKey.getParameters().getName()
                + " does not match engine " + params.getName());
        }
        byte[] pk = pubKey.borrowEncoded();
        if (params.isCompressedPublicKey())
        {
            // expandPublicKey allocates a fresh full pk; no clone needed.
            pk = expandPublicKey(pk);
        }
        return verifyInternal(pk, message, sig);
    }

    private boolean verifyInternal(byte[] pk, byte[] message, byte[] sig)
    {
        byte[] expected = new byte[mByte];
        SHAKEDigest h = new SHAKEDigest(256);
        h.update(message, 0, message.length);
        h.update(sig, nByte, UOVParameters.SALT_BYTES);
        h.doFinal(expected, 0, mByte);

        byte[] computed = new byte[mByte];
        publicMap(computed, pk, sig);
        return Arrays.constantTimeAreEqual(expected, computed);
    }

    // -------------- batched matrix ops (reference path) --------------------

    void calculateF2P3(byte[] s, int sOff, byte[] p3, int p3Off, byte[] p1Src, int p1Off, byte[] p2Src, int p2Off,
                      byte[] oMap, int oMapOff)
    {
        if (s != p2Src || sOff != p2Off)
        {
            System.arraycopy(p2Src, p2Off, s, sOff, pkP2Bytes);
        }
        batchTrimatMadd(s, sOff, p1Src, p1Off, oMap, oMapOff, v, vByte, m, oByte);
        batchUpperMatTrXMat(p3, p3Off, oMap, oMapOff, v, vByte, m, s, sOff, m, oByte);
        batchTrimatTrMadd(s, sOff, p1Src, p1Off, oMap, oMapOff, v, vByte, m, oByte);
    }

    private void batchTrimatMadd(byte[] bC, int cOff, byte[] btriA, int aOff, byte[] b, int bOff,
                                 int bHeight, int sizeBcolvec, int bWidth, int sizeBatch)
    {
        if (gf16)
        {
            batchTrimatMaddGF16(bC, cOff, btriA, aOff, b, bOff, bHeight, sizeBcolvec, bWidth, sizeBatch);
        }
        else
        {
            batchTrimatMaddGF256(bC, cOff, btriA, aOff, b, bOff, bHeight, sizeBcolvec, bWidth, sizeBatch);
        }
    }

    private void batchTrimatTrMadd(byte[] bC, int cOff, byte[] btriA, int aOff, byte[] b, int bOff,
                                   int bHeight, int sizeBcolvec, int bWidth, int sizeBatch)
    {
        if (gf16)
        {
            batchTrimatTrMaddGF16(bC, cOff, btriA, aOff, b, bOff, bHeight, sizeBcolvec, bWidth, sizeBatch);
        }
        else
        {
            batchTrimatTrMaddGF256(bC, cOff, btriA, aOff, b, bOff, bHeight, sizeBcolvec, bWidth, sizeBatch);
        }
    }

    private void batchUpperMatTrXMat(byte[] bC, int cOff, byte[] aToTr, int aOff, int aHeight, int sizeAcolvec,
                                     int aWidth, byte[] bB, int bOff, int bWidth, int sizeBatch)
    {
        if (gf16)
        {
            batchUpperMatTrXMatGF16(bC, cOff, aToTr, aOff, aHeight, sizeAcolvec, aWidth, bB, bOff, bWidth, sizeBatch);
        }
        else
        {
            batchUpperMatTrXMatGF256(bC, cOff, aToTr, aOff, aHeight, sizeAcolvec, aWidth, bB, bOff, bWidth, sizeBatch);
        }
    }

    private void batchTrimatMaddGF256(byte[] bC, int cOff, byte[] btriA, int aOff, byte[] b, int bOff,
                                      int bHeight, int sizeBcolvec, int bWidth, int sizeBatch)
    {
        byte[] tmp = new byte[sizeBatch];
        int aHeight = bHeight;
        for (int i = 0; i < aHeight; i++)
        {
            for (int j = 0; j < bWidth; j++)
            {
                gf256MatProd(tmp, 0, btriA, aOff, sizeBatch, aHeight - i, b, bOff + j * sizeBcolvec + i);
                GF.vecAdd(bC, cOff, tmp, 0, sizeBatch);
                cOff += sizeBatch;
            }
            aOff += sizeBatch * (aHeight - i);
        }
    }

    private void batchTrimatMaddGF16(byte[] bC, int cOff, byte[] btriA, int aOff, byte[] b, int bOff,
                                     int bHeight, int sizeBcolvec, int bWidth, int sizeBatch)
    {
        int aHeight = bHeight;
        byte[] b2 = new byte[bWidth * sizeBcolvec];
        for (int i = 0; i < bWidth; i++)
        {
            int base = bOff + i * sizeBcolvec;
            for (int j = 0; j < sizeBcolvec - 1; j++)
            {
                b2[i * sizeBcolvec + j] = (byte)(((b[base + j] & 0xff) >>> 4) | ((b[base + j + 1] & 0xff) << 4));
            }
            b2[i * sizeBcolvec + sizeBcolvec - 1] = (byte)((b[base + sizeBcolvec - 1] & 0xff) >>> 4);
        }
        byte[] tmp = new byte[sizeBatch];
        for (int i = 0; i < aHeight; i += 2)
        {
            for (int j = 0; j < bWidth; j++)
            {
                gf16MatProd(tmp, 0, btriA, aOff, sizeBatch, aHeight - i, b, bOff + j * sizeBcolvec + (i / 2));
                GF.vecAdd(bC, cOff, tmp, 0, sizeBatch);
                cOff += sizeBatch;
            }
            aOff += sizeBatch * (aHeight - i);
            for (int j = 0; j < bWidth; j++)
            {
                gf16MatProd(tmp, 0, btriA, aOff, sizeBatch, aHeight - i - 1, b2, j * sizeBcolvec + (i / 2));
                GF.vecAdd(bC, cOff, tmp, 0, sizeBatch);
                cOff += sizeBatch;
            }
            aOff += sizeBatch * (aHeight - i - 1);
        }
    }

    private void batchTrimatTrMaddGF256(byte[] bC, int cOff, byte[] btriA, int aOff, byte[] b, int bOff,
                                        int bHeight, int sizeBcolvec, int bWidth, int sizeBatch)
    {
        int aHeight = bHeight;
        byte[] row = new byte[aHeight * sizeBatch];
        for (int i = 0; i < aHeight; i++)
        {
            int ptr = aOff + i * sizeBatch;
            for (int j = 0; j < i; j++)
            {
                System.arraycopy(btriA, ptr, row, j * sizeBatch, sizeBatch);
                ptr += (aHeight - j - 1) * sizeBatch;
            }
            System.arraycopy(btriA, ptr, row, i * sizeBatch, sizeBatch);

            byte[] tmp = new byte[sizeBatch];
            for (int j = 0; j < bWidth; j++)
            {
                gf256MatProd(tmp, 0, row, 0, sizeBatch, i + 1, b, bOff + j * sizeBcolvec);
                GF.vecAdd(bC, cOff, tmp, 0, sizeBatch);
                cOff += sizeBatch;
            }
        }
    }

    private void batchTrimatTrMaddGF16(byte[] bC, int cOff, byte[] btriA, int aOff, byte[] b, int bOff,
                                       int bHeight, int sizeBcolvec, int bWidth, int sizeBatch)
    {
        int aHeight = bHeight;
        byte[] row = new byte[aHeight * sizeBatch];
        byte[] tmp = new byte[sizeBatch];
        for (int i = 0; i < aHeight; i++)
        {
            int ptr = aOff + i * sizeBatch;
            for (int j = 0; j < i; j++)
            {
                System.arraycopy(btriA, ptr, row, j * sizeBatch, sizeBatch);
                ptr += (aHeight - j - 1) * sizeBatch;
            }
            System.arraycopy(btriA, ptr, row, i * sizeBatch, sizeBatch);

            for (int j = 0; j < bWidth; j++)
            {
                gf16MatProd(tmp, 0, row, 0, sizeBatch, i + 1, b, bOff + j * sizeBcolvec);
                GF.vecAdd(bC, cOff, tmp, 0, sizeBatch);
                cOff += sizeBatch;
            }
        }
    }

    private void batchUpperMatTrXMatGF256(byte[] bC, int cOff, byte[] aToTr, int aOff, int aHeight, int sizeAcolvec,
                                          int aWidth, byte[] bB, int bOff, int bWidth, int sizeBatch)
    {
        int atrHeight = aWidth;
        int atrWidth = aHeight;
        byte[] row = new byte[bWidth * sizeBatch];
        for (int i = 0; i < atrHeight; i++)
        {
            gf256MatProd(row, 0, bB, bOff, bWidth * sizeBatch, atrWidth, aToTr, aOff + sizeAcolvec * i);
            int ptr = cOff + i * sizeBatch;
            for (int j = 0; j < i; j++)
            {
                GF.vecAdd(bC, ptr, row, j * sizeBatch, sizeBatch);
                ptr += (bWidth - j - 1) * sizeBatch;
            }
            System.arraycopy(row, i * sizeBatch, bC, ptr, sizeBatch * (bWidth - i));
        }
    }

    private void batchUpperMatTrXMatGF16(byte[] bC, int cOff, byte[] aToTr, int aOff, int aHeight, int sizeAcolvec,
                                         int aWidth, byte[] bB, int bOff, int bWidth, int sizeBatch)
    {
        int atrHeight = aWidth;
        int atrWidth = aHeight;
        byte[] row = new byte[bWidth * sizeBatch];
        for (int i = 0; i < atrHeight; i++)
        {
            gf16MatProd(row, 0, bB, bOff, bWidth * sizeBatch, atrWidth, aToTr, aOff + sizeAcolvec * i);
            int ptr = cOff + i * sizeBatch;
            for (int j = 0; j < i; j++)
            {
                GF.vecAdd(bC, ptr, row, j * sizeBatch, sizeBatch);
                ptr += (bWidth - j - 1) * sizeBatch;
            }
            System.arraycopy(row, i * sizeBatch, bC, ptr, sizeBatch * (bWidth - i));
        }
    }

    // -------------- gfmat_prod (reference) --------------------------------

    private void gfmatProd(byte[] c, byte[] matA, int aOff, int vecBytes, int width, byte[] b)
    {
        if (gf16)
        {
            gf16MatProd(c, 0, matA, aOff, vecBytes, width, b, 0);
        }
        else
        {
            gf256MatProd(c, 0, matA, aOff, vecBytes, width, b, 0);
        }
    }

    private static void gf256MatProd(byte[] c, int cOff, byte[] matA, int aOff, int vecBytes, int width,
                                     byte[] b, int bOff)
    {
        java.util.Arrays.fill(c, cOff, cOff + vecBytes, (byte)0);
        for (int i = 0; i < width; i++)
        {
            GF.vecMadd256(c, cOff, matA, aOff, b[bOff + i] & 0xff, vecBytes);
            aOff += vecBytes;
        }
    }

    private static void gf16MatProd(byte[] c, int cOff, byte[] matA, int aOff, int vecBytes, int width,
                                    byte[] b, int bOff)
    {
        java.util.Arrays.fill(c, cOff, cOff + vecBytes, (byte)0);
        for (int i = 0; i < width; i++)
        {
            int bb = GF.getEle16(b, bOff * 2 + i);
            // ^ when b is packed and bOff is a byte offset, accessing the i-th nibble.
            GF.vecMadd16(c, cOff, matA, aOff, bb, vecBytes);
            aOff += vecBytes;
        }
    }

    // -------------- batch_quad_trimat_eval (reference) --------------------

    private void batchQuadTrimatEval(byte[] y, byte[] trimat, int aOff, byte[] x, int dim, int sizeBatch)
    {
        if (gf16)
        {
            batchQuadTrimatEvalGF16(y, trimat, aOff, x, dim, sizeBatch);
        }
        else
        {
            batchQuadTrimatEvalGF256(y, trimat, aOff, x, dim, sizeBatch);
        }
    }

    private static void batchQuadTrimatEvalGF256(byte[] y, byte[] trimat, int aOff, byte[] x, int dim, int sizeBatch)
    {
        java.util.Arrays.fill(y, 0, sizeBatch, (byte)0);
        byte[] tmp = new byte[sizeBatch];
        for (int i = 0; i < dim; i++)
        {
            gf256MatProd(tmp, 0, trimat, aOff, sizeBatch, dim - i, x, i);
            GF.vecMadd256(y, 0, tmp, 0, x[i] & 0xff, sizeBatch);
            aOff += (dim - i) * sizeBatch;
        }
    }

    private static void batchQuadTrimatEvalGF16(byte[] y, byte[] trimat, int aOff, byte[] x, int dim, int sizeBatch)
    {
        java.util.Arrays.fill(y, 0, sizeBatch, (byte)0);
        byte[] tmp = new byte[sizeBatch];
        int xByteLen = (dim + 1) >>> 1;
        byte[] x2 = new byte[xByteLen];
        for (int j = 0; j < xByteLen - 1; j++)
        {
            x2[j] = (byte)(((x[j] & 0xff) >>> 4) | ((x[j + 1] & 0xff) << 4));
        }
        x2[xByteLen - 1] = (byte)((x[xByteLen - 1] & 0xff) >>> 4);

        for (int i = 0; i < dim; i += 2)
        {
            gf16MatProd(tmp, 0, trimat, aOff, sizeBatch, dim - i, x, i / 2);
            GF.vecMadd16(y, 0, tmp, 0, GF.getEle16(x, i), sizeBatch);
            aOff += (dim - i) * sizeBatch;

            gf16MatProd(tmp, 0, trimat, aOff, sizeBatch, dim - i - 1, x2, i / 2);
            GF.vecMadd16(y, 0, tmp, 0, GF.getEle16(x, i + 1), sizeBatch);
            aOff += (dim - i - 1) * sizeBatch;
        }
    }

    // -------------- ov_publicmap (reference simplified) -------------------

    void publicMap(byte[] y, byte[] pk, byte[] w)
    {
        // y[k] = sum_{0<=i<=j<N} Q[i][j][k] * w[i] * w[j] where the upper-
        // triangular pk is stored as three contiguous blocks P1 || P2 || P3:
        //   P1: 0 <= i <= j < V                      (V*(V+1)/2 cells)
        //   P2: 0 <= i < V, V <= j < N               (V*O cells)
        //   P3: V <= i <= j < N                      (O*(O+1)/2 cells)
        // Each cell is sizeBatch=mByte bytes. The standard
        // batch_quad_trimat_eval(y, pk, w, n, mByte) form would assume
        // P1/P2 interleaved row-by-row — the pqov pk layout does NOT, so we
        // walk the three regions explicitly.
        if (gf16)
        {
            publicMapGF16(y, pk, w);
        }
        else
        {
            publicMapGF256(y, pk, w);
        }
    }

    private void publicMapGF256(byte[] y, byte[] pk, byte[] w)
    {
        java.util.Arrays.fill(y, 0, mByte, (byte)0);
        byte[] tmp = new byte[mByte];
        int p1Off = 0;
        int p2Off = pkP1Bytes;
        int p3Off = pkP1Bytes + pkP2Bytes;

        // P1 + P2 rows
        for (int i = 0; i < v; i++)
        {
            // tmp = sum_{j=i..V-1} P1[i][j-i] * w[j]
            gf256MatProd(tmp, 0, pk, p1Off, mByte, v - i, w, i);
            // tmp += sum_{j=0..O-1} P2[i][j] * w[V+j]
            for (int j = 0; j < m; j++)
            {
                GF.vecMadd256(tmp, 0, pk, p2Off + j * mByte, w[v + j] & 0xff, mByte);
            }
            GF.vecMadd256(y, 0, tmp, 0, w[i] & 0xff, mByte);
            p1Off += (v - i) * mByte;
            p2Off += m * mByte;
        }
        // P3 rows
        for (int i = 0; i < m; i++)
        {
            gf256MatProd(tmp, 0, pk, p3Off, mByte, m - i, w, v + i);
            GF.vecMadd256(y, 0, tmp, 0, w[v + i] & 0xff, mByte);
            p3Off += (m - i) * mByte;
        }
    }

    private void publicMapGF16(byte[] y, byte[] pk, byte[] w)
    {
        java.util.Arrays.fill(y, 0, mByte, (byte)0);
        byte[] tmp = new byte[mByte];
        int p1Off = 0;
        int p2Off = pkP1Bytes;
        int p3Off = pkP1Bytes + pkP2Bytes;

        // We need a packed "w[i:]" pointer; use the dual-byte preshift trick
        // for odd column offsets, matching the gf16 trimat eval path.
        byte[] wShift = new byte[nByte];
        for (int j = 0; j < nByte - 1; j++)
        {
            wShift[j] = (byte)(((w[j] & 0xff) >>> 4) | ((w[j + 1] & 0xff) << 4));
        }
        wShift[nByte - 1] = (byte)((w[nByte - 1] & 0xff) >>> 4);

        // P1: rows i in [0, V), columns j in [i, V)
        for (int i = 0; i < v; i++)
        {
            byte[] src = (i % 2 == 0) ? w : wShift;
            int srcOff = i / 2;
            gf16MatProd(tmp, 0, pk, p1Off, mByte, v - i, src, srcOff);
            // P2 contribution: P2[i] is a row of m cells, multiplied by w[V..V+m-1]
            for (int j = 0; j < m; j++)
            {
                GF.vecMadd16(tmp, 0, pk, p2Off + j * mByte, GF.getEle16(w, v + j), mByte);
            }
            GF.vecMadd16(y, 0, tmp, 0, GF.getEle16(w, i), mByte);
            p1Off += (v - i) * mByte;
            p2Off += m * mByte;
        }
        // P3: rows i' in [0, O), columns j' in [i', O), accessed via w[V+i'..V+O-1]
        for (int i = 0; i < m; i++)
        {
            int colIdx = v + i;
            byte[] src = (colIdx % 2 == 0) ? w : wShift;
            int srcOff = colIdx / 2;
            gf16MatProd(tmp, 0, pk, p3Off, mByte, m - i, src, srcOff);
            GF.vecMadd16(y, 0, tmp, 0, GF.getEle16(w, colIdx), mByte);
            p3Off += (m - i) * mByte;
        }
    }

    // -------------- gaussian elimination + back substitute ---------------
    //
    // Input layout (matches reference C):
    //   sqmat_a (len*len bytes for GF256, len*len/2 bytes for GF16) stored
    //   column-major: column j is the j-th oil-variable's coefficients
    //   across the m=len equations.
    //   constant (mByte bytes packed) is the RHS.
    //
    // After gaussianElim returns rank=1, sqmat_a is rewritten in ROW-MAJOR
    // upper-triangular row-echelon form, with constant updated. Then
    // backSubstitute resolves constant in-place to the oil solution.

    int gaussianElim(byte[] sqmatA, byte[] constant, int len)
    {
        if (gf16)
        {
            return gaussianElimGF16(sqmatA, constant, len);
        }
        return gaussianElimGF256(sqmatA, constant, len);
    }

    void backSubstitute(byte[] constant, byte[] sqRowMatA, int len)
    {
        if (gf16)
        {
            backSubstituteGF16(constant, sqRowMatA, len);
        }
        else
        {
            backSubstituteGF256(constant, sqRowMatA, len);
        }
    }

    private static int gaussianElimGF256(byte[] sqmatA, byte[] constant, int len)
    {
        int height = len;
        int width = len + 1; // augmented column
        byte[] mat = new byte[height * width];
        try
        {
            for (int i = 0; i < height; i++)
            {
                int aiOff = i * width;
                for (int j = 0; j < height; j++)
                {
                    mat[aiOff + j] = sqmatA[j * len + i];
                }
                mat[aiOff + height] = constant[i];
            }
            int r8 = 1;
            for (int i = 0; i < height; i++)
            {
                int aiOff = i * width;
                int iStart = i;
                for (int j = i + 1; j < height; j++)
                {
                    int ajOff = j * width;
                    int condition = 1 - GF.isNonzero256(mat[aiOff + i] & 0xff);
                    GF.vecConditionalAdd(mat, aiOff + iStart, condition, mat, ajOff + iStart, width - iStart);
                }
                int pivot = mat[aiOff + i] & 0xff;
                r8 &= GF.isNonzero256(pivot);
                int inv = GF256AES.inv(pivot);
                GF.vecMulScalar256(mat, aiOff + iStart, inv, width - iStart);
                for (int j = i + 1; j < height; j++)
                {
                    int ajOff = j * width;
                    GF.vecMadd256(mat, ajOff + iStart, mat, aiOff + iStart, mat[ajOff + i] & 0xff,
                        width - iStart);
                }
            }
            for (int i = 0; i < height; i++)
            {
                int aiOff = i * width;
                System.arraycopy(mat, aiOff, sqmatA, i * len, len);
                constant[i] = mat[aiOff + len];
            }
            return r8;
        }
        finally
        {
            // mat is the transposed augmented matrix in row-major form;
            // every cell is secret-correlated (derived from F2 and rhs).
            java.util.Arrays.fill(mat, (byte)0);
        }
    }

    private static void backSubstituteGF256(byte[] constant, byte[] sqRowMatA, int len)
    {
        byte[] column = new byte[len];
        try
        {
            for (int i = len - 1; i > 0; i--)
            {
                for (int j = 0; j < i; j++)
                {
                    column[j] = sqRowMatA[j * len + i];
                }
                int c = constant[i] & 0xff;
                for (int j = 0; j < i; j++)
                {
                    constant[j] ^= (byte)GF256AES.mul(column[j] & 0xff, c);
                }
            }
        }
        finally
        {
            // column holds extracted secret-correlated values from sqRowMatA.
            java.util.Arrays.fill(column, (byte)0);
        }
    }

    private static int gaussianElimGF16(byte[] sqmatA, byte[] constant, int len)
    {
        // Internal mat is row-major with len columns + 1 augmented column,
        // packed at 4 bits per element. We allocate one byte per element here
        // for simplicity; the row-echelon form will be re-packed at the end.
        int height = len;
        byte[] mat = new byte[height * (len + 1)];
        try
        {
            for (int i = 0; i < height; i++)
            {
                int aiOff = i * (len + 1);
                for (int j = 0; j < height; j++)
                {
                    mat[aiOff + j] = (byte)GF.getEle16(sqmatA, j * len + i);
                }
                mat[aiOff + len] = (byte)GF.getEle16(constant, i);
            }
            int r8 = 1;
            for (int i = 0; i < height; i++)
            {
                int aiOff = i * (len + 1);
                for (int j = i + 1; j < height; j++)
                {
                    int ajOff = j * (len + 1);
                    int condition = 1 - GF.isNonzero16(mat[aiOff + i] & 0xf);
                    int mask = -(condition & 1);
                    for (int kk = i; kk <= len; kk++)
                    {
                        mat[aiOff + kk] ^= (byte)(mat[ajOff + kk] & mask);
                    }
                }
                int pivot = mat[aiOff + i] & 0xf;
                r8 &= GF.isNonzero16(pivot);
                int inv = GF16.inv(pivot);
                for (int kk = i; kk <= len; kk++)
                {
                    mat[aiOff + kk] = (byte)GF16.mul(mat[aiOff + kk] & 0xf, inv);
                }
                for (int j = i + 1; j < height; j++)
                {
                    int ajOff = j * (len + 1);
                    // No `if (scalar != 0)` guard: scalar is the leading
                    // coefficient of a secret-derived row, so branching on its
                    // zero-ness leaks one bit of timing per sub-diagonal row per
                    // pivot. GF16.mul returns 0 for a zero scalar, so the
                    // unconditional madd is functionally identical. Matches the
                    // reference gf16mat_gauss_elim_row_echolen, which calls
                    // gf16v_madd unconditionally (src/ref/blas_matrix_ref.c).
                    int scalar = mat[ajOff + i] & 0xf;
                    for (int kk = i; kk <= len; kk++)
                    {
                        mat[ajOff + kk] ^= (byte)GF16.mul(mat[aiOff + kk] & 0xf, scalar);
                    }
                }
            }
            java.util.Arrays.fill(sqmatA, (byte)0);
            for (int i = 0; i < height; i++)
            {
                int aiOff = i * (len + 1);
                for (int j = 0; j < len; j++)
                {
                    GF.setEle16(sqmatA, i * len + j, mat[aiOff + j] & 0xf);
                }
                GF.setEle16(constant, i, mat[aiOff + len] & 0xf);
            }
            return r8;
        }
        finally
        {
            // mat holds the augmented matrix in unpacked form — every byte
            // is a secret-correlated nibble. Scrub before drop.
            java.util.Arrays.fill(mat, (byte)0);
        }
    }

    private static void backSubstituteGF16(byte[] constant, byte[] sqRowMatA, int len)
    {
        for (int i = len - 1; i > 0; i--)
        {
            int c = GF.getEle16(constant, i);
            for (int j = 0; j < i; j++)
            {
                int v = GF.getEle16(sqRowMatA, j * len + i);
                int currentJ = GF.getEle16(constant, j);
                GF.setEle16(constant, j, currentJ ^ GF16.mul(v, c));
            }
        }
    }

    // -------------- AES-128-CTR public-inputs PRNG -----------------------

    private static byte[] aesCtrPrng(byte[] key16, int outLen)
    {
        return aesCtrPrng(key16, 0, outLen);
    }

    /**
     * AES-128-CTR PRNG matching pqov's <code>prng_publicinputs_t</code>.
     * Key, nonce (zero), and output are all public ("public inputs") — the
     * key {@code pk_seed} is part of the compressed public key and the
     * output is {@code P1 || P2}, the public coefficients of the
     * public-key polynomial. No secret data flows through this function, so
     * encrypting in place into {@code out} is safe (no need to scrub a
     * scratch buffer).
     */
    private static byte[] aesCtrPrng(byte[] keySrc, int keyOff, int outLen)
    {
        AESEngine aes = new AESEngine();
        byte[] key16;
        if (keyOff == 0 && keySrc.length == 16)
        {
            key16 = keySrc;
        }
        else
        {
            key16 = new byte[16];
            System.arraycopy(keySrc, keyOff, key16, 0, 16);
        }
        aes.init(true, new KeyParameter(key16));
        byte[] out = new byte[outLen];
        byte[] counterBlock = new byte[16];
        // The reference packs the counter big-endian into the last 4 bytes
        // of the AES input block; the first 12 bytes are the zero nonce.
        int counter = 0;
        int written = 0;
        // Full 16-byte blocks: encrypt directly into the destination — avoids
        // per-block 16-byte scratch allocations (pkP1+pkP2 is ~2.4 MB for
        // uov-V, i.e. ~150k blocks per keygen). The branch on `written + 16
        // <= outLen` depends only on the algorithm parameter set, not on any
        // secret material.
        while (written + 16 <= outLen)
        {
            Pack.intToBigEndian(counter, counterBlock, 12);
            aes.processBlock(counterBlock, 0, out, written);
            written += 16;
            counter++;
        }
        // Trailing partial block, if any.
        if (written < outLen)
        {
            Pack.intToBigEndian(counter, counterBlock, 12);
            byte[] block = new byte[16];
            aes.processBlock(counterBlock, 0, block, 0);
            System.arraycopy(block, 0, out, written, outLen - written);
        }
        return out;
    }

    private static byte[] shake256(byte[] input, int outLen)
    {
        SHAKEDigest s = new SHAKEDigest(256);
        s.update(input, 0, input.length);
        byte[] out = new byte[outLen];
        s.doFinal(out, 0, outLen);
        return out;
    }
}
