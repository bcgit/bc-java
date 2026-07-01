package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.math.raw.GF256AES;
import org.bouncycastle.util.Pack;

/**
 * Low-level GF arithmetic for MQOM v2.1. Each field family in MQOM
 * (GF(2), GF(4), GF(16), GF(256), GF(256^2)) has its own packing and
 * multiplication rules; this class is a single place that mirrors the
 * <code>fields_ref.h</code> primitives from the upstream C reference.
 *
 * <p>Element conventions:
 * <ul>
 *  <li>GF(256): single byte, Rijndael polynomial x^8 + x^4 + x^3 + x + 1
 *      (0x11B), primitive element xi = 3.
 *  <li>GF(256^2): two-byte little-endian (a1 high, a0 low) for the element
 *      a0 + a1 * X with reduction polynomial X^2 + X + 32 over GF(256).
 *  <li>GF(16), GF(4), GF(2): right-justified in low bits of a byte, with
 *      packing densities 2, 4, 8 elements/byte respectively.
 * </ul>
 *
 * <p>Vector ops operate on the natural packed wire format. Subfield
 * embeddings (GF(2) -> GF(256), GF(4) -> GF(256), GF(16) -> GF(256), and
 * lifts of those to GF(256^2)) follow the exact polynomial maps in the
 * reference; KAT-level interop with the C code depends on this.
 */
final class MQOMField
{
    private MQOMField()
    {
    }

    /* ===================================================================
     * GF(256) -- a single byte, Rijndael polynomial.
     * =================================================================== */

    static void gf256ConstantVectMult(int a, byte[] b, int bOff, byte[] c, int cOff, int len)
    {
        // Constant-time c[i] = a * b[i]: word-parallel over eight lanes per long
        // via the shared GF256AES.mulFx8, scalar tail via GF256AES.mul. The previous
        // form had aa==0/aa==1 scalar fast-paths and a per-element bi==0 branch
        // over EXP_TABLE/LOG_TABLE indices, all secret-dependent on the MPCitH
        // path. Byte-identical, table-free, no data-dependent branch.
        int i = 0;
        for (; i + 8 <= len; i += 8)
        {
            Pack.longToLittleEndian(GF256AES.mulFx8(a, Pack.littleEndianToLong(b, bOff + i)), c, cOff + i);
        }
        for (; i < len; i++)
        {
            c[cOff + i] = (byte)GF256AES.mul(a, b[bOff + i] & 0xFF);
        }
    }

    static int gf256VectMult(byte[] a, int aOff, byte[] b, int bOff, int len)
    {
        // Constant-time dot product sum_i a[i]*b[i]. Element-wise GF256AES.mul is
        // table-free and handles zero operands correctly, so the previous
        // ai!=0 && bi!=0 branch over EXP_TABLE/LOG_TABLE indices — secret-
        // dependent on the MPCitH path — is gone. Byte-identical.
        int acc = 0;
        for (int i = 0; i < len; i++)
        {
            acc ^= GF256AES.mul(a[aOff + i] & 0xFF, b[bOff + i] & 0xFF);
        }
        return acc & 0xFF;
    }

    /**
     * Y[j] = sum_{k=0..j} A[j][k] * X[k] over GF(256), with the n*n matrix
     * stored row-major, lower-triangular.
     *
     * <p>Output {@code y} must NOT alias input {@code x} — writing y[j]
     * would corrupt x[j] before later j iterations read it.
     */
    static void gf256MatMultTriInf(byte[] a, int aOff, byte[] x, int xOff, byte[] y, int yOff, int n)
    {
        for (int j = 0; j < n; j++)
        {
            y[yOff + j] = (byte)gf256VectMult(a, aOff + j * n, x, xOff, j + 1);
        }
    }

    /* ===================================================================
     * GF(256^2) = GF(256)[X] / (X^2 + X + 32).
     * Element stored as int with low byte = a0, high byte = a1.
     * Vectors stored as 2 bytes per element, little-endian.
     * =================================================================== */

    static int gf256to2Mult(int a, int b)
    {
        int a0 = a & 0xFF;
        int a1 = (a >>> 8) & 0xFF;
        int b0 = b & 0xFF;
        int b1 = (b >>> 8) & 0xFF;
        int a1b1 = GF256AES.mul(a1, b1);
        int a0b0 = GF256AES.mul(a0, b0);
        int c0 = a0b0 ^ GF256AES.mul(a1b1, 32);
        int c1 = a0b0 ^ GF256AES.mul(a0 ^ a1, b0 ^ b1);
        return ((c1 << 8) | c0) & 0xFFFF;
    }

    static int gf256to2GetElt(byte[] vec, int vecOff, int i)
    {
        int idx = vecOff + 2 * i;
        return (vec[idx] & 0xFF) | ((vec[idx + 1] & 0xFF) << 8);
    }

    static void gf256to2PutElt(byte[] vec, int vecOff, int i, int v)
    {
        int idx = vecOff + 2 * i;
        vec[idx] = (byte)(v & 0xFF);
        vec[idx + 1] = (byte)((v >>> 8) & 0xFF);
    }

    /** XOR two packed GF(256^2) vectors: just byte-wise XOR over 2*len bytes. */
    static void gf256to2VectAdd(byte[] a, int aOff, byte[] b, int bOff, byte[] c, int cOff, int len)
    {
        for (int i = 0; i < 2 * len; i++)
        {
            c[cOff + i] = (byte)((a[aOff + i] ^ b[bOff + i]) & 0xFF);
        }
    }

    static void gf256to2ConstantVectMult(int a, byte[] b, int bOff, byte[] c, int cOff, int len)
    {
        for (int i = 0; i < len; i++)
        {
            int prod = gf256to2Mult(a, gf256to2GetElt(b, bOff, i));
            gf256to2PutElt(c, cOff, i, prod);
        }
    }

    static int gf256to2VectMult(byte[] a, int aOff, byte[] b, int bOff, int len)
    {
        int acc = 0;
        for (int i = 0; i < len; i++)
        {
            int ai = gf256to2GetElt(a, aOff, i);
            int bi = gf256to2GetElt(b, bOff, i);
            acc ^= gf256to2Mult(ai, bi);
        }
        return acc & 0xFFFF;
    }

    /**
     * Lower-triangular mat·vec over GF(256^2). Matrix is stored as 2*n*n
     * bytes (row-major, each element 2 bytes). Output {@code y} must NOT
     * alias input {@code x}.
     */
    static void gf256to2MatMultTriInf(byte[] a, int aOff, byte[] x, int xOff, byte[] y, int yOff, int n)
    {
        for (int j = 0; j < n; j++)
        {
            int acc = 0;
            int rowOff = aOff + j * n * 2;
            for (int k = 0; k <= j; k++)
            {
                int aJK = gf256to2GetElt(a, rowOff, k);
                int xK = gf256to2GetElt(x, xOff, k);
                acc ^= gf256to2Mult(aJK, xK);
            }
            gf256to2PutElt(y, yOff, j, acc);
        }
    }

    /* ===================================================================
     * Subfield embeddings into GF(256) / GF(256^2)
     * =================================================================== */

    /** GF(16) -> GF(256) polynomial embedding (from reference gf16_gf256_mult_ref). */
    static int gf16ToGf256(int a16)
    {
        int x = a16 & 0x0F;
        int acc = (x & 1);
        acc ^= ((-((x >>> 1) & 1)) & 0xE0);
        acc ^= ((-((x >>> 2) & 1)) & 0x5D);
        acc ^= ((-((x >>> 3) & 1)) & 0xB0);
        return acc & 0xFF;
    }

    /** GF(4) -> GF(256) embedding: a_gf4 = a1*X + a0, lifted via b * mult_0xBC. */
    static int gf4Gf256Mult(int a4, int bGf256)
    {
        int b = bGf256 & 0xFF;
        int x = GF256AES.mul(0xBC, b);
        int t = ((-((a4 >>> 1) & 1)) & x) ^ ((-(a4 & 1)) & b);
        return t & 0xFF;
    }

    /** GF(16) * GF(256) multiplication. */
    static int gf16Gf256Mult(int a16, int bGf256)
    {
        int lifted = gf16ToGf256(a16);
        return GF256AES.mul(lifted, bGf256);
    }

    /** GF(2) * GF(256) multiplication: 0 or b. */
    static int gf2Gf256Mult(int a2, int bGf256)
    {
        return (a2 & 1) == 0 ? 0 : (bGf256 & 0xFF);
    }

    /* ===================================================================
     * Packed-byte unpackers (per-element extraction).
     * =================================================================== */

    static int gf2Unpack(byte[] vec, int vecOff, int i)
    {
        return (vec[vecOff + (i >>> 3)] >>> (i & 7)) & 1;
    }

    static int gf4Unpack(byte[] vec, int vecOff, int i)
    {
        return (vec[vecOff + (i >>> 2)] >>> (2 * (i & 3))) & 0x03;
    }

    static int gf16Unpack(byte[] vec, int vecOff, int i)
    {
        return (vec[vecOff + (i >>> 1)] >>> (4 * (i & 1))) & 0x0F;
    }

    /* ===================================================================
     * Hybrid base × ext operations.
     * "ext_base_vect_mult" returns sum_i a_ext[i] * b_base[i] in K.
     * "ext_base_constant_vect_mult" computes c_ext[i] = a_ext * b_base[i].
     * "base_ext_constant_vect_mult" computes c_ext[i] = a_base * b_ext[i].
     * The result is always in the extension field K.
     * =================================================================== */

    /** sum_i a_base_packed[i] * b_ext[i] over K = GF(256). */
    static int baseExtVectMult_baseToGf256(int baseLog2,
                                           byte[] aBase, int aBaseOff,
                                           byte[] bExt, int bExtOff,
                                           int n)
    {
        int acc = 0;
        switch (baseLog2)
        {
        case 1:
            for (int i = 0; i < n; i++)
            {
                if (gf2Unpack(aBase, aBaseOff, i) == 1)
                {
                    acc ^= bExt[bExtOff + i] & 0xFF;
                }
            }
            return acc & 0xFF;
        case 2:
            for (int i = 0; i < n; i++)
            {
                acc ^= gf4Gf256Mult(gf4Unpack(aBase, aBaseOff, i), bExt[bExtOff + i] & 0xFF);
            }
            return acc & 0xFF;
        case 4:
            for (int i = 0; i < n; i++)
            {
                acc ^= gf16Gf256Mult(gf16Unpack(aBase, aBaseOff, i), bExt[bExtOff + i] & 0xFF);
            }
            return acc & 0xFF;
        case 8:
            return gf256VectMult(aBase, aBaseOff, bExt, bExtOff, n);
        default:
            throw new IllegalArgumentException("bad base field log2: " + baseLog2);
        }
    }

    /** sum_i a_base_packed[i] * b_ext[i] over K = GF(256^2). */
    static int baseExtVectMult_baseToGf256to2(int baseLog2,
                                              byte[] aBase, int aBaseOff,
                                              byte[] bExt, int bExtOff,
                                              int n)
    {
        int acc = 0;
        for (int i = 0; i < n; i++)
        {
            int ai;
            switch (baseLog2)
            {
            case 1: ai = gf2Unpack(aBase, aBaseOff, i); break;
            case 2: ai = gf4Unpack(aBase, aBaseOff, i); break;
            case 4: ai = gf16Unpack(aBase, aBaseOff, i); break;
            case 8: ai = aBase[aBaseOff + i] & 0xFF; break;
            default: throw new IllegalArgumentException("bad base field log2: " + baseLog2);
            }
            int bi = gf256to2GetElt(bExt, bExtOff, i);
            // Embed a (in F) into GF(256^2): subfield element with a1 = 0, a0 = lift_to_gf256(a).
            int aLifted;
            switch (baseLog2)
            {
            case 1: aLifted = ai & 1; break;
            case 2:
                // GF(4) element first lifts to GF(256) via gf4Gf256Mult with 1
                aLifted = gf4Gf256Mult(ai, 1);
                break;
            case 4: aLifted = gf16ToGf256(ai); break;
            case 8: aLifted = ai; break;
            default: throw new IllegalArgumentException();
            }
            // gf256 * gf256to2: multiply each byte independently by aLifted in GF(256).
            int b0 = bi & 0xFF;
            int b1 = (bi >>> 8) & 0xFF;
            int p0 = GF256AES.mul(aLifted, b0);
            int p1 = GF256AES.mul(aLifted, b1);
            acc ^= (p0 & 0xFF) | ((p1 & 0xFF) << 8);
        }
        return acc & 0xFFFF;
    }

    /**
     * extBaseConstantVectMult: c_ext[i] = a_ext * b_base[i] for K = GF(256).
     * a is an element of K; b is a packed F-vector; c is a GF(256) vector.
     */
    static void extBaseConstantVectMult_gf256(int baseLog2, int aExt,
                                              byte[] bBase, int bBaseOff,
                                              byte[] cExt, int cExtOff, int n)
    {
        for (int i = 0; i < n; i++)
        {
            int bi;
            switch (baseLog2)
            {
            case 1: bi = gf2Unpack(bBase, bBaseOff, i); break;
            case 2: bi = gf4Unpack(bBase, bBaseOff, i); break;
            case 4: bi = gf16Unpack(bBase, bBaseOff, i); break;
            case 8: bi = bBase[bBaseOff + i] & 0xFF; break;
            default: throw new IllegalArgumentException();
            }
            int prod;
            switch (baseLog2)
            {
            case 1: prod = (bi == 0) ? 0 : (aExt & 0xFF); break;
            case 2: prod = gf4Gf256Mult(bi, aExt); break;
            case 4: prod = gf16Gf256Mult(bi, aExt); break;
            case 8: prod = GF256AES.mul(aExt, bi); break;
            default: throw new IllegalArgumentException();
            }
            cExt[cExtOff + i] = (byte)(prod & 0xFF);
        }
    }

    /**
     * extBaseConstantVectMult for K = GF(256^2). a is K-element (16 bits),
     * b is packed F-vector, c is a GF(256^2) vector (2 bytes per element).
     */
    static void extBaseConstantVectMult_gf256to2(int baseLog2, int aExt,
                                                 byte[] bBase, int bBaseOff,
                                                 byte[] cExt, int cExtOff, int n)
    {
        for (int i = 0; i < n; i++)
        {
            int bi;
            switch (baseLog2)
            {
            case 1: bi = gf2Unpack(bBase, bBaseOff, i); break;
            case 2: bi = gf4Unpack(bBase, bBaseOff, i); break;
            case 4: bi = gf16Unpack(bBase, bBaseOff, i); break;
            case 8: bi = bBase[bBaseOff + i] & 0xFF; break;
            default: throw new IllegalArgumentException();
            }
            // F embeds into the GF(256) component of K = GF(256^2) (so the
            // "a1 * X" part stays 0). Lift bi into GF(256) and multiply by aExt
            // bytewise: prod = aExt * lift(bi) treating aExt as (a1, a0).
            int lifted;
            switch (baseLog2)
            {
            case 1: lifted = bi & 1; break;
            case 2: lifted = gf4Gf256Mult(bi, 1); break;
            case 4: lifted = gf16ToGf256(bi); break;
            case 8: lifted = bi; break;
            default: throw new IllegalArgumentException();
            }
            int a0 = aExt & 0xFF;
            int a1 = (aExt >>> 8) & 0xFF;
            int p0 = GF256AES.mul(a0, lifted);
            int p1 = GF256AES.mul(a1, lifted);
            gf256to2PutElt(cExt, cExtOff, i, ((p1 & 0xFF) << 8) | (p0 & 0xFF));
        }
    }

    /**
     * extBaseMatMultTriInf for K = GF(256): Y[j] = sum_{k=0..j} A[j][k] * X[k]
     * where A is in K^{n*n} (lower-triangular) and X is in F^n (packed).
     */
    static void extBaseMatMultTriInf_gf256(int baseLog2,
                                           byte[] a, int aOff,
                                           byte[] x, int xOff,
                                           byte[] y, int yOff,
                                           int n)
    {
        for (int j = 0; j < n; j++)
        {
            int acc = 0;
            int rowOff = aOff + j * n;
            for (int k = 0; k <= j; k++)
            {
                int xk;
                switch (baseLog2)
                {
                case 1: xk = gf2Unpack(x, xOff, k); break;
                case 2: xk = gf4Unpack(x, xOff, k); break;
                case 4: xk = gf16Unpack(x, xOff, k); break;
                case 8: xk = x[xOff + k] & 0xFF; break;
                default: throw new IllegalArgumentException();
                }
                int aJK = a[rowOff + k] & 0xFF;
                int prod;
                switch (baseLog2)
                {
                case 1: prod = (xk == 0) ? 0 : aJK; break;
                case 2: prod = gf4Gf256Mult(xk, aJK); break;
                case 4: prod = gf16Gf256Mult(xk, aJK); break;
                case 8: prod = GF256AES.mul(aJK, xk); break;
                default: throw new IllegalArgumentException();
                }
                acc ^= prod;
            }
            y[yOff + j] = (byte)(acc & 0xFF);
        }
    }

    /** extBaseMatMultTriInf for K = GF(256^2). */
    static void extBaseMatMultTriInf_gf256to2(int baseLog2,
                                              byte[] a, int aOff,
                                              byte[] x, int xOff,
                                              byte[] y, int yOff,
                                              int n)
    {
        for (int j = 0; j < n; j++)
        {
            int acc = 0;
            int rowOff = aOff + j * n * 2;
            for (int k = 0; k <= j; k++)
            {
                int xk;
                switch (baseLog2)
                {
                case 1: xk = gf2Unpack(x, xOff, k); break;
                case 2: xk = gf4Unpack(x, xOff, k); break;
                case 4: xk = gf16Unpack(x, xOff, k); break;
                case 8: xk = x[xOff + k] & 0xFF; break;
                default: throw new IllegalArgumentException();
                }
                int aJK = gf256to2GetElt(a, rowOff, k);
                int lifted;
                switch (baseLog2)
                {
                case 1: lifted = xk & 1; break;
                case 2: lifted = gf4Gf256Mult(xk, 1); break;
                case 4: lifted = gf16ToGf256(xk); break;
                case 8: lifted = xk; break;
                default: throw new IllegalArgumentException();
                }
                int a0 = aJK & 0xFF;
                int a1 = (aJK >>> 8) & 0xFF;
                int p0 = GF256AES.mul(lifted, a0);
                int p1 = GF256AES.mul(lifted, a1);
                acc ^= ((p1 & 0xFF) << 8) | (p0 & 0xFF);
            }
            gf256to2PutElt(y, yOff, j, acc);
        }
    }

    /* ===================================================================
     * Gray-code / evaluation point helpers (always over K).
     * =================================================================== */

    static int grayCodeBitPosition(int i, int nbEvals)
    {
        int g1 = i ^ (i >>> 1);
        int g2 = (i + 1 < nbEvals) ? (i + 1) ^ ((i + 1) >>> 1) : 0;
        int diff = g1 ^ g2;
        int idx = 0;
        while ((diff & 1) == 0)
        {
            diff >>>= 1;
            idx++;
        }
        return idx;
    }

    /** omega_i in K. The C reference uses w_i = gray(i) cast to field_ext_elt. */
    static int evaluationPoint(int i, int extFieldLog2)
    {
        int g = i ^ (i >>> 1);
        return (extFieldLog2 == 8) ? (g & 0xFF) : (g & 0xFFFF);
    }
}
