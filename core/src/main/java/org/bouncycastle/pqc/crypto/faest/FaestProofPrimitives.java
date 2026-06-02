package org.bouncycastle.pqc.crypto.faest;

/**
 * Atomic prover/verifier primitives shared by the FAEST AES constraint system.
 * <p>
 * Each primitive comes in three width variants (128 / 192 / 256). The naming
 * tracks faest-ref {@code faest_aes.c} ({@code aes_<lambda>_<name>_{prover,verifier}})
 * so individual functions can be diffed against the reference.
 * <p>
 * Conventions:
 * <ul>
 *   <li>Bit-level state arrays are passed as {@code byte[]}, one bit per entry,
 *       low byte first. Length: {@code Nst * 32}.</li>
 *   <li>Tag / key arrays of {@code n} field elements occupy {@code n *
 *       BF{128,192,256}.LIMBS} consecutive longs in a flat {@code long[]}. The
 *       i-th element lives at offset {@code i * LIMBS}.</li>
 *   <li>{@code Nst} is the number of AES state columns (4, 6, or 8) — i.e.
 *       {@code faest_param.Nst} in upstream.</li>
 * </ul>
 * <p>
 * faest-ref source of truth: {@code faest_aes.c}.
 */
final class FaestProofPrimitives
{
    private FaestProofPrimitives()
    {
    }

    // ====== add_round_key ======
    // faest_aes.c:92 (prover) / faest_aes.c:117 (verifier).
    //
    // Bit-level state of size Nst*32: out[i] = in[i] ^ k[i]; out_tag[i] = in_tag[i] + k_tag[i].
    // Verifier has only the tag/key arithmetic.

    static void addRoundKeyProver128(byte[] outBits, long[] outTag, byte[] inBits, long[] inTag,
                                     byte[] kBits, long[] kTag, int Nst)
    {
        int n = Nst * 32;
        for (int i = 0; i < n; i++)
        {
            outBits[i] = (byte)((inBits[i] ^ kBits[i]) & 1);
            BF128.add(outTag, i * BF128.LIMBS, inTag, i * BF128.LIMBS, kTag, i * BF128.LIMBS);
        }
    }

    static void addRoundKeyProver192(byte[] outBits, long[] outTag, byte[] inBits, long[] inTag,
                                     byte[] kBits, long[] kTag, int Nst)
    {
        int n = Nst * 32;
        for (int i = 0; i < n; i++)
        {
            outBits[i] = (byte)((inBits[i] ^ kBits[i]) & 1);
            BF192.add(outTag, i * BF192.LIMBS, inTag, i * BF192.LIMBS, kTag, i * BF192.LIMBS);
        }
    }

    static void addRoundKeyProver256(byte[] outBits, long[] outTag, byte[] inBits, long[] inTag,
                                     byte[] kBits, long[] kTag, int Nst)
    {
        int n = Nst * 32;
        for (int i = 0; i < n; i++)
        {
            outBits[i] = (byte)((inBits[i] ^ kBits[i]) & 1);
            BF256.add(outTag, i * BF256.LIMBS, inTag, i * BF256.LIMBS, kTag, i * BF256.LIMBS);
        }
    }

    static void addRoundKeyVerifier128(long[] outKey, long[] inKey, long[] kKey, int Nst)
    {
        int n = Nst * 32;
        for (int i = 0; i < n; i++)
        {
            BF128.add(outKey, i * BF128.LIMBS, inKey, i * BF128.LIMBS, kKey, i * BF128.LIMBS);
        }
    }

    static void addRoundKeyVerifier192(long[] outKey, long[] inKey, long[] kKey, int Nst)
    {
        int n = Nst * 32;
        for (int i = 0; i < n; i++)
        {
            BF192.add(outKey, i * BF192.LIMBS, inKey, i * BF192.LIMBS, kKey, i * BF192.LIMBS);
        }
    }

    static void addRoundKeyVerifier256(long[] outKey, long[] inKey, long[] kKey, int Nst)
    {
        int n = Nst * 32;
        for (int i = 0; i < n; i++)
        {
            BF256.add(outKey, i * BF256.LIMBS, inKey, i * BF256.LIMBS, kKey, i * BF256.LIMBS);
        }
    }

    // ====== F256/F2 conjugates ======
    // faest_aes.c:146 (bit input) / faest_aes.c:200 (lambda input).
    //
    // For each of Nst*4 bytes in the state, emit 8 GF(2^lambda) elements
    // y[i*8 + 0..7] = byte_combine_bits(x), byte_combine_bits(bits_sq(x)),
    //                 byte_combine_bits(bits_sq^2(x)), ..., byte_combine_bits(bits_sq^7(x)).
    // The seven successive applications of bits_sq generate the Frobenius
    // conjugates {x, x^2, x^4, ..., x^128} in the GF(2^8) subfield.

    static void f256F2Conjugates1_128(long[] y, byte[] stateBits, int Nst)
    {
        int Nstb = Nst * 4;
        byte[] x = new byte[8];
        for (int i = 0; i < Nstb; i++)
        {
            System.arraycopy(stateBits, i * 8, x, 0, 8);
            for (int j = 0; j < 7; j++)
            {
                BF128.byteCombineBits(y, (i * 8 + j) * BF128.LIMBS, x, 0);
                BF8.bits_sq(x);
            }
            BF128.byteCombineBits(y, (i * 8 + 7) * BF128.LIMBS, x, 0);
        }
    }

    static void f256F2Conjugates1_192(long[] y, byte[] stateBits, int Nst)
    {
        int Nstb = Nst * 4;
        byte[] x = new byte[8];
        for (int i = 0; i < Nstb; i++)
        {
            System.arraycopy(stateBits, i * 8, x, 0, 8);
            for (int j = 0; j < 7; j++)
            {
                BF192.byteCombineBits(y, (i * 8 + j) * BF192.LIMBS, x, 0);
                BF8.bits_sq(x);
            }
            BF192.byteCombineBits(y, (i * 8 + 7) * BF192.LIMBS, x, 0);
        }
    }

    static void f256F2Conjugates1_256(long[] y, byte[] stateBits, int Nst)
    {
        int Nstb = Nst * 4;
        byte[] x = new byte[8];
        for (int i = 0; i < Nstb; i++)
        {
            System.arraycopy(stateBits, i * 8, x, 0, 8);
            for (int j = 0; j < 7; j++)
            {
                BF256.byteCombineBits(y, (i * 8 + j) * BF256.LIMBS, x, 0);
                BF8.bits_sq(x);
            }
            BF256.byteCombineBits(y, (i * 8 + 7) * BF256.LIMBS, x, 0);
        }
    }

    static void f256F2ConjugatesLambda_128(long[] y, long[] state, int Nst)
    {
        int Nstb = Nst * 4;
        long[] x = new long[8 * BF128.LIMBS];
        long[] tmp = new long[8 * BF128.LIMBS];
        for (int i = 0; i < Nstb; i++)
        {
            System.arraycopy(state, i * 8 * BF128.LIMBS, x, 0, 8 * BF128.LIMBS);
            for (int j = 0; j < 7; j++)
            {
                BF128.byteCombine(y, (i * 8 + j) * BF128.LIMBS, x, 0);
                System.arraycopy(x, 0, tmp, 0, 8 * BF128.LIMBS);
                BF128.sqBit(x, 0, tmp, 0);
            }
            BF128.byteCombine(y, (i * 8 + 7) * BF128.LIMBS, x, 0);
        }
    }

    static void f256F2ConjugatesLambda_192(long[] y, long[] state, int Nst)
    {
        int Nstb = Nst * 4;
        long[] x = new long[8 * BF192.LIMBS];
        long[] tmp = new long[8 * BF192.LIMBS];
        for (int i = 0; i < Nstb; i++)
        {
            System.arraycopy(state, i * 8 * BF192.LIMBS, x, 0, 8 * BF192.LIMBS);
            for (int j = 0; j < 7; j++)
            {
                BF192.byteCombine(y, (i * 8 + j) * BF192.LIMBS, x, 0);
                System.arraycopy(x, 0, tmp, 0, 8 * BF192.LIMBS);
                BF192.sqBit(x, 0, tmp, 0);
            }
            BF192.byteCombine(y, (i * 8 + 7) * BF192.LIMBS, x, 0);
        }
    }

    static void f256F2ConjugatesLambda_256(long[] y, long[] state, int Nst)
    {
        int Nstb = Nst * 4;
        long[] x = new long[8 * BF256.LIMBS];
        long[] tmp = new long[8 * BF256.LIMBS];
        for (int i = 0; i < Nstb; i++)
        {
            System.arraycopy(state, i * 8 * BF256.LIMBS, x, 0, 8 * BF256.LIMBS);
            for (int j = 0; j < 7; j++)
            {
                BF256.byteCombine(y, (i * 8 + j) * BF256.LIMBS, x, 0);
                System.arraycopy(x, 0, tmp, 0, 8 * BF256.LIMBS);
                BF256.sqBit(x, 0, tmp, 0);
            }
            BF256.byteCombine(y, (i * 8 + 7) * BF256.LIMBS, x, 0);
        }
    }

    // ====== shiftrows ======
    // faest_aes.c:796 (prover) / faest_aes.c:860 (verifier).
    //
    // Permutes Nst*4 elements per "row" by AES-style cyclic shift. For Nst=8 (256-bit
    // Rijndael block) the rows 2 and 3 shift one extra position, per the Rijndael spec.

    private static int shiftRowsSrc(int Nst, int c, int r)
    {
        int s = ((Nst != 8) || (r <= 1)) ? r : (r + 1);
        return 4 * ((c + s) % Nst) + r;
    }

    static void shiftRowsProver128(long[] outDeg0, long[] outDeg1, long[] outDeg2,
                                   long[] inDeg0, long[] inDeg1, long[] inDeg2, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int dst = (4 * c + r) * BF128.LIMBS;
                int src = shiftRowsSrc(Nst, c, r) * BF128.LIMBS;
                System.arraycopy(inDeg0, src, outDeg0, dst, BF128.LIMBS);
                System.arraycopy(inDeg1, src, outDeg1, dst, BF128.LIMBS);
                System.arraycopy(inDeg2, src, outDeg2, dst, BF128.LIMBS);
            }
        }
    }

    static void shiftRowsProver192(long[] outDeg0, long[] outDeg1, long[] outDeg2,
                                   long[] inDeg0, long[] inDeg1, long[] inDeg2, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int dst = (4 * c + r) * BF192.LIMBS;
                int src = shiftRowsSrc(Nst, c, r) * BF192.LIMBS;
                System.arraycopy(inDeg0, src, outDeg0, dst, BF192.LIMBS);
                System.arraycopy(inDeg1, src, outDeg1, dst, BF192.LIMBS);
                System.arraycopy(inDeg2, src, outDeg2, dst, BF192.LIMBS);
            }
        }
    }

    static void shiftRowsProver256(long[] outDeg0, long[] outDeg1, long[] outDeg2,
                                   long[] inDeg0, long[] inDeg1, long[] inDeg2, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int dst = (4 * c + r) * BF256.LIMBS;
                int src = shiftRowsSrc(Nst, c, r) * BF256.LIMBS;
                System.arraycopy(inDeg0, src, outDeg0, dst, BF256.LIMBS);
                System.arraycopy(inDeg1, src, outDeg1, dst, BF256.LIMBS);
                System.arraycopy(inDeg2, src, outDeg2, dst, BF256.LIMBS);
            }
        }
    }

    static void shiftRowsVerifier128(long[] outDeg1, long[] inDeg1, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int dst = (4 * c + r) * BF128.LIMBS;
                int src = shiftRowsSrc(Nst, c, r) * BF128.LIMBS;
                System.arraycopy(inDeg1, src, outDeg1, dst, BF128.LIMBS);
            }
        }
    }

    static void shiftRowsVerifier192(long[] outDeg1, long[] inDeg1, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int dst = (4 * c + r) * BF192.LIMBS;
                int src = shiftRowsSrc(Nst, c, r) * BF192.LIMBS;
                System.arraycopy(inDeg1, src, outDeg1, dst, BF192.LIMBS);
            }
        }
    }

    static void shiftRowsVerifier256(long[] outDeg1, long[] inDeg1, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int dst = (4 * c + r) * BF256.LIMBS;
                int src = shiftRowsSrc(Nst, c, r) * BF256.LIMBS;
                System.arraycopy(inDeg1, src, outDeg1, dst, BF256.LIMBS);
            }
        }
    }

    // ====== inverse_shiftrows ======
    // faest_aes.c:1463 (prover) / faest_aes.c:1524 (verifier).
    //
    // Bit-level (not byte-level) inverse permutation. Each (c,r) byte position
    // moves to (c, r) from src = 4*((c + Nst - r [- 1 if Nst==8 and r>=2]) % Nst) + r;
    // then all 8 bits of that byte are copied across in lockstep.

    private static int inverseShiftRowsSrc(int Nst, int c, int r)
    {
        int s = ((Nst != 8) || (r <= 1)) ? r : (r + 1);
        return 4 * ((c + Nst - s) % Nst) + r;
    }

    static void inverseShiftRowsProver128(byte[] outBits, long[] outTag,
                                          byte[] inBits, long[] inTag, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int i = inverseShiftRowsSrc(Nst, c, r);
                int dstByte = (4 * c + r) * 8;
                int srcByte = i * 8;
                System.arraycopy(inBits, srcByte, outBits, dstByte, 8);
                System.arraycopy(inTag, srcByte * BF128.LIMBS, outTag, dstByte * BF128.LIMBS,
                    8 * BF128.LIMBS);
            }
        }
    }

    static void inverseShiftRowsProver192(byte[] outBits, long[] outTag,
                                          byte[] inBits, long[] inTag, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int i = inverseShiftRowsSrc(Nst, c, r);
                int dstByte = (4 * c + r) * 8;
                int srcByte = i * 8;
                System.arraycopy(inBits, srcByte, outBits, dstByte, 8);
                System.arraycopy(inTag, srcByte * BF192.LIMBS, outTag, dstByte * BF192.LIMBS,
                    8 * BF192.LIMBS);
            }
        }
    }

    static void inverseShiftRowsProver256(byte[] outBits, long[] outTag,
                                          byte[] inBits, long[] inTag, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int i = inverseShiftRowsSrc(Nst, c, r);
                int dstByte = (4 * c + r) * 8;
                int srcByte = i * 8;
                System.arraycopy(inBits, srcByte, outBits, dstByte, 8);
                System.arraycopy(inTag, srcByte * BF256.LIMBS, outTag, dstByte * BF256.LIMBS,
                    8 * BF256.LIMBS);
            }
        }
    }

    static void inverseShiftRowsVerifier128(long[] outTag, long[] inTag, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int i = inverseShiftRowsSrc(Nst, c, r);
                int dstByte = (4 * c + r) * 8;
                int srcByte = i * 8;
                System.arraycopy(inTag, srcByte * BF128.LIMBS, outTag, dstByte * BF128.LIMBS,
                    8 * BF128.LIMBS);
            }
        }
    }

    static void inverseShiftRowsVerifier192(long[] outTag, long[] inTag, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int i = inverseShiftRowsSrc(Nst, c, r);
                int dstByte = (4 * c + r) * 8;
                int srcByte = i * 8;
                System.arraycopy(inTag, srcByte * BF192.LIMBS, outTag, dstByte * BF192.LIMBS,
                    8 * BF192.LIMBS);
            }
        }
    }

    static void inverseShiftRowsVerifier256(long[] outTag, long[] inTag, int Nst)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int i = inverseShiftRowsSrc(Nst, c, r);
                int dstByte = (4 * c + r) * 8;
                int srcByte = i * 8;
                System.arraycopy(inTag, srcByte * BF256.LIMBS, outTag, dstByte * BF256.LIMBS,
                    8 * BF256.LIMBS);
            }
        }
    }

    // ====== constant_to_vole ======
    // faest_aes.c:1994 (prover) / faest_aes.c:2013 (verifier).
    //
    // Prover: tags for a public constant are all zero (since the constant's value is
    // public, no commitment is needed).
    // Verifier: key[i] = bit_i(val) * delta — encodes the public bits as VOLE keys
    // so the verifier can subtract them out of the tag/key polynomial.

    static void constantToVoleProver128(long[] tag, int n)
    {
        java.util.Arrays.fill(tag, 0, n * BF128.LIMBS, 0L);
    }

    static void constantToVoleProver192(long[] tag, int n)
    {
        java.util.Arrays.fill(tag, 0, n * BF192.LIMBS, 0L);
    }

    static void constantToVoleProver256(long[] tag, int n)
    {
        java.util.Arrays.fill(tag, 0, n * BF256.LIMBS, 0L);
    }

    static void constantToVoleVerifier128(long[] key, byte[] val, long[] delta, int n)
    {
        for (int i = 0; i < n; i++)
        {
            int bit = (val[i >> 3] >>> (i & 7)) & 1;
            BF128.mulBit(key, i * BF128.LIMBS, delta, 0, bit);
        }
    }

    static void constantToVoleVerifier192(long[] key, byte[] val, long[] delta, int n)
    {
        for (int i = 0; i < n; i++)
        {
            int bit = (val[i >> 3] >>> (i & 7)) & 1;
            BF192.mulBit(key, i * BF192.LIMBS, delta, 0, bit);
        }
    }

    static void constantToVoleVerifier256(long[] key, byte[] val, long[] delta, int n)
    {
        for (int i = 0; i < n; i++)
        {
            int bit = (val[i >> 3] >>> (i & 7)) & 1;
            BF256.mulBit(key, i * BF256.LIMBS, delta, 0, bit);
        }
    }

    // ====== deg2to3 ======
    // faest_aes.c:2030 (prover) / faest_aes.c:2043 (verifier).
    //
    // Prover: store (tag, val) into adjacent (deg1, deg2) slots — used when a
    // degree-2 polynomial constraint needs a deg-3 slot for an unchanged term.
    // Verifier: deg1 = key * delta.

    static void deg2to3Prover128(long[] deg1, int deg1Off, long[] deg2, int deg2Off,
                                 long[] tag, int tagOff, long[] val, int valOff)
    {
        System.arraycopy(tag, tagOff, deg1, deg1Off, BF128.LIMBS);
        System.arraycopy(val, valOff, deg2, deg2Off, BF128.LIMBS);
    }

    static void deg2to3Prover192(long[] deg1, int deg1Off, long[] deg2, int deg2Off,
                                 long[] tag, int tagOff, long[] val, int valOff)
    {
        System.arraycopy(tag, tagOff, deg1, deg1Off, BF192.LIMBS);
        System.arraycopy(val, valOff, deg2, deg2Off, BF192.LIMBS);
    }

    static void deg2to3Prover256(long[] deg1, int deg1Off, long[] deg2, int deg2Off,
                                 long[] tag, int tagOff, long[] val, int valOff)
    {
        System.arraycopy(tag, tagOff, deg1, deg1Off, BF256.LIMBS);
        System.arraycopy(val, valOff, deg2, deg2Off, BF256.LIMBS);
    }

    static void deg2to3Verifier128(long[] deg1, int deg1Off, long[] key, int keyOff,
                                   long[] delta, int deltaOff)
    {
        BF128.mul(deg1, deg1Off, key, keyOff, delta, deltaOff);
    }

    static void deg2to3Verifier192(long[] deg1, int deg1Off, long[] key, int keyOff,
                                   long[] delta, int deltaOff)
    {
        BF192.mul(deg1, deg1Off, key, keyOff, delta, deltaOff);
    }

    static void deg2to3Verifier256(long[] deg1, int deg1Off, long[] key, int keyOff,
                                   long[] delta, int deltaOff)
    {
        BF256.mul(deg1, deg1Off, key, keyOff, delta, deltaOff);
    }

    // ====== state_to_bytes ======
    // faest_aes.c:511 (prover) / faest_aes.c:536 (verifier).
    //
    // Reduces an Nst_bytes*8 bit-level witness/tag pair into Nst_bytes byte-level
    // field elements via byte_combine_bits / byte_combine.

    static void stateToBytesProver128(long[] out, long[] outTag, byte[] k, long[] kTag, int Nst)
    {
        int NstBytes = Nst * 4;
        for (int i = 0; i < NstBytes; i++)
        {
            BF128.byteCombineBits(out, i * BF128.LIMBS, k, i * 8);
            BF128.byteCombine(outTag, i * BF128.LIMBS, kTag, i * 8 * BF128.LIMBS);
        }
    }

    static void stateToBytesProver192(long[] out, long[] outTag, byte[] k, long[] kTag, int Nst)
    {
        int NstBytes = Nst * 4;
        for (int i = 0; i < NstBytes; i++)
        {
            BF192.byteCombineBits(out, i * BF192.LIMBS, k, i * 8);
            BF192.byteCombine(outTag, i * BF192.LIMBS, kTag, i * 8 * BF192.LIMBS);
        }
    }

    static void stateToBytesProver256(long[] out, long[] outTag, byte[] k, long[] kTag, int Nst)
    {
        int NstBytes = Nst * 4;
        for (int i = 0; i < NstBytes; i++)
        {
            BF256.byteCombineBits(out, i * BF256.LIMBS, k, i * 8);
            BF256.byteCombine(outTag, i * BF256.LIMBS, kTag, i * 8 * BF256.LIMBS);
        }
    }

    static void stateToBytesVerifier128(long[] outKey, long[] kKey, int Nst)
    {
        int NstBytes = Nst * 4;
        for (int i = 0; i < NstBytes; i++)
        {
            BF128.byteCombine(outKey, i * BF128.LIMBS, kKey, i * 8 * BF128.LIMBS);
        }
    }

    static void stateToBytesVerifier192(long[] outKey, long[] kKey, int Nst)
    {
        int NstBytes = Nst * 4;
        for (int i = 0; i < NstBytes; i++)
        {
            BF192.byteCombine(outKey, i * BF192.LIMBS, kKey, i * 8 * BF192.LIMBS);
        }
    }

    static void stateToBytesVerifier256(long[] outKey, long[] kKey, int Nst)
    {
        int NstBytes = Nst * 4;
        for (int i = 0; i < NstBytes; i++)
        {
            BF256.byteCombine(outKey, i * BF256.LIMBS, kKey, i * 8 * BF256.LIMBS);
        }
    }

    // ====== add_round_key_bytes ======
    // faest_aes.c:1378 (prover) / faest_aes.c:1416 (verifier).
    //
    // Byte-level analogue of add_round_key: element-wise add over Nst*4 GF(2^lambda)
    // entries. Verifier supports a "shift_tag" mode where k_tag is degree-1 (so it
    // must be multiplied by delta to align with the degree-2 in_tag).

    static void addRoundKeyBytesProver128(long[] yDeg0, long[] yDeg1, long[] yDeg2,
                                          long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                          long[] kDeg0, long[] kDeg1, long[] kDeg2, int Nst)
    {
        int n = Nst * 4;
        for (int i = 0; i < n; i++)
        {
            int off = i * BF128.LIMBS;
            BF128.add(yDeg0, off, inDeg0, off, kDeg0, off);
            BF128.add(yDeg1, off, inDeg1, off, kDeg1, off);
            BF128.add(yDeg2, off, inDeg2, off, kDeg2, off);
        }
    }

    static void addRoundKeyBytesProver192(long[] yDeg0, long[] yDeg1, long[] yDeg2,
                                          long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                          long[] kDeg0, long[] kDeg1, long[] kDeg2, int Nst)
    {
        int n = Nst * 4;
        for (int i = 0; i < n; i++)
        {
            int off = i * BF192.LIMBS;
            BF192.add(yDeg0, off, inDeg0, off, kDeg0, off);
            BF192.add(yDeg1, off, inDeg1, off, kDeg1, off);
            BF192.add(yDeg2, off, inDeg2, off, kDeg2, off);
        }
    }

    static void addRoundKeyBytesProver256(long[] yDeg0, long[] yDeg1, long[] yDeg2,
                                          long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                          long[] kDeg0, long[] kDeg1, long[] kDeg2, int Nst)
    {
        int n = Nst * 4;
        for (int i = 0; i < n; i++)
        {
            int off = i * BF256.LIMBS;
            BF256.add(yDeg0, off, inDeg0, off, kDeg0, off);
            BF256.add(yDeg1, off, inDeg1, off, kDeg1, off);
            BF256.add(yDeg2, off, inDeg2, off, kDeg2, off);
        }
    }

    static void addRoundKeyBytesVerifier128(long[] yDeg1, long[] inTag, long[] kTag,
                                            long[] delta, boolean shiftTag, int Nst)
    {
        int n = Nst * 4;
        long[] tmp = shiftTag ? new long[BF128.LIMBS] : null;
        for (int i = 0; i < n; i++)
        {
            int off = i * BF128.LIMBS;
            if (shiftTag)
            {
                BF128.mul(tmp, 0, kTag, off, delta, 0);
                BF128.add(yDeg1, off, inTag, off, tmp, 0);
            }
            else
            {
                BF128.add(yDeg1, off, inTag, off, kTag, off);
            }
        }
    }

    static void addRoundKeyBytesVerifier192(long[] yDeg1, long[] inTag, long[] kTag,
                                            long[] delta, boolean shiftTag, int Nst)
    {
        int n = Nst * 4;
        long[] tmp = shiftTag ? new long[BF192.LIMBS] : null;
        for (int i = 0; i < n; i++)
        {
            int off = i * BF192.LIMBS;
            if (shiftTag)
            {
                BF192.mul(tmp, 0, kTag, off, delta, 0);
                BF192.add(yDeg1, off, inTag, off, tmp, 0);
            }
            else
            {
                BF192.add(yDeg1, off, inTag, off, kTag, off);
            }
        }
    }

    static void addRoundKeyBytesVerifier256(long[] yDeg1, long[] inTag, long[] kTag,
                                            long[] delta, boolean shiftTag, int Nst)
    {
        int n = Nst * 4;
        long[] tmp = shiftTag ? new long[BF256.LIMBS] : null;
        for (int i = 0; i < n; i++)
        {
            int off = i * BF256.LIMBS;
            if (shiftTag)
            {
                BF256.mul(tmp, 0, kTag, off, delta, 0);
                BF256.add(yDeg1, off, inTag, off, tmp, 0);
            }
            else
            {
                BF256.add(yDeg1, off, inTag, off, kTag, off);
            }
        }
    }

    // ====== inv_norm_to_conjugates ======
    // faest_aes.c:249 (prover) / faest_aes.c:349 (verifier).
    //
    // Expands a 4-bit nibble into 4 GF(2^lambda) Frobenius conjugates of beta = a^4
    // (which equals alpha^6 + alpha^4 in the upstream embedding). Prover computes
    // values from bits (mulBit) and tags from field elements (mul); verifier
    // only has the eval form.

    static void invNormToConjugatesProver128(long[] yVal, long[] yTag,
                                             byte[] xVal, long[] xTag)
    {
        long[] beta4 = new long[BF128.LIMBS];
        BF128.add(beta4, 0, BF128.ALPHA[5], 0, BF128.ALPHA[3], 0);
        long[] betaSq = (long[])beta4.clone();
        long[] betaSq1 = new long[BF128.LIMBS];
        BF128.mul(betaSq1, 0, beta4, 0, beta4, 0);
        long[] betaCube = new long[BF128.LIMBS];
        BF128.mul(betaCube, 0, betaSq1, 0, beta4, 0);

        long[] tmp = new long[BF128.LIMBS];
        long[] one = new long[BF128.LIMBS]; BF128.one(one, 0);
        for (int i = 0; i < 4; i++)
        {
            // yVal[i] = mulBit(1, x[0]) + mulBit(betaSq, x[1]) + mulBit(betaSq1, x[2]) + mulBit(betaCube, x[3])
            int dst = i * BF128.LIMBS;
            BF128.mulBit(yVal, dst, one, 0, xVal[0]);
            BF128.mulBit(tmp, 0, betaSq, 0, xVal[1]);   BF128.addInPlace(yVal, dst, tmp, 0);
            BF128.mulBit(tmp, 0, betaSq1, 0, xVal[2]);  BF128.addInPlace(yVal, dst, tmp, 0);
            BF128.mulBit(tmp, 0, betaCube, 0, xVal[3]); BF128.addInPlace(yVal, dst, tmp, 0);
            // yTag[i] = mul(1, xTag[0]) + mul(betaSq, xTag[1]) + mul(betaSq1, xTag[2]) + mul(betaCube, xTag[3])
            //        = xTag[0] + ...   (since mul(one, x) == x)
            System.arraycopy(xTag, 0 * BF128.LIMBS, yTag, dst, BF128.LIMBS);
            BF128.mul(tmp, 0, betaSq, 0, xTag, 1 * BF128.LIMBS);   BF128.addInPlace(yTag, dst, tmp, 0);
            BF128.mul(tmp, 0, betaSq1, 0, xTag, 2 * BF128.LIMBS);  BF128.addInPlace(yTag, dst, tmp, 0);
            BF128.mul(tmp, 0, betaCube, 0, xTag, 3 * BF128.LIMBS); BF128.addInPlace(yTag, dst, tmp, 0);

            BF128.mul(betaSq, 0, betaSq, 0, betaSq, 0);
            BF128.mul(betaSq1, 0, betaSq1, 0, betaSq1, 0);
            BF128.mul(betaCube, 0, betaCube, 0, betaCube, 0);
        }
    }

    static void invNormToConjugatesProver192(long[] yVal, long[] yTag,
                                             byte[] xVal, long[] xTag)
    {
        long[] beta4 = new long[BF192.LIMBS];
        BF192.add(beta4, 0, BF192.ALPHA[5], 0, BF192.ALPHA[3], 0);
        long[] betaSq = (long[])beta4.clone();
        long[] betaSq1 = new long[BF192.LIMBS];
        BF192.mul(betaSq1, 0, beta4, 0, beta4, 0);
        long[] betaCube = new long[BF192.LIMBS];
        BF192.mul(betaCube, 0, betaSq1, 0, beta4, 0);

        long[] tmp = new long[BF192.LIMBS];
        long[] one = new long[BF192.LIMBS]; BF192.one(one, 0);
        for (int i = 0; i < 4; i++)
        {
            int dst = i * BF192.LIMBS;
            BF192.mulBit(yVal, dst, one, 0, xVal[0]);
            BF192.mulBit(tmp, 0, betaSq, 0, xVal[1]);   BF192.addInPlace(yVal, dst, tmp, 0);
            BF192.mulBit(tmp, 0, betaSq1, 0, xVal[2]);  BF192.addInPlace(yVal, dst, tmp, 0);
            BF192.mulBit(tmp, 0, betaCube, 0, xVal[3]); BF192.addInPlace(yVal, dst, tmp, 0);
            System.arraycopy(xTag, 0 * BF192.LIMBS, yTag, dst, BF192.LIMBS);
            BF192.mul(tmp, 0, betaSq, 0, xTag, 1 * BF192.LIMBS);   BF192.addInPlace(yTag, dst, tmp, 0);
            BF192.mul(tmp, 0, betaSq1, 0, xTag, 2 * BF192.LIMBS);  BF192.addInPlace(yTag, dst, tmp, 0);
            BF192.mul(tmp, 0, betaCube, 0, xTag, 3 * BF192.LIMBS); BF192.addInPlace(yTag, dst, tmp, 0);

            BF192.mul(betaSq, 0, betaSq, 0, betaSq, 0);
            BF192.mul(betaSq1, 0, betaSq1, 0, betaSq1, 0);
            BF192.mul(betaCube, 0, betaCube, 0, betaCube, 0);
        }
    }

    static void invNormToConjugatesProver256(long[] yVal, long[] yTag,
                                             byte[] xVal, long[] xTag)
    {
        long[] beta4 = new long[BF256.LIMBS];
        BF256.add(beta4, 0, BF256.ALPHA[5], 0, BF256.ALPHA[3], 0);
        long[] betaSq = (long[])beta4.clone();
        long[] betaSq1 = new long[BF256.LIMBS];
        BF256.mul(betaSq1, 0, beta4, 0, beta4, 0);
        long[] betaCube = new long[BF256.LIMBS];
        BF256.mul(betaCube, 0, betaSq1, 0, beta4, 0);

        long[] tmp = new long[BF256.LIMBS];
        long[] one = new long[BF256.LIMBS]; BF256.one(one, 0);
        for (int i = 0; i < 4; i++)
        {
            int dst = i * BF256.LIMBS;
            BF256.mulBit(yVal, dst, one, 0, xVal[0]);
            BF256.mulBit(tmp, 0, betaSq, 0, xVal[1]);   BF256.addInPlace(yVal, dst, tmp, 0);
            BF256.mulBit(tmp, 0, betaSq1, 0, xVal[2]);  BF256.addInPlace(yVal, dst, tmp, 0);
            BF256.mulBit(tmp, 0, betaCube, 0, xVal[3]); BF256.addInPlace(yVal, dst, tmp, 0);
            System.arraycopy(xTag, 0 * BF256.LIMBS, yTag, dst, BF256.LIMBS);
            BF256.mul(tmp, 0, betaSq, 0, xTag, 1 * BF256.LIMBS);   BF256.addInPlace(yTag, dst, tmp, 0);
            BF256.mul(tmp, 0, betaSq1, 0, xTag, 2 * BF256.LIMBS);  BF256.addInPlace(yTag, dst, tmp, 0);
            BF256.mul(tmp, 0, betaCube, 0, xTag, 3 * BF256.LIMBS); BF256.addInPlace(yTag, dst, tmp, 0);

            BF256.mul(betaSq, 0, betaSq, 0, betaSq, 0);
            BF256.mul(betaSq1, 0, betaSq1, 0, betaSq1, 0);
            BF256.mul(betaCube, 0, betaCube, 0, betaCube, 0);
        }
    }

    static void invNormToConjugatesVerifier128(long[] yEval, long[] xEval)
    {
        long[] beta4 = new long[BF128.LIMBS];
        BF128.add(beta4, 0, BF128.ALPHA[5], 0, BF128.ALPHA[3], 0);
        long[] betaSq = (long[])beta4.clone();
        long[] betaSq1 = new long[BF128.LIMBS];
        BF128.mul(betaSq1, 0, beta4, 0, beta4, 0);
        long[] betaCube = new long[BF128.LIMBS];
        BF128.mul(betaCube, 0, betaSq1, 0, beta4, 0);

        long[] tmp = new long[BF128.LIMBS];
        for (int i = 0; i < 4; i++)
        {
            int dst = i * BF128.LIMBS;
            System.arraycopy(xEval, 0 * BF128.LIMBS, yEval, dst, BF128.LIMBS);
            BF128.mul(tmp, 0, betaSq, 0, xEval, 1 * BF128.LIMBS);   BF128.addInPlace(yEval, dst, tmp, 0);
            BF128.mul(tmp, 0, betaSq1, 0, xEval, 2 * BF128.LIMBS);  BF128.addInPlace(yEval, dst, tmp, 0);
            BF128.mul(tmp, 0, betaCube, 0, xEval, 3 * BF128.LIMBS); BF128.addInPlace(yEval, dst, tmp, 0);

            BF128.mul(betaSq, 0, betaSq, 0, betaSq, 0);
            BF128.mul(betaSq1, 0, betaSq1, 0, betaSq1, 0);
            BF128.mul(betaCube, 0, betaCube, 0, betaCube, 0);
        }
    }

    static void invNormToConjugatesVerifier192(long[] yEval, long[] xEval)
    {
        long[] beta4 = new long[BF192.LIMBS];
        BF192.add(beta4, 0, BF192.ALPHA[5], 0, BF192.ALPHA[3], 0);
        long[] betaSq = (long[])beta4.clone();
        long[] betaSq1 = new long[BF192.LIMBS];
        BF192.mul(betaSq1, 0, beta4, 0, beta4, 0);
        long[] betaCube = new long[BF192.LIMBS];
        BF192.mul(betaCube, 0, betaSq1, 0, beta4, 0);

        long[] tmp = new long[BF192.LIMBS];
        for (int i = 0; i < 4; i++)
        {
            int dst = i * BF192.LIMBS;
            System.arraycopy(xEval, 0 * BF192.LIMBS, yEval, dst, BF192.LIMBS);
            BF192.mul(tmp, 0, betaSq, 0, xEval, 1 * BF192.LIMBS);   BF192.addInPlace(yEval, dst, tmp, 0);
            BF192.mul(tmp, 0, betaSq1, 0, xEval, 2 * BF192.LIMBS);  BF192.addInPlace(yEval, dst, tmp, 0);
            BF192.mul(tmp, 0, betaCube, 0, xEval, 3 * BF192.LIMBS); BF192.addInPlace(yEval, dst, tmp, 0);

            BF192.mul(betaSq, 0, betaSq, 0, betaSq, 0);
            BF192.mul(betaSq1, 0, betaSq1, 0, betaSq1, 0);
            BF192.mul(betaCube, 0, betaCube, 0, betaCube, 0);
        }
    }

    static void invNormToConjugatesVerifier256(long[] yEval, long[] xEval)
    {
        long[] beta4 = new long[BF256.LIMBS];
        BF256.add(beta4, 0, BF256.ALPHA[5], 0, BF256.ALPHA[3], 0);
        long[] betaSq = (long[])beta4.clone();
        long[] betaSq1 = new long[BF256.LIMBS];
        BF256.mul(betaSq1, 0, beta4, 0, beta4, 0);
        long[] betaCube = new long[BF256.LIMBS];
        BF256.mul(betaCube, 0, betaSq1, 0, beta4, 0);

        long[] tmp = new long[BF256.LIMBS];
        for (int i = 0; i < 4; i++)
        {
            int dst = i * BF256.LIMBS;
            System.arraycopy(xEval, 0 * BF256.LIMBS, yEval, dst, BF256.LIMBS);
            BF256.mul(tmp, 0, betaSq, 0, xEval, 1 * BF256.LIMBS);   BF256.addInPlace(yEval, dst, tmp, 0);
            BF256.mul(tmp, 0, betaSq1, 0, xEval, 2 * BF256.LIMBS);  BF256.addInPlace(yEval, dst, tmp, 0);
            BF256.mul(tmp, 0, betaCube, 0, xEval, 3 * BF256.LIMBS); BF256.addInPlace(yEval, dst, tmp, 0);

            BF256.mul(betaSq, 0, betaSq, 0, betaSq, 0);
            BF256.mul(betaSq1, 0, betaSq1, 0, betaSq1, 0);
            BF256.mul(betaCube, 0, betaCube, 0, betaCube, 0);
        }
    }

    // ====== inv_norm_constraints ======
    // faest_aes.c:421 (prover) / faest_aes.c:482 (verifier).
    //
    // Single-element constraint that y * conjugates[1] * conjugates[4] == conjugates[0].
    // Prover splits this into degrees {0, 1, 2} by Schoenemann's product rule.

    static void invNormConstraintsProver128(long[] zDeg0, int z0Off,
                                            long[] zDeg1, int z1Off,
                                            long[] zDeg2, int z2Off,
                                            long[] conj, long[] conjTag,
                                            long[] y, long[] yTag,
                                            long[] t1, long[] t2)
    {
        // zDeg0 = yTag * conjTag[1] * conjTag[4]
        BF128.mul(t1, 0, yTag, 0, conjTag, 1 * BF128.LIMBS);
        BF128.mul(zDeg0, z0Off, t1, 0, conjTag, 4 * BF128.LIMBS);

        // zDeg1 = y*ct[1]*ct[4] + yt*ct[1]*c[4] + yt*c[1]*ct[4]
        BF128.mul(t1, 0, y, 0, conjTag, 1 * BF128.LIMBS);
        BF128.mul(zDeg1, z1Off, t1, 0, conjTag, 4 * BF128.LIMBS);
        BF128.mul(t1, 0, yTag, 0, conjTag, 1 * BF128.LIMBS);
        BF128.mul(t2, 0, t1, 0, conj, 4 * BF128.LIMBS);
        BF128.addInPlace(zDeg1, z1Off, t2, 0);
        BF128.mul(t1, 0, yTag, 0, conj, 1 * BF128.LIMBS);
        BF128.mul(t2, 0, t1, 0, conjTag, 4 * BF128.LIMBS);
        BF128.addInPlace(zDeg1, z1Off, t2, 0);

        // zDeg2 = y*c[1]*ct[4] + y*ct[1]*c[4] + yt*c[1]*c[4] + ct[0]
        BF128.mul(t1, 0, y, 0, conj, 1 * BF128.LIMBS);
        BF128.mul(zDeg2, z2Off, t1, 0, conjTag, 4 * BF128.LIMBS);
        BF128.mul(t1, 0, y, 0, conjTag, 1 * BF128.LIMBS);
        BF128.mul(t2, 0, t1, 0, conj, 4 * BF128.LIMBS);
        BF128.addInPlace(zDeg2, z2Off, t2, 0);
        BF128.mul(t1, 0, yTag, 0, conj, 1 * BF128.LIMBS);
        BF128.mul(t2, 0, t1, 0, conj, 4 * BF128.LIMBS);
        BF128.addInPlace(zDeg2, z2Off, t2, 0);
        BF128.addInPlace(zDeg2, z2Off, conjTag, 0 * BF128.LIMBS);
    }

    static void invNormConstraintsProver192(long[] zDeg0, int z0Off,
                                            long[] zDeg1, int z1Off,
                                            long[] zDeg2, int z2Off,
                                            long[] conj, long[] conjTag,
                                            long[] y, long[] yTag,
                                            long[] t1, long[] t2)
    {
        BF192.mul(t1, 0, yTag, 0, conjTag, 1 * BF192.LIMBS);
        BF192.mul(zDeg0, z0Off, t1, 0, conjTag, 4 * BF192.LIMBS);

        BF192.mul(t1, 0, y, 0, conjTag, 1 * BF192.LIMBS);
        BF192.mul(zDeg1, z1Off, t1, 0, conjTag, 4 * BF192.LIMBS);
        BF192.mul(t1, 0, yTag, 0, conjTag, 1 * BF192.LIMBS);
        BF192.mul(t2, 0, t1, 0, conj, 4 * BF192.LIMBS);
        BF192.addInPlace(zDeg1, z1Off, t2, 0);
        BF192.mul(t1, 0, yTag, 0, conj, 1 * BF192.LIMBS);
        BF192.mul(t2, 0, t1, 0, conjTag, 4 * BF192.LIMBS);
        BF192.addInPlace(zDeg1, z1Off, t2, 0);

        BF192.mul(t1, 0, y, 0, conj, 1 * BF192.LIMBS);
        BF192.mul(zDeg2, z2Off, t1, 0, conjTag, 4 * BF192.LIMBS);
        BF192.mul(t1, 0, y, 0, conjTag, 1 * BF192.LIMBS);
        BF192.mul(t2, 0, t1, 0, conj, 4 * BF192.LIMBS);
        BF192.addInPlace(zDeg2, z2Off, t2, 0);
        BF192.mul(t1, 0, yTag, 0, conj, 1 * BF192.LIMBS);
        BF192.mul(t2, 0, t1, 0, conj, 4 * BF192.LIMBS);
        BF192.addInPlace(zDeg2, z2Off, t2, 0);
        BF192.addInPlace(zDeg2, z2Off, conjTag, 0 * BF192.LIMBS);
    }

    static void invNormConstraintsProver256(long[] zDeg0, int z0Off,
                                            long[] zDeg1, int z1Off,
                                            long[] zDeg2, int z2Off,
                                            long[] conj, long[] conjTag,
                                            long[] y, long[] yTag,
                                            long[] t1, long[] t2)
    {
        BF256.mul(t1, 0, yTag, 0, conjTag, 1 * BF256.LIMBS);
        BF256.mul(zDeg0, z0Off, t1, 0, conjTag, 4 * BF256.LIMBS);

        BF256.mul(t1, 0, y, 0, conjTag, 1 * BF256.LIMBS);
        BF256.mul(zDeg1, z1Off, t1, 0, conjTag, 4 * BF256.LIMBS);
        BF256.mul(t1, 0, yTag, 0, conjTag, 1 * BF256.LIMBS);
        BF256.mul(t2, 0, t1, 0, conj, 4 * BF256.LIMBS);
        BF256.addInPlace(zDeg1, z1Off, t2, 0);
        BF256.mul(t1, 0, yTag, 0, conj, 1 * BF256.LIMBS);
        BF256.mul(t2, 0, t1, 0, conjTag, 4 * BF256.LIMBS);
        BF256.addInPlace(zDeg1, z1Off, t2, 0);

        BF256.mul(t1, 0, y, 0, conj, 1 * BF256.LIMBS);
        BF256.mul(zDeg2, z2Off, t1, 0, conjTag, 4 * BF256.LIMBS);
        BF256.mul(t1, 0, y, 0, conjTag, 1 * BF256.LIMBS);
        BF256.mul(t2, 0, t1, 0, conj, 4 * BF256.LIMBS);
        BF256.addInPlace(zDeg2, z2Off, t2, 0);
        BF256.mul(t1, 0, yTag, 0, conj, 1 * BF256.LIMBS);
        BF256.mul(t2, 0, t1, 0, conj, 4 * BF256.LIMBS);
        BF256.addInPlace(zDeg2, z2Off, t2, 0);
        BF256.addInPlace(zDeg2, z2Off, conjTag, 0 * BF256.LIMBS);
    }

    /**
     * z = y * c[1] * c[4] + c[0] * delta^2.
     * <p>
     * {@code d2} is the caller's pre-computed {@code delta * delta} — passing it in
     * avoids redundantly squaring delta on every inner-loop call. {@code t} is a
     * caller-allocated scratch of length {@code BF128.LIMBS}.
     */
    static void invNormConstraintsVerifier128(long[] zEval, int zEvalOff,
                                              long[] conjEval, long[] yEval,
                                              long[] d2, long[] t)
    {
        BF128.mul(t, 0, yEval, 0, conjEval, 1 * BF128.LIMBS);
        BF128.mul(zEval, zEvalOff, t, 0, conjEval, 4 * BF128.LIMBS);
        BF128.mul(t, 0, conjEval, 0 * BF128.LIMBS, d2, 0);
        BF128.addInPlace(zEval, zEvalOff, t, 0);
    }

    static void invNormConstraintsVerifier192(long[] zEval, int zEvalOff,
                                              long[] conjEval, long[] yEval,
                                              long[] d2, long[] t)
    {
        BF192.mul(t, 0, yEval, 0, conjEval, 1 * BF192.LIMBS);
        BF192.mul(zEval, zEvalOff, t, 0, conjEval, 4 * BF192.LIMBS);
        BF192.mul(t, 0, conjEval, 0 * BF192.LIMBS, d2, 0);
        BF192.addInPlace(zEval, zEvalOff, t, 0);
    }

    static void invNormConstraintsVerifier256(long[] zEval, int zEvalOff,
                                              long[] conjEval, long[] yEval,
                                              long[] d2, long[] t)
    {
        BF256.mul(t, 0, yEval, 0, conjEval, 1 * BF256.LIMBS);
        BF256.mul(zEval, zEvalOff, t, 0, conjEval, 4 * BF256.LIMBS);
        BF256.mul(t, 0, conjEval, 0 * BF256.LIMBS, d2, 0);
        BF256.addInPlace(zEval, zEvalOff, t, 0);
    }

    // ====== sbox_affine ======
    // faest_aes.c:559 (prover) / faest_aes.c:680 (verifier).
    //
    // Applies the AES S-box affine map (post-inverse part) at the byte_combine
    // level. The 9 coefficients are derived from the standard S-box affine
    // polynomial; when {@code dosq} is true we use the squared (Frobenius-twisted)
    // version with t=1 cyclic shift.

    private static final int[] SBOX_AFFINE_X    = { 0x05, 0x09, 0xf9, 0x25, 0xf4, 0x01, 0xb5, 0x8f, 0x63 };
    private static final int[] SBOX_AFFINE_X_SQ = { 0x11, 0x41, 0x07, 0x7d, 0x56, 0x01, 0xfc, 0xcf, 0xc2 };

    private static void sboxAffineConstants128(long[] C, boolean dosq)
    {
        int[] src = dosq ? SBOX_AFFINE_X_SQ : SBOX_AFFINE_X;
        byte[] tmp = new byte[8];
        for (int i = 0; i < 9; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                tmp[j] = (byte)((src[i] >>> j) & 1);
            }
            BF128.byteCombineBits(C, i * BF128.LIMBS, tmp, 0);
        }
    }

    private static void sboxAffineConstants192(long[] C, boolean dosq)
    {
        int[] src = dosq ? SBOX_AFFINE_X_SQ : SBOX_AFFINE_X;
        byte[] tmp = new byte[8];
        for (int i = 0; i < 9; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                tmp[j] = (byte)((src[i] >>> j) & 1);
            }
            BF192.byteCombineBits(C, i * BF192.LIMBS, tmp, 0);
        }
    }

    private static void sboxAffineConstants256(long[] C, boolean dosq)
    {
        int[] src = dosq ? SBOX_AFFINE_X_SQ : SBOX_AFFINE_X;
        byte[] tmp = new byte[8];
        for (int i = 0; i < 9; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                tmp[j] = (byte)((src[i] >>> j) & 1);
            }
            BF256.byteCombineBits(C, i * BF256.LIMBS, tmp, 0);
        }
    }

    static void sboxAffineProver128(long[] outDeg0, long[] outDeg1, long[] outDeg2,
                                    long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                    boolean dosq, int Nst)
    {
        long[] C = new long[9 * BF128.LIMBS];
        sboxAffineConstants128(C, dosq);
        int t = dosq ? 1 : 0;
        int Nstb = Nst * 4;
        long[] tmp = new long[BF128.LIMBS];

        // Zero the accumulators first (callers may pass any state).
        java.util.Arrays.fill(outDeg0, 0, Nstb * BF128.LIMBS, 0L);
        java.util.Arrays.fill(outDeg1, 0, Nstb * BF128.LIMBS, 0L);
        java.util.Arrays.fill(outDeg2, 0, Nstb * BF128.LIMBS, 0L);

        for (int i = 0; i < Nstb; i++)
        {
            int dst = i * BF128.LIMBS;
            for (int Cidx = 0; Cidx < 8; Cidx++)
            {
                int srcIdx = (i * 8 + (Cidx + t) % 8) * BF128.LIMBS;
                BF128.mul(tmp, 0, C, Cidx * BF128.LIMBS, inDeg2, srcIdx);
                BF128.addInPlace(outDeg2, dst, tmp, 0);
                BF128.mul(tmp, 0, C, Cidx * BF128.LIMBS, inDeg1, srcIdx);
                BF128.addInPlace(outDeg1, dst, tmp, 0);
                BF128.mul(tmp, 0, C, Cidx * BF128.LIMBS, inDeg0, srcIdx);
                BF128.addInPlace(outDeg0, dst, tmp, 0);
            }
            // out_deg2 += C[8]
            BF128.addInPlace(outDeg2, dst, C, 8 * BF128.LIMBS);
        }
    }

    static void sboxAffineProver192(long[] outDeg0, long[] outDeg1, long[] outDeg2,
                                    long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                    boolean dosq, int Nst)
    {
        long[] C = new long[9 * BF192.LIMBS];
        sboxAffineConstants192(C, dosq);
        int t = dosq ? 1 : 0;
        int Nstb = Nst * 4;
        long[] tmp = new long[BF192.LIMBS];

        java.util.Arrays.fill(outDeg0, 0, Nstb * BF192.LIMBS, 0L);
        java.util.Arrays.fill(outDeg1, 0, Nstb * BF192.LIMBS, 0L);
        java.util.Arrays.fill(outDeg2, 0, Nstb * BF192.LIMBS, 0L);

        for (int i = 0; i < Nstb; i++)
        {
            int dst = i * BF192.LIMBS;
            for (int Cidx = 0; Cidx < 8; Cidx++)
            {
                int srcIdx = (i * 8 + (Cidx + t) % 8) * BF192.LIMBS;
                BF192.mul(tmp, 0, C, Cidx * BF192.LIMBS, inDeg2, srcIdx);
                BF192.addInPlace(outDeg2, dst, tmp, 0);
                BF192.mul(tmp, 0, C, Cidx * BF192.LIMBS, inDeg1, srcIdx);
                BF192.addInPlace(outDeg1, dst, tmp, 0);
                BF192.mul(tmp, 0, C, Cidx * BF192.LIMBS, inDeg0, srcIdx);
                BF192.addInPlace(outDeg0, dst, tmp, 0);
            }
            BF192.addInPlace(outDeg2, dst, C, 8 * BF192.LIMBS);
        }
    }

    static void sboxAffineProver256(long[] outDeg0, long[] outDeg1, long[] outDeg2,
                                    long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                    boolean dosq, int Nst)
    {
        long[] C = new long[9 * BF256.LIMBS];
        sboxAffineConstants256(C, dosq);
        int t = dosq ? 1 : 0;
        int Nstb = Nst * 4;
        long[] tmp = new long[BF256.LIMBS];

        java.util.Arrays.fill(outDeg0, 0, Nstb * BF256.LIMBS, 0L);
        java.util.Arrays.fill(outDeg1, 0, Nstb * BF256.LIMBS, 0L);
        java.util.Arrays.fill(outDeg2, 0, Nstb * BF256.LIMBS, 0L);

        for (int i = 0; i < Nstb; i++)
        {
            int dst = i * BF256.LIMBS;
            for (int Cidx = 0; Cidx < 8; Cidx++)
            {
                int srcIdx = (i * 8 + (Cidx + t) % 8) * BF256.LIMBS;
                BF256.mul(tmp, 0, C, Cidx * BF256.LIMBS, inDeg2, srcIdx);
                BF256.addInPlace(outDeg2, dst, tmp, 0);
                BF256.mul(tmp, 0, C, Cidx * BF256.LIMBS, inDeg1, srcIdx);
                BF256.addInPlace(outDeg1, dst, tmp, 0);
                BF256.mul(tmp, 0, C, Cidx * BF256.LIMBS, inDeg0, srcIdx);
                BF256.addInPlace(outDeg0, dst, tmp, 0);
            }
            BF256.addInPlace(outDeg2, dst, C, 8 * BF256.LIMBS);
        }
    }

    static void sboxAffineVerifier128(long[] outDeg1, long[] inDeg1, long[] delta,
                                      boolean dosq, int Nst)
    {
        long[] C = new long[9 * BF128.LIMBS];
        sboxAffineConstants128(C, dosq);
        int t = dosq ? 1 : 0;
        int Nstb = Nst * 4;
        long[] tmp = new long[BF128.LIMBS];
        long[] d2 = new long[BF128.LIMBS];
        BF128.mul(d2, 0, delta, 0, delta, 0);
        long[] c8d2 = new long[BF128.LIMBS];
        BF128.mul(c8d2, 0, C, 8 * BF128.LIMBS, d2, 0);

        java.util.Arrays.fill(outDeg1, 0, Nstb * BF128.LIMBS, 0L);
        for (int i = 0; i < Nstb; i++)
        {
            int dst = i * BF128.LIMBS;
            for (int Cidx = 0; Cidx < 8; Cidx++)
            {
                int srcIdx = (i * 8 + (Cidx + t) % 8) * BF128.LIMBS;
                BF128.mul(tmp, 0, C, Cidx * BF128.LIMBS, inDeg1, srcIdx);
                BF128.addInPlace(outDeg1, dst, tmp, 0);
            }
            BF128.addInPlace(outDeg1, dst, c8d2, 0);
        }
    }

    static void sboxAffineVerifier192(long[] outDeg1, long[] inDeg1, long[] delta,
                                      boolean dosq, int Nst)
    {
        long[] C = new long[9 * BF192.LIMBS];
        sboxAffineConstants192(C, dosq);
        int t = dosq ? 1 : 0;
        int Nstb = Nst * 4;
        long[] tmp = new long[BF192.LIMBS];
        long[] d2 = new long[BF192.LIMBS];
        BF192.mul(d2, 0, delta, 0, delta, 0);
        long[] c8d2 = new long[BF192.LIMBS];
        BF192.mul(c8d2, 0, C, 8 * BF192.LIMBS, d2, 0);

        java.util.Arrays.fill(outDeg1, 0, Nstb * BF192.LIMBS, 0L);
        for (int i = 0; i < Nstb; i++)
        {
            int dst = i * BF192.LIMBS;
            for (int Cidx = 0; Cidx < 8; Cidx++)
            {
                int srcIdx = (i * 8 + (Cidx + t) % 8) * BF192.LIMBS;
                BF192.mul(tmp, 0, C, Cidx * BF192.LIMBS, inDeg1, srcIdx);
                BF192.addInPlace(outDeg1, dst, tmp, 0);
            }
            BF192.addInPlace(outDeg1, dst, c8d2, 0);
        }
    }

    static void sboxAffineVerifier256(long[] outDeg1, long[] inDeg1, long[] delta,
                                      boolean dosq, int Nst)
    {
        long[] C = new long[9 * BF256.LIMBS];
        sboxAffineConstants256(C, dosq);
        int t = dosq ? 1 : 0;
        int Nstb = Nst * 4;
        long[] tmp = new long[BF256.LIMBS];
        long[] d2 = new long[BF256.LIMBS];
        BF256.mul(d2, 0, delta, 0, delta, 0);
        long[] c8d2 = new long[BF256.LIMBS];
        BF256.mul(c8d2, 0, C, 8 * BF256.LIMBS, d2, 0);

        java.util.Arrays.fill(outDeg1, 0, Nstb * BF256.LIMBS, 0L);
        for (int i = 0; i < Nstb; i++)
        {
            int dst = i * BF256.LIMBS;
            for (int Cidx = 0; Cidx < 8; Cidx++)
            {
                int srcIdx = (i * 8 + (Cidx + t) % 8) * BF256.LIMBS;
                BF256.mul(tmp, 0, C, Cidx * BF256.LIMBS, inDeg1, srcIdx);
                BF256.addInPlace(outDeg1, dst, tmp, 0);
            }
            BF256.addInPlace(outDeg1, dst, c8d2, 0);
        }
    }

    // ====== mix_columns ======
    // faest_aes.c:907 (prover) / faest_aes.c:1220 (verifier).
    //
    // AES MixColumns at the byte_combine field-element level. The standard {01,02,03}
    // matrix coefficients are encoded as v1 / v2 / v3 (= byteCombineBits of {1,2,3}),
    // optionally squared for the Frobenius-twisted variant.

    private static void mixColumnsCoeffs128(long[] v1, long[] v2, long[] v3, boolean dosq)
    {
        byte[] one = {1,0,0,0,0,0,0,0};
        byte[] two = {0,1,0,0,0,0,0,0};
        byte[] three = {1,1,0,0,0,0,0,0};
        BF128.byteCombineBits(v1, 0, one, 0);
        BF128.byteCombineBits(v2, 0, two, 0);
        BF128.byteCombineBits(v3, 0, three, 0);
        if (dosq)
        {
            BF128.mul(v1, 0, v1, 0, v1, 0);
            BF128.mul(v2, 0, v2, 0, v2, 0);
            BF128.mul(v3, 0, v3, 0, v3, 0);
        }
    }

    private static void mixColumnsCoeffs192(long[] v1, long[] v2, long[] v3, boolean dosq)
    {
        byte[] one = {1,0,0,0,0,0,0,0};
        byte[] two = {0,1,0,0,0,0,0,0};
        byte[] three = {1,1,0,0,0,0,0,0};
        BF192.byteCombineBits(v1, 0, one, 0);
        BF192.byteCombineBits(v2, 0, two, 0);
        BF192.byteCombineBits(v3, 0, three, 0);
        if (dosq)
        {
            BF192.mul(v1, 0, v1, 0, v1, 0);
            BF192.mul(v2, 0, v2, 0, v2, 0);
            BF192.mul(v3, 0, v3, 0, v3, 0);
        }
    }

    private static void mixColumnsCoeffs256(long[] v1, long[] v2, long[] v3, boolean dosq)
    {
        byte[] one = {1,0,0,0,0,0,0,0};
        byte[] two = {0,1,0,0,0,0,0,0};
        byte[] three = {1,1,0,0,0,0,0,0};
        BF256.byteCombineBits(v1, 0, one, 0);
        BF256.byteCombineBits(v2, 0, two, 0);
        BF256.byteCombineBits(v3, 0, three, 0);
        if (dosq)
        {
            BF256.mul(v1, 0, v1, 0, v1, 0);
            BF256.mul(v2, 0, v2, 0, v2, 0);
            BF256.mul(v3, 0, v3, 0, v3, 0);
        }
    }

    /**
     * MixColumns row {@code rowK} produces output {@code y[i+rowK]} as a linear
     * combination of inputs {@code in[i+0..3]} with the row's coefficient pattern
     * (one of the four cyclic rotations of {v2, v3, v1, v1}).
     */
    private static void mixRow128(long[] out, int outOff, long[] in, int inOff,
                                  long[] cA, long[] cB, long[] cC, long[] cD)
    {
        long[] t = new long[BF128.LIMBS];
        BF128.mul(out, outOff, in, inOff, cA, 0);
        BF128.mul(t, 0, in, inOff + 1 * BF128.LIMBS, cB, 0); BF128.addInPlace(out, outOff, t, 0);
        BF128.mul(t, 0, in, inOff + 2 * BF128.LIMBS, cC, 0); BF128.addInPlace(out, outOff, t, 0);
        BF128.mul(t, 0, in, inOff + 3 * BF128.LIMBS, cD, 0); BF128.addInPlace(out, outOff, t, 0);
    }

    private static void mixRow192(long[] out, int outOff, long[] in, int inOff,
                                  long[] cA, long[] cB, long[] cC, long[] cD)
    {
        long[] t = new long[BF192.LIMBS];
        BF192.mul(out, outOff, in, inOff, cA, 0);
        BF192.mul(t, 0, in, inOff + 1 * BF192.LIMBS, cB, 0); BF192.addInPlace(out, outOff, t, 0);
        BF192.mul(t, 0, in, inOff + 2 * BF192.LIMBS, cC, 0); BF192.addInPlace(out, outOff, t, 0);
        BF192.mul(t, 0, in, inOff + 3 * BF192.LIMBS, cD, 0); BF192.addInPlace(out, outOff, t, 0);
    }

    private static void mixRow256(long[] out, int outOff, long[] in, int inOff,
                                  long[] cA, long[] cB, long[] cC, long[] cD)
    {
        long[] t = new long[BF256.LIMBS];
        BF256.mul(out, outOff, in, inOff, cA, 0);
        BF256.mul(t, 0, in, inOff + 1 * BF256.LIMBS, cB, 0); BF256.addInPlace(out, outOff, t, 0);
        BF256.mul(t, 0, in, inOff + 2 * BF256.LIMBS, cC, 0); BF256.addInPlace(out, outOff, t, 0);
        BF256.mul(t, 0, in, inOff + 3 * BF256.LIMBS, cD, 0); BF256.addInPlace(out, outOff, t, 0);
    }

    static void mixColumnsProver128(long[] yDeg0, long[] yDeg1, long[] yDeg2,
                                    long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                    boolean dosq, int Nst)
    {
        long[] v1 = new long[BF128.LIMBS], v2 = new long[BF128.LIMBS], v3 = new long[BF128.LIMBS];
        mixColumnsCoeffs128(v1, v2, v3, dosq);
        for (int c = 0; c < Nst; c++)
        {
            int colOff = 4 * c * BF128.LIMBS;
            // y[i0]: (v2,v3,v1,v1); y[i1]: (v1,v2,v3,v1); y[i2]: (v1,v1,v2,v3); y[i3]: (v3,v1,v1,v2)
            mixRow128(yDeg2, colOff + 0 * BF128.LIMBS, inDeg2, colOff, v2, v3, v1, v1);
            mixRow128(yDeg2, colOff + 1 * BF128.LIMBS, inDeg2, colOff, v1, v2, v3, v1);
            mixRow128(yDeg2, colOff + 2 * BF128.LIMBS, inDeg2, colOff, v1, v1, v2, v3);
            mixRow128(yDeg2, colOff + 3 * BF128.LIMBS, inDeg2, colOff, v3, v1, v1, v2);

            mixRow128(yDeg1, colOff + 0 * BF128.LIMBS, inDeg1, colOff, v2, v3, v1, v1);
            mixRow128(yDeg1, colOff + 1 * BF128.LIMBS, inDeg1, colOff, v1, v2, v3, v1);
            mixRow128(yDeg1, colOff + 2 * BF128.LIMBS, inDeg1, colOff, v1, v1, v2, v3);
            mixRow128(yDeg1, colOff + 3 * BF128.LIMBS, inDeg1, colOff, v3, v1, v1, v2);

            mixRow128(yDeg0, colOff + 0 * BF128.LIMBS, inDeg0, colOff, v2, v3, v1, v1);
            mixRow128(yDeg0, colOff + 1 * BF128.LIMBS, inDeg0, colOff, v1, v2, v3, v1);
            mixRow128(yDeg0, colOff + 2 * BF128.LIMBS, inDeg0, colOff, v1, v1, v2, v3);
            mixRow128(yDeg0, colOff + 3 * BF128.LIMBS, inDeg0, colOff, v3, v1, v1, v2);
        }
    }

    static void mixColumnsProver192(long[] yDeg0, long[] yDeg1, long[] yDeg2,
                                    long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                    boolean dosq, int Nst)
    {
        long[] v1 = new long[BF192.LIMBS], v2 = new long[BF192.LIMBS], v3 = new long[BF192.LIMBS];
        mixColumnsCoeffs192(v1, v2, v3, dosq);
        for (int c = 0; c < Nst; c++)
        {
            int colOff = 4 * c * BF192.LIMBS;
            mixRow192(yDeg2, colOff + 0 * BF192.LIMBS, inDeg2, colOff, v2, v3, v1, v1);
            mixRow192(yDeg2, colOff + 1 * BF192.LIMBS, inDeg2, colOff, v1, v2, v3, v1);
            mixRow192(yDeg2, colOff + 2 * BF192.LIMBS, inDeg2, colOff, v1, v1, v2, v3);
            mixRow192(yDeg2, colOff + 3 * BF192.LIMBS, inDeg2, colOff, v3, v1, v1, v2);

            mixRow192(yDeg1, colOff + 0 * BF192.LIMBS, inDeg1, colOff, v2, v3, v1, v1);
            mixRow192(yDeg1, colOff + 1 * BF192.LIMBS, inDeg1, colOff, v1, v2, v3, v1);
            mixRow192(yDeg1, colOff + 2 * BF192.LIMBS, inDeg1, colOff, v1, v1, v2, v3);
            mixRow192(yDeg1, colOff + 3 * BF192.LIMBS, inDeg1, colOff, v3, v1, v1, v2);

            mixRow192(yDeg0, colOff + 0 * BF192.LIMBS, inDeg0, colOff, v2, v3, v1, v1);
            mixRow192(yDeg0, colOff + 1 * BF192.LIMBS, inDeg0, colOff, v1, v2, v3, v1);
            mixRow192(yDeg0, colOff + 2 * BF192.LIMBS, inDeg0, colOff, v1, v1, v2, v3);
            mixRow192(yDeg0, colOff + 3 * BF192.LIMBS, inDeg0, colOff, v3, v1, v1, v2);
        }
    }

    static void mixColumnsProver256(long[] yDeg0, long[] yDeg1, long[] yDeg2,
                                    long[] inDeg0, long[] inDeg1, long[] inDeg2,
                                    boolean dosq, int Nst)
    {
        long[] v1 = new long[BF256.LIMBS], v2 = new long[BF256.LIMBS], v3 = new long[BF256.LIMBS];
        mixColumnsCoeffs256(v1, v2, v3, dosq);
        for (int c = 0; c < Nst; c++)
        {
            int colOff = 4 * c * BF256.LIMBS;
            mixRow256(yDeg2, colOff + 0 * BF256.LIMBS, inDeg2, colOff, v2, v3, v1, v1);
            mixRow256(yDeg2, colOff + 1 * BF256.LIMBS, inDeg2, colOff, v1, v2, v3, v1);
            mixRow256(yDeg2, colOff + 2 * BF256.LIMBS, inDeg2, colOff, v1, v1, v2, v3);
            mixRow256(yDeg2, colOff + 3 * BF256.LIMBS, inDeg2, colOff, v3, v1, v1, v2);

            mixRow256(yDeg1, colOff + 0 * BF256.LIMBS, inDeg1, colOff, v2, v3, v1, v1);
            mixRow256(yDeg1, colOff + 1 * BF256.LIMBS, inDeg1, colOff, v1, v2, v3, v1);
            mixRow256(yDeg1, colOff + 2 * BF256.LIMBS, inDeg1, colOff, v1, v1, v2, v3);
            mixRow256(yDeg1, colOff + 3 * BF256.LIMBS, inDeg1, colOff, v3, v1, v1, v2);

            mixRow256(yDeg0, colOff + 0 * BF256.LIMBS, inDeg0, colOff, v2, v3, v1, v1);
            mixRow256(yDeg0, colOff + 1 * BF256.LIMBS, inDeg0, colOff, v1, v2, v3, v1);
            mixRow256(yDeg0, colOff + 2 * BF256.LIMBS, inDeg0, colOff, v1, v1, v2, v3);
            mixRow256(yDeg0, colOff + 3 * BF256.LIMBS, inDeg0, colOff, v3, v1, v1, v2);
        }
    }

    static void mixColumnsVerifier128(long[] yDeg1, long[] inDeg1, boolean dosq, int Nst)
    {
        long[] v1 = new long[BF128.LIMBS], v2 = new long[BF128.LIMBS], v3 = new long[BF128.LIMBS];
        mixColumnsCoeffs128(v1, v2, v3, dosq);
        for (int c = 0; c < Nst; c++)
        {
            int colOff = 4 * c * BF128.LIMBS;
            mixRow128(yDeg1, colOff + 0 * BF128.LIMBS, inDeg1, colOff, v2, v3, v1, v1);
            mixRow128(yDeg1, colOff + 1 * BF128.LIMBS, inDeg1, colOff, v1, v2, v3, v1);
            mixRow128(yDeg1, colOff + 2 * BF128.LIMBS, inDeg1, colOff, v1, v1, v2, v3);
            mixRow128(yDeg1, colOff + 3 * BF128.LIMBS, inDeg1, colOff, v3, v1, v1, v2);
        }
    }

    static void mixColumnsVerifier192(long[] yDeg1, long[] inDeg1, boolean dosq, int Nst)
    {
        long[] v1 = new long[BF192.LIMBS], v2 = new long[BF192.LIMBS], v3 = new long[BF192.LIMBS];
        mixColumnsCoeffs192(v1, v2, v3, dosq);
        for (int c = 0; c < Nst; c++)
        {
            int colOff = 4 * c * BF192.LIMBS;
            mixRow192(yDeg1, colOff + 0 * BF192.LIMBS, inDeg1, colOff, v2, v3, v1, v1);
            mixRow192(yDeg1, colOff + 1 * BF192.LIMBS, inDeg1, colOff, v1, v2, v3, v1);
            mixRow192(yDeg1, colOff + 2 * BF192.LIMBS, inDeg1, colOff, v1, v1, v2, v3);
            mixRow192(yDeg1, colOff + 3 * BF192.LIMBS, inDeg1, colOff, v3, v1, v1, v2);
        }
    }

    static void mixColumnsVerifier256(long[] yDeg1, long[] inDeg1, boolean dosq, int Nst)
    {
        long[] v1 = new long[BF256.LIMBS], v2 = new long[BF256.LIMBS], v3 = new long[BF256.LIMBS];
        mixColumnsCoeffs256(v1, v2, v3, dosq);
        for (int c = 0; c < Nst; c++)
        {
            int colOff = 4 * c * BF256.LIMBS;
            mixRow256(yDeg1, colOff + 0 * BF256.LIMBS, inDeg1, colOff, v2, v3, v1, v1);
            mixRow256(yDeg1, colOff + 1 * BF256.LIMBS, inDeg1, colOff, v1, v2, v3, v1);
            mixRow256(yDeg1, colOff + 2 * BF256.LIMBS, inDeg1, colOff, v1, v1, v2, v3);
            mixRow256(yDeg1, colOff + 3 * BF256.LIMBS, inDeg1, colOff, v3, v1, v1, v2);
        }
    }

    // ====== inverse_affine (byte + state) ======
    // faest_aes.c:2054 (byte prover) / faest_aes.c:2103 (state prover) /
    // faest_aes.c:2128 (byte verifier) / faest_aes.c:2174 (state verifier).
    //
    // Per-bit linear map: y_bits[i] = x[(i-1)&7] ^ x[(i-3)&7] ^ x[(i-6)&7] ^ c_i,
    // with c_i = 1 only for i in {0, 2}. This inverts the AES S-box affine.

    private static int invAffineSrc(int bitI, int offset)
    {
        // offsets: -1, -3, -6 mod 8
        return ((bitI - offset) + 8) & 7;
    }

    static void inverseAffineByteProver128(byte[] y, int yOff, long[] yTag, int yTagOff,
                                           byte[] x, int xOff, long[] xTag, int xTagOff)
    {
        for (int i = 0; i < 8; i++)
        {
            int c = (i == 0 || i == 2) ? 1 : 0;
            y[yOff + i] = (byte)((x[xOff + invAffineSrc(i, 1)]
                ^ x[xOff + invAffineSrc(i, 3)]
                ^ x[xOff + invAffineSrc(i, 6)]
                ^ c) & 1);
            long[] tmp = new long[BF128.LIMBS];
            BF128.add(tmp, 0, xTag, xTagOff + invAffineSrc(i, 1) * BF128.LIMBS,
                xTag, xTagOff + invAffineSrc(i, 3) * BF128.LIMBS);
            BF128.add(yTag, yTagOff + i * BF128.LIMBS, tmp, 0,
                xTag, xTagOff + invAffineSrc(i, 6) * BF128.LIMBS);
        }
    }

    static void inverseAffineByteProver192(byte[] y, int yOff, long[] yTag, int yTagOff,
                                           byte[] x, int xOff, long[] xTag, int xTagOff)
    {
        for (int i = 0; i < 8; i++)
        {
            int c = (i == 0 || i == 2) ? 1 : 0;
            y[yOff + i] = (byte)((x[xOff + invAffineSrc(i, 1)]
                ^ x[xOff + invAffineSrc(i, 3)]
                ^ x[xOff + invAffineSrc(i, 6)]
                ^ c) & 1);
            long[] tmp = new long[BF192.LIMBS];
            BF192.add(tmp, 0, xTag, xTagOff + invAffineSrc(i, 1) * BF192.LIMBS,
                xTag, xTagOff + invAffineSrc(i, 3) * BF192.LIMBS);
            BF192.add(yTag, yTagOff + i * BF192.LIMBS, tmp, 0,
                xTag, xTagOff + invAffineSrc(i, 6) * BF192.LIMBS);
        }
    }

    static void inverseAffineByteProver256(byte[] y, int yOff, long[] yTag, int yTagOff,
                                           byte[] x, int xOff, long[] xTag, int xTagOff)
    {
        for (int i = 0; i < 8; i++)
        {
            int c = (i == 0 || i == 2) ? 1 : 0;
            y[yOff + i] = (byte)((x[xOff + invAffineSrc(i, 1)]
                ^ x[xOff + invAffineSrc(i, 3)]
                ^ x[xOff + invAffineSrc(i, 6)]
                ^ c) & 1);
            long[] tmp = new long[BF256.LIMBS];
            BF256.add(tmp, 0, xTag, xTagOff + invAffineSrc(i, 1) * BF256.LIMBS,
                xTag, xTagOff + invAffineSrc(i, 3) * BF256.LIMBS);
            BF256.add(yTag, yTagOff + i * BF256.LIMBS, tmp, 0,
                xTag, xTagOff + invAffineSrc(i, 6) * BF256.LIMBS);
        }
    }

    static void inverseAffineByteVerifier128(long[] yKey, int yKeyOff, long[] xKey, int xKeyOff,
                                             long[] delta)
    {
        long[] tmp = new long[BF128.LIMBS];
        long[] cDelta = new long[BF128.LIMBS];
        for (int i = 0; i < 8; i++)
        {
            int c = (i == 0 || i == 2) ? 1 : 0;
            BF128.mulBit(cDelta, 0, delta, 0, c);
            BF128.add(tmp, 0, xKey, xKeyOff + invAffineSrc(i, 1) * BF128.LIMBS,
                xKey, xKeyOff + invAffineSrc(i, 3) * BF128.LIMBS);
            BF128.addInPlace(tmp, 0, xKey, xKeyOff + invAffineSrc(i, 6) * BF128.LIMBS);
            BF128.add(yKey, yKeyOff + i * BF128.LIMBS, tmp, 0, cDelta, 0);
        }
    }

    static void inverseAffineByteVerifier192(long[] yKey, int yKeyOff, long[] xKey, int xKeyOff,
                                             long[] delta)
    {
        long[] tmp = new long[BF192.LIMBS];
        long[] cDelta = new long[BF192.LIMBS];
        for (int i = 0; i < 8; i++)
        {
            int c = (i == 0 || i == 2) ? 1 : 0;
            BF192.mulBit(cDelta, 0, delta, 0, c);
            BF192.add(tmp, 0, xKey, xKeyOff + invAffineSrc(i, 1) * BF192.LIMBS,
                xKey, xKeyOff + invAffineSrc(i, 3) * BF192.LIMBS);
            BF192.addInPlace(tmp, 0, xKey, xKeyOff + invAffineSrc(i, 6) * BF192.LIMBS);
            BF192.add(yKey, yKeyOff + i * BF192.LIMBS, tmp, 0, cDelta, 0);
        }
    }

    static void inverseAffineByteVerifier256(long[] yKey, int yKeyOff, long[] xKey, int xKeyOff,
                                             long[] delta)
    {
        long[] tmp = new long[BF256.LIMBS];
        long[] cDelta = new long[BF256.LIMBS];
        for (int i = 0; i < 8; i++)
        {
            int c = (i == 0 || i == 2) ? 1 : 0;
            BF256.mulBit(cDelta, 0, delta, 0, c);
            BF256.add(tmp, 0, xKey, xKeyOff + invAffineSrc(i, 1) * BF256.LIMBS,
                xKey, xKeyOff + invAffineSrc(i, 3) * BF256.LIMBS);
            BF256.addInPlace(tmp, 0, xKey, xKeyOff + invAffineSrc(i, 6) * BF256.LIMBS);
            BF256.add(yKey, yKeyOff + i * BF256.LIMBS, tmp, 0, cDelta, 0);
        }
    }

    static void inverseAffineProver128(byte[] y, long[] yTag, byte[] x, long[] xTag, int Nst)
    {
        int Nstb = Nst * 4;
        for (int i = 0; i < Nstb; i++)
        {
            inverseAffineByteProver128(y, i * 8, yTag, i * 8 * BF128.LIMBS,
                x, i * 8, xTag, i * 8 * BF128.LIMBS);
        }
    }

    static void inverseAffineProver192(byte[] y, long[] yTag, byte[] x, long[] xTag, int Nst)
    {
        int Nstb = Nst * 4;
        for (int i = 0; i < Nstb; i++)
        {
            inverseAffineByteProver192(y, i * 8, yTag, i * 8 * BF192.LIMBS,
                x, i * 8, xTag, i * 8 * BF192.LIMBS);
        }
    }

    static void inverseAffineProver256(byte[] y, long[] yTag, byte[] x, long[] xTag, int Nst)
    {
        int Nstb = Nst * 4;
        for (int i = 0; i < Nstb; i++)
        {
            inverseAffineByteProver256(y, i * 8, yTag, i * 8 * BF256.LIMBS,
                x, i * 8, xTag, i * 8 * BF256.LIMBS);
        }
    }

    static void inverseAffineVerifier128(long[] yKey, long[] xKey, long[] delta, int Nst)
    {
        int Nstb = Nst * 4;
        for (int i = 0; i < Nstb; i++)
        {
            inverseAffineByteVerifier128(yKey, i * 8 * BF128.LIMBS, xKey, i * 8 * BF128.LIMBS, delta);
        }
    }

    static void inverseAffineVerifier192(long[] yKey, long[] xKey, long[] delta, int Nst)
    {
        int Nstb = Nst * 4;
        for (int i = 0; i < Nstb; i++)
        {
            inverseAffineByteVerifier192(yKey, i * 8 * BF192.LIMBS, xKey, i * 8 * BF192.LIMBS, delta);
        }
    }

    static void inverseAffineVerifier256(long[] yKey, long[] xKey, long[] delta, int Nst)
    {
        int Nstb = Nst * 4;
        for (int i = 0; i < Nstb; i++)
        {
            inverseAffineByteVerifier256(yKey, i * 8 * BF256.LIMBS, xKey, i * 8 * BF256.LIMBS, delta);
        }
    }

    // ====== bitwise_mix_column ======
    // faest_aes.c:1583 (prover) / faest_aes.c:1797 (verifier).
    //
    // Bit-level MixColumns over a state of Nst columns × 4 rows × 8 bits.
    // For each column c and row r:
    //   - a_bits = s[r] (8 bits)
    //   - b_bits = xtime(a_bits) — multiplication-by-x in GF(2^8) at bit level
    // Then each output byte is a linear combination of a_bits[r] and b_bits[r]
    // matching the AES MixColumns matrix.

    private static void xtime128(byte[] aBits, long[] aTag, byte[] bBits, long[] bTag, int r)
    {
        // b[0] = a[7];      b[1] = a[0] ^ a[7]; b[2] = a[1];      b[3] = a[2] ^ a[7];
        // b[4] = a[3] ^ a[7]; b[5] = a[4]; b[6] = a[5];           b[7] = a[6];
        int ab = r * 8;
        bBits[ab + 0] = aBits[ab + 7];
        bBits[ab + 1] = (byte)((aBits[ab + 0] ^ aBits[ab + 7]) & 1);
        bBits[ab + 2] = aBits[ab + 1];
        bBits[ab + 3] = (byte)((aBits[ab + 2] ^ aBits[ab + 7]) & 1);
        bBits[ab + 4] = (byte)((aBits[ab + 3] ^ aBits[ab + 7]) & 1);
        bBits[ab + 5] = aBits[ab + 4];
        bBits[ab + 6] = aBits[ab + 5];
        bBits[ab + 7] = aBits[ab + 6];

        int abL = ab * BF128.LIMBS;
        System.arraycopy(aTag, (ab + 7) * BF128.LIMBS, bTag, abL + 0 * BF128.LIMBS, BF128.LIMBS);
        BF128.add(bTag, abL + 1 * BF128.LIMBS, aTag, (ab + 0) * BF128.LIMBS,
            aTag, (ab + 7) * BF128.LIMBS);
        System.arraycopy(aTag, (ab + 1) * BF128.LIMBS, bTag, abL + 2 * BF128.LIMBS, BF128.LIMBS);
        BF128.add(bTag, abL + 3 * BF128.LIMBS, aTag, (ab + 2) * BF128.LIMBS,
            aTag, (ab + 7) * BF128.LIMBS);
        BF128.add(bTag, abL + 4 * BF128.LIMBS, aTag, (ab + 3) * BF128.LIMBS,
            aTag, (ab + 7) * BF128.LIMBS);
        System.arraycopy(aTag, (ab + 4) * BF128.LIMBS, bTag, abL + 5 * BF128.LIMBS, BF128.LIMBS);
        System.arraycopy(aTag, (ab + 5) * BF128.LIMBS, bTag, abL + 6 * BF128.LIMBS, BF128.LIMBS);
        System.arraycopy(aTag, (ab + 6) * BF128.LIMBS, bTag, abL + 7 * BF128.LIMBS, BF128.LIMBS);
    }

    private static void xtime192(byte[] aBits, long[] aTag, byte[] bBits, long[] bTag, int r)
    {
        int ab = r * 8;
        bBits[ab + 0] = aBits[ab + 7];
        bBits[ab + 1] = (byte)((aBits[ab + 0] ^ aBits[ab + 7]) & 1);
        bBits[ab + 2] = aBits[ab + 1];
        bBits[ab + 3] = (byte)((aBits[ab + 2] ^ aBits[ab + 7]) & 1);
        bBits[ab + 4] = (byte)((aBits[ab + 3] ^ aBits[ab + 7]) & 1);
        bBits[ab + 5] = aBits[ab + 4];
        bBits[ab + 6] = aBits[ab + 5];
        bBits[ab + 7] = aBits[ab + 6];

        int abL = ab * BF192.LIMBS;
        System.arraycopy(aTag, (ab + 7) * BF192.LIMBS, bTag, abL + 0 * BF192.LIMBS, BF192.LIMBS);
        BF192.add(bTag, abL + 1 * BF192.LIMBS, aTag, (ab + 0) * BF192.LIMBS,
            aTag, (ab + 7) * BF192.LIMBS);
        System.arraycopy(aTag, (ab + 1) * BF192.LIMBS, bTag, abL + 2 * BF192.LIMBS, BF192.LIMBS);
        BF192.add(bTag, abL + 3 * BF192.LIMBS, aTag, (ab + 2) * BF192.LIMBS,
            aTag, (ab + 7) * BF192.LIMBS);
        BF192.add(bTag, abL + 4 * BF192.LIMBS, aTag, (ab + 3) * BF192.LIMBS,
            aTag, (ab + 7) * BF192.LIMBS);
        System.arraycopy(aTag, (ab + 4) * BF192.LIMBS, bTag, abL + 5 * BF192.LIMBS, BF192.LIMBS);
        System.arraycopy(aTag, (ab + 5) * BF192.LIMBS, bTag, abL + 6 * BF192.LIMBS, BF192.LIMBS);
        System.arraycopy(aTag, (ab + 6) * BF192.LIMBS, bTag, abL + 7 * BF192.LIMBS, BF192.LIMBS);
    }

    private static void xtime256(byte[] aBits, long[] aTag, byte[] bBits, long[] bTag, int r)
    {
        int ab = r * 8;
        bBits[ab + 0] = aBits[ab + 7];
        bBits[ab + 1] = (byte)((aBits[ab + 0] ^ aBits[ab + 7]) & 1);
        bBits[ab + 2] = aBits[ab + 1];
        bBits[ab + 3] = (byte)((aBits[ab + 2] ^ aBits[ab + 7]) & 1);
        bBits[ab + 4] = (byte)((aBits[ab + 3] ^ aBits[ab + 7]) & 1);
        bBits[ab + 5] = aBits[ab + 4];
        bBits[ab + 6] = aBits[ab + 5];
        bBits[ab + 7] = aBits[ab + 6];

        int abL = ab * BF256.LIMBS;
        System.arraycopy(aTag, (ab + 7) * BF256.LIMBS, bTag, abL + 0 * BF256.LIMBS, BF256.LIMBS);
        BF256.add(bTag, abL + 1 * BF256.LIMBS, aTag, (ab + 0) * BF256.LIMBS,
            aTag, (ab + 7) * BF256.LIMBS);
        System.arraycopy(aTag, (ab + 1) * BF256.LIMBS, bTag, abL + 2 * BF256.LIMBS, BF256.LIMBS);
        BF256.add(bTag, abL + 3 * BF256.LIMBS, aTag, (ab + 2) * BF256.LIMBS,
            aTag, (ab + 7) * BF256.LIMBS);
        BF256.add(bTag, abL + 4 * BF256.LIMBS, aTag, (ab + 3) * BF256.LIMBS,
            aTag, (ab + 7) * BF256.LIMBS);
        System.arraycopy(aTag, (ab + 4) * BF256.LIMBS, bTag, abL + 5 * BF256.LIMBS, BF256.LIMBS);
        System.arraycopy(aTag, (ab + 5) * BF256.LIMBS, bTag, abL + 6 * BF256.LIMBS, BF256.LIMBS);
        System.arraycopy(aTag, (ab + 6) * BF256.LIMBS, bTag, abL + 7 * BF256.LIMBS, BF256.LIMBS);
    }

    static void bitwiseMixColumnProver128(byte[] out, long[] outTag, byte[] s, long[] sTag, int Nst)
    {
        byte[] aBits = new byte[32];
        long[] aTag = new long[32 * BF128.LIMBS];
        byte[] bBits = new byte[32];
        long[] bTag = new long[32 * BF128.LIMBS];

        for (int c = 0; c < Nst; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                System.arraycopy(s, 32 * c + 8 * r, aBits, r * 8, 8);
                System.arraycopy(sTag, (32 * c + 8 * r) * BF128.LIMBS,
                    aTag, r * 8 * BF128.LIMBS, 8 * BF128.LIMBS);
                xtime128(aBits, aTag, bBits, bTag, r);
            }
            for (int ib = 0; ib < 8; ib++)
            {
                // Upstream rows (rB0, rA1, rA2, rB1, rALast):
                // Row 0: b[0]^a[3]^a[2]^b[1]^a[1]  → (0, 3, 2, 1, 1)
                // Row 1: b[1]^a[0]^a[3]^b[2]^a[2]  → (1, 0, 3, 2, 2)
                // Row 2: b[2]^a[1]^a[0]^b[3]^a[3]  → (2, 1, 0, 3, 3)
                // Row 3: b[3]^a[2]^a[1]^b[0]^a[0]  → (3, 2, 1, 0, 0)
                bitwiseMixRowBit128(out, outTag, c * 4 + 0, ib, bBits, bTag, aBits, aTag, 0, 3, 2, 1, 1);
                bitwiseMixRowBit128(out, outTag, c * 4 + 1, ib, bBits, bTag, aBits, aTag, 1, 0, 3, 2, 2);
                bitwiseMixRowBit128(out, outTag, c * 4 + 2, ib, bBits, bTag, aBits, aTag, 2, 1, 0, 3, 3);
                bitwiseMixRowBit128(out, outTag, c * 4 + 3, ib, bBits, bTag, aBits, aTag, 3, 2, 1, 0, 0);
            }
        }
    }

    /** out[dstByte][ib] = b[rB0] ^ a[rA1] ^ a[rA2] ^ b[rB1] ^ a[rALast], at bit position ib. */
    private static void bitwiseMixRowBit128(byte[] out, long[] outTag, int dstByte, int ib,
                                            byte[] bBits, long[] bTag, byte[] aBits, long[] aTag,
                                            int rB0, int rA1, int rA2, int rB1, int rALast)
    {
        int outIdx = (dstByte * 8 + ib);
        out[outIdx] = (byte)((bBits[rB0 * 8 + ib]
            ^ aBits[rA1 * 8 + ib]
            ^ aBits[rA2 * 8 + ib]
            ^ bBits[rB1 * 8 + ib]
            ^ aBits[rALast * 8 + ib]) & 1);

        BF128.add(outTag, outIdx * BF128.LIMBS,
            bTag, (rB0 * 8 + ib) * BF128.LIMBS, aTag, (rA1 * 8 + ib) * BF128.LIMBS);
        BF128.addInPlace(outTag, outIdx * BF128.LIMBS, aTag, (rA2 * 8 + ib) * BF128.LIMBS);
        BF128.addInPlace(outTag, outIdx * BF128.LIMBS, bTag, (rB1 * 8 + ib) * BF128.LIMBS);
        BF128.addInPlace(outTag, outIdx * BF128.LIMBS, aTag, (rALast * 8 + ib) * BF128.LIMBS);
    }

    static void bitwiseMixColumnProver192(byte[] out, long[] outTag, byte[] s, long[] sTag, int Nst)
    {
        byte[] aBits = new byte[32];
        long[] aTag = new long[32 * BF192.LIMBS];
        byte[] bBits = new byte[32];
        long[] bTag = new long[32 * BF192.LIMBS];

        for (int c = 0; c < Nst; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                System.arraycopy(s, 32 * c + 8 * r, aBits, r * 8, 8);
                System.arraycopy(sTag, (32 * c + 8 * r) * BF192.LIMBS,
                    aTag, r * 8 * BF192.LIMBS, 8 * BF192.LIMBS);
                xtime192(aBits, aTag, bBits, bTag, r);
            }
            for (int ib = 0; ib < 8; ib++)
            {
                bitwiseMixRowBit192(out, outTag, c * 4 + 0, ib, bBits, bTag, aBits, aTag, 0, 3, 2, 1, 1);
                bitwiseMixRowBit192(out, outTag, c * 4 + 1, ib, bBits, bTag, aBits, aTag, 1, 0, 3, 2, 2);
                bitwiseMixRowBit192(out, outTag, c * 4 + 2, ib, bBits, bTag, aBits, aTag, 2, 1, 0, 3, 3);
                bitwiseMixRowBit192(out, outTag, c * 4 + 3, ib, bBits, bTag, aBits, aTag, 3, 2, 1, 0, 0);
            }
        }
    }

    private static void bitwiseMixRowBit192(byte[] out, long[] outTag, int dstByte, int ib,
                                            byte[] bBits, long[] bTag, byte[] aBits, long[] aTag,
                                            int rB0, int rA1, int rA2, int rB1, int rALast)
    {
        int outIdx = (dstByte * 8 + ib);
        out[outIdx] = (byte)((bBits[rB0 * 8 + ib]
            ^ aBits[rA1 * 8 + ib]
            ^ aBits[rA2 * 8 + ib]
            ^ bBits[rB1 * 8 + ib]
            ^ aBits[rALast * 8 + ib]) & 1);
        BF192.add(outTag, outIdx * BF192.LIMBS,
            bTag, (rB0 * 8 + ib) * BF192.LIMBS, aTag, (rA1 * 8 + ib) * BF192.LIMBS);
        BF192.addInPlace(outTag, outIdx * BF192.LIMBS, aTag, (rA2 * 8 + ib) * BF192.LIMBS);
        BF192.addInPlace(outTag, outIdx * BF192.LIMBS, bTag, (rB1 * 8 + ib) * BF192.LIMBS);
        BF192.addInPlace(outTag, outIdx * BF192.LIMBS, aTag, (rALast * 8 + ib) * BF192.LIMBS);
    }

    static void bitwiseMixColumnProver256(byte[] out, long[] outTag, byte[] s, long[] sTag, int Nst)
    {
        byte[] aBits = new byte[32];
        long[] aTag = new long[32 * BF256.LIMBS];
        byte[] bBits = new byte[32];
        long[] bTag = new long[32 * BF256.LIMBS];

        for (int c = 0; c < Nst; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                System.arraycopy(s, 32 * c + 8 * r, aBits, r * 8, 8);
                System.arraycopy(sTag, (32 * c + 8 * r) * BF256.LIMBS,
                    aTag, r * 8 * BF256.LIMBS, 8 * BF256.LIMBS);
                xtime256(aBits, aTag, bBits, bTag, r);
            }
            for (int ib = 0; ib < 8; ib++)
            {
                bitwiseMixRowBit256(out, outTag, c * 4 + 0, ib, bBits, bTag, aBits, aTag, 0, 3, 2, 1, 1);
                bitwiseMixRowBit256(out, outTag, c * 4 + 1, ib, bBits, bTag, aBits, aTag, 1, 0, 3, 2, 2);
                bitwiseMixRowBit256(out, outTag, c * 4 + 2, ib, bBits, bTag, aBits, aTag, 2, 1, 0, 3, 3);
                bitwiseMixRowBit256(out, outTag, c * 4 + 3, ib, bBits, bTag, aBits, aTag, 3, 2, 1, 0, 0);
            }
        }
    }

    private static void bitwiseMixRowBit256(byte[] out, long[] outTag, int dstByte, int ib,
                                            byte[] bBits, long[] bTag, byte[] aBits, long[] aTag,
                                            int rB0, int rA1, int rA2, int rB1, int rALast)
    {
        int outIdx = (dstByte * 8 + ib);
        out[outIdx] = (byte)((bBits[rB0 * 8 + ib]
            ^ aBits[rA1 * 8 + ib]
            ^ aBits[rA2 * 8 + ib]
            ^ bBits[rB1 * 8 + ib]
            ^ aBits[rALast * 8 + ib]) & 1);
        BF256.add(outTag, outIdx * BF256.LIMBS,
            bTag, (rB0 * 8 + ib) * BF256.LIMBS, aTag, (rA1 * 8 + ib) * BF256.LIMBS);
        BF256.addInPlace(outTag, outIdx * BF256.LIMBS, aTag, (rA2 * 8 + ib) * BF256.LIMBS);
        BF256.addInPlace(outTag, outIdx * BF256.LIMBS, bTag, (rB1 * 8 + ib) * BF256.LIMBS);
        BF256.addInPlace(outTag, outIdx * BF256.LIMBS, aTag, (rALast * 8 + ib) * BF256.LIMBS);
    }

    static void bitwiseMixColumnVerifier128(long[] outKey, long[] sKeysTag, int Nst)
    {
        long[] aKey = new long[32 * BF128.LIMBS];
        long[] bKey = new long[32 * BF128.LIMBS];
        for (int c = 0; c < Nst; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                System.arraycopy(sKeysTag, (32 * c + 8 * r) * BF128.LIMBS,
                    aKey, r * 8 * BF128.LIMBS, 8 * BF128.LIMBS);
            }
            // xtime on key form (no bits, only tag arithmetic).
            for (int r = 0; r < 4; r++)
            {
                int ab = r * 8 * BF128.LIMBS;
                System.arraycopy(aKey, ab + 7 * BF128.LIMBS, bKey, ab + 0 * BF128.LIMBS, BF128.LIMBS);
                BF128.add(bKey, ab + 1 * BF128.LIMBS, aKey, ab + 0 * BF128.LIMBS, aKey, ab + 7 * BF128.LIMBS);
                System.arraycopy(aKey, ab + 1 * BF128.LIMBS, bKey, ab + 2 * BF128.LIMBS, BF128.LIMBS);
                BF128.add(bKey, ab + 3 * BF128.LIMBS, aKey, ab + 2 * BF128.LIMBS, aKey, ab + 7 * BF128.LIMBS);
                BF128.add(bKey, ab + 4 * BF128.LIMBS, aKey, ab + 3 * BF128.LIMBS, aKey, ab + 7 * BF128.LIMBS);
                System.arraycopy(aKey, ab + 4 * BF128.LIMBS, bKey, ab + 5 * BF128.LIMBS, BF128.LIMBS);
                System.arraycopy(aKey, ab + 5 * BF128.LIMBS, bKey, ab + 6 * BF128.LIMBS, BF128.LIMBS);
                System.arraycopy(aKey, ab + 6 * BF128.LIMBS, bKey, ab + 7 * BF128.LIMBS, BF128.LIMBS);
            }
            for (int ib = 0; ib < 8; ib++)
            {
                bitwiseMixRowKey128(outKey, c * 4 + 0, ib, bKey, aKey, 0, 3, 2, 1, 1);
                bitwiseMixRowKey128(outKey, c * 4 + 1, ib, bKey, aKey, 1, 0, 3, 2, 2);
                bitwiseMixRowKey128(outKey, c * 4 + 2, ib, bKey, aKey, 2, 1, 0, 3, 3);
                bitwiseMixRowKey128(outKey, c * 4 + 3, ib, bKey, aKey, 3, 2, 1, 0, 0);
            }
        }
    }

    private static void bitwiseMixRowKey128(long[] outKey, int dstByte, int ib,
                                            long[] bKey, long[] aKey,
                                            int rB0, int rA1, int rA2, int rB1, int rALast)
    {
        int outIdx = (dstByte * 8 + ib) * BF128.LIMBS;
        BF128.add(outKey, outIdx, bKey, (rB0 * 8 + ib) * BF128.LIMBS, aKey, (rA1 * 8 + ib) * BF128.LIMBS);
        BF128.addInPlace(outKey, outIdx, aKey, (rA2 * 8 + ib) * BF128.LIMBS);
        BF128.addInPlace(outKey, outIdx, bKey, (rB1 * 8 + ib) * BF128.LIMBS);
        BF128.addInPlace(outKey, outIdx, aKey, (rALast * 8 + ib) * BF128.LIMBS);
    }

    static void bitwiseMixColumnVerifier192(long[] outKey, long[] sKeysTag, int Nst)
    {
        long[] aKey = new long[32 * BF192.LIMBS];
        long[] bKey = new long[32 * BF192.LIMBS];
        for (int c = 0; c < Nst; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                System.arraycopy(sKeysTag, (32 * c + 8 * r) * BF192.LIMBS,
                    aKey, r * 8 * BF192.LIMBS, 8 * BF192.LIMBS);
            }
            for (int r = 0; r < 4; r++)
            {
                int ab = r * 8 * BF192.LIMBS;
                System.arraycopy(aKey, ab + 7 * BF192.LIMBS, bKey, ab + 0 * BF192.LIMBS, BF192.LIMBS);
                BF192.add(bKey, ab + 1 * BF192.LIMBS, aKey, ab + 0 * BF192.LIMBS, aKey, ab + 7 * BF192.LIMBS);
                System.arraycopy(aKey, ab + 1 * BF192.LIMBS, bKey, ab + 2 * BF192.LIMBS, BF192.LIMBS);
                BF192.add(bKey, ab + 3 * BF192.LIMBS, aKey, ab + 2 * BF192.LIMBS, aKey, ab + 7 * BF192.LIMBS);
                BF192.add(bKey, ab + 4 * BF192.LIMBS, aKey, ab + 3 * BF192.LIMBS, aKey, ab + 7 * BF192.LIMBS);
                System.arraycopy(aKey, ab + 4 * BF192.LIMBS, bKey, ab + 5 * BF192.LIMBS, BF192.LIMBS);
                System.arraycopy(aKey, ab + 5 * BF192.LIMBS, bKey, ab + 6 * BF192.LIMBS, BF192.LIMBS);
                System.arraycopy(aKey, ab + 6 * BF192.LIMBS, bKey, ab + 7 * BF192.LIMBS, BF192.LIMBS);
            }
            for (int ib = 0; ib < 8; ib++)
            {
                bitwiseMixRowKey192(outKey, c * 4 + 0, ib, bKey, aKey, 0, 3, 2, 1, 1);
                bitwiseMixRowKey192(outKey, c * 4 + 1, ib, bKey, aKey, 1, 0, 3, 2, 2);
                bitwiseMixRowKey192(outKey, c * 4 + 2, ib, bKey, aKey, 2, 1, 0, 3, 3);
                bitwiseMixRowKey192(outKey, c * 4 + 3, ib, bKey, aKey, 3, 2, 1, 0, 0);
            }
        }
    }

    private static void bitwiseMixRowKey192(long[] outKey, int dstByte, int ib,
                                            long[] bKey, long[] aKey,
                                            int rB0, int rA1, int rA2, int rB1, int rALast)
    {
        int outIdx = (dstByte * 8 + ib) * BF192.LIMBS;
        BF192.add(outKey, outIdx, bKey, (rB0 * 8 + ib) * BF192.LIMBS, aKey, (rA1 * 8 + ib) * BF192.LIMBS);
        BF192.addInPlace(outKey, outIdx, aKey, (rA2 * 8 + ib) * BF192.LIMBS);
        BF192.addInPlace(outKey, outIdx, bKey, (rB1 * 8 + ib) * BF192.LIMBS);
        BF192.addInPlace(outKey, outIdx, aKey, (rALast * 8 + ib) * BF192.LIMBS);
    }

    static void bitwiseMixColumnVerifier256(long[] outKey, long[] sKeysTag, int Nst)
    {
        long[] aKey = new long[32 * BF256.LIMBS];
        long[] bKey = new long[32 * BF256.LIMBS];
        for (int c = 0; c < Nst; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                System.arraycopy(sKeysTag, (32 * c + 8 * r) * BF256.LIMBS,
                    aKey, r * 8 * BF256.LIMBS, 8 * BF256.LIMBS);
            }
            for (int r = 0; r < 4; r++)
            {
                int ab = r * 8 * BF256.LIMBS;
                System.arraycopy(aKey, ab + 7 * BF256.LIMBS, bKey, ab + 0 * BF256.LIMBS, BF256.LIMBS);
                BF256.add(bKey, ab + 1 * BF256.LIMBS, aKey, ab + 0 * BF256.LIMBS, aKey, ab + 7 * BF256.LIMBS);
                System.arraycopy(aKey, ab + 1 * BF256.LIMBS, bKey, ab + 2 * BF256.LIMBS, BF256.LIMBS);
                BF256.add(bKey, ab + 3 * BF256.LIMBS, aKey, ab + 2 * BF256.LIMBS, aKey, ab + 7 * BF256.LIMBS);
                BF256.add(bKey, ab + 4 * BF256.LIMBS, aKey, ab + 3 * BF256.LIMBS, aKey, ab + 7 * BF256.LIMBS);
                System.arraycopy(aKey, ab + 4 * BF256.LIMBS, bKey, ab + 5 * BF256.LIMBS, BF256.LIMBS);
                System.arraycopy(aKey, ab + 5 * BF256.LIMBS, bKey, ab + 6 * BF256.LIMBS, BF256.LIMBS);
                System.arraycopy(aKey, ab + 6 * BF256.LIMBS, bKey, ab + 7 * BF256.LIMBS, BF256.LIMBS);
            }
            for (int ib = 0; ib < 8; ib++)
            {
                bitwiseMixRowKey256(outKey, c * 4 + 0, ib, bKey, aKey, 0, 3, 2, 1, 1);
                bitwiseMixRowKey256(outKey, c * 4 + 1, ib, bKey, aKey, 1, 0, 3, 2, 2);
                bitwiseMixRowKey256(outKey, c * 4 + 2, ib, bKey, aKey, 2, 1, 0, 3, 3);
                bitwiseMixRowKey256(outKey, c * 4 + 3, ib, bKey, aKey, 3, 2, 1, 0, 0);
            }
        }
    }

    private static void bitwiseMixRowKey256(long[] outKey, int dstByte, int ib,
                                            long[] bKey, long[] aKey,
                                            int rB0, int rA1, int rA2, int rB1, int rALast)
    {
        int outIdx = (dstByte * 8 + ib) * BF256.LIMBS;
        BF256.add(outKey, outIdx, bKey, (rB0 * 8 + ib) * BF256.LIMBS, aKey, (rA1 * 8 + ib) * BF256.LIMBS);
        BF256.addInPlace(outKey, outIdx, aKey, (rA2 * 8 + ib) * BF256.LIMBS);
        BF256.addInPlace(outKey, outIdx, bKey, (rB1 * 8 + ib) * BF256.LIMBS);
        BF256.addInPlace(outKey, outIdx, aKey, (rALast * 8 + ib) * BF256.LIMBS);
    }
}
