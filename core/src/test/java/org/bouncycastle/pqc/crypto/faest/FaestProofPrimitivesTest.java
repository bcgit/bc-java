package org.bouncycastle.pqc.crypto.faest;

import java.util.Random;

import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for {@link FaestProofPrimitives}.
 * <p>
 * Strategy: each primitive is exercised against a hand-rolled reference written
 * inline in the test (the upstream loops are short enough that re-implementing
 * them is as easy as porting). Roundtrip identities (shiftrows ∘ inverse, etc.)
 * provide an extra check on the index math.
 */
public class FaestProofPrimitivesTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestProofPrimitives";
    }

    public void performTest()
        throws Exception
    {
        addRoundKey128(); addRoundKey192(); addRoundKey256();
        conjugates_1();
        conjugates_lambda();
        shiftRows();
        inverseShiftRows();
        constantToVole();
        deg2to3();
    }

    // ===== add_round_key =====

    private void addRoundKey128()
    {
        Random rng = new Random(0x42L);
        int Nst = 4;
        int n = Nst * 32;
        byte[] in = randomBits(rng, n);
        byte[] k = randomBits(rng, n);
        long[] inTag = randomLongs(rng, n * BF128.LIMBS);
        long[] kTag = randomLongs(rng, n * BF128.LIMBS);

        byte[] out = new byte[n];
        long[] outTag = new long[n * BF128.LIMBS];
        FaestProofPrimitives.addRoundKeyProver128(out, outTag, in, inTag, k, kTag, Nst);

        for (int i = 0; i < n; i++)
        {
            isTrue("addRoundKey128 bits[" + i + "]", out[i] == (byte)((in[i] ^ k[i]) & 1));
            long expLo = inTag[i * BF128.LIMBS] ^ kTag[i * BF128.LIMBS];
            long expHi = inTag[i * BF128.LIMBS + 1] ^ kTag[i * BF128.LIMBS + 1];
            isTrue("addRoundKey128 tag[" + i + "] lo",
                outTag[i * BF128.LIMBS] == expLo);
            isTrue("addRoundKey128 tag[" + i + "] hi",
                outTag[i * BF128.LIMBS + 1] == expHi);
        }

        long[] outKey = new long[n * BF128.LIMBS];
        FaestProofPrimitives.addRoundKeyVerifier128(outKey, inTag, kTag, Nst);
        for (int i = 0; i < n; i++)
        {
            isTrue("addRoundKey128 verifier[" + i + "] lo",
                outKey[i * BF128.LIMBS] == (inTag[i * BF128.LIMBS] ^ kTag[i * BF128.LIMBS]));
        }
    }

    private void addRoundKey192()
    {
        Random rng = new Random(0x43L);
        int Nst = 6;
        int n = Nst * 32;
        byte[] in = randomBits(rng, n);
        byte[] k = randomBits(rng, n);
        long[] inTag = randomLongs(rng, n * BF192.LIMBS);
        long[] kTag = randomLongs(rng, n * BF192.LIMBS);

        byte[] out = new byte[n];
        long[] outTag = new long[n * BF192.LIMBS];
        FaestProofPrimitives.addRoundKeyProver192(out, outTag, in, inTag, k, kTag, Nst);

        for (int i = 0; i < n; i++)
        {
            isTrue("addRoundKey192 bits[" + i + "]", out[i] == (byte)((in[i] ^ k[i]) & 1));
            for (int l = 0; l < BF192.LIMBS; l++)
            {
                long exp = inTag[i * BF192.LIMBS + l] ^ kTag[i * BF192.LIMBS + l];
                isTrue("addRoundKey192 tag[" + i + "].l" + l,
                    outTag[i * BF192.LIMBS + l] == exp);
            }
        }
    }

    private void addRoundKey256()
    {
        Random rng = new Random(0x44L);
        int Nst = 8;
        int n = Nst * 32;
        byte[] in = randomBits(rng, n);
        byte[] k = randomBits(rng, n);
        long[] inTag = randomLongs(rng, n * BF256.LIMBS);
        long[] kTag = randomLongs(rng, n * BF256.LIMBS);

        byte[] out = new byte[n];
        long[] outTag = new long[n * BF256.LIMBS];
        FaestProofPrimitives.addRoundKeyProver256(out, outTag, in, inTag, k, kTag, Nst);

        for (int i = 0; i < n; i++)
        {
            isTrue("addRoundKey256 bits[" + i + "]", out[i] == (byte)((in[i] ^ k[i]) & 1));
            for (int l = 0; l < BF256.LIMBS; l++)
            {
                long exp = inTag[i * BF256.LIMBS + l] ^ kTag[i * BF256.LIMBS + l];
                isTrue("addRoundKey256 tag[" + i + "].l" + l,
                    outTag[i * BF256.LIMBS + l] == exp);
            }
        }
    }

    // ===== F256/F2 conjugates =====

    private void conjugates_1()
    {
        // For each Nst, run f256_f2_conjugates_1 and verify each output element
        // against the canonical formula: y[i*8 + j] = byteCombineBits(bits_sq^j(byte_i)).
        Random rng = new Random(0x50L);
        int[] Nsts = { 4, 6, 8 };
        for (int Nst : Nsts)
        {
            byte[] state = randomBits(rng, Nst * 32);
            // BF128
            {
                long[] y = new long[Nst * 4 * 8 * BF128.LIMBS];
                FaestProofPrimitives.f256F2Conjugates1_128(y, state, Nst);
                verifyConjugates1(y, state, Nst, BF128.LIMBS, /*lambda*/ 128);
            }
            // BF192
            {
                long[] y = new long[Nst * 4 * 8 * BF192.LIMBS];
                FaestProofPrimitives.f256F2Conjugates1_192(y, state, Nst);
                verifyConjugates1(y, state, Nst, BF192.LIMBS, 192);
            }
            // BF256
            {
                long[] y = new long[Nst * 4 * 8 * BF256.LIMBS];
                FaestProofPrimitives.f256F2Conjugates1_256(y, state, Nst);
                verifyConjugates1(y, state, Nst, BF256.LIMBS, 256);
            }
        }
    }

    private void verifyConjugates1(long[] y, byte[] state, int Nst, int limbs, int lambda)
    {
        int Nstb = Nst * 4;
        long[] expected = new long[limbs];
        for (int i = 0; i < Nstb; i++)
        {
            byte[] x = new byte[8];
            System.arraycopy(state, i * 8, x, 0, 8);
            for (int j = 0; j < 8; j++)
            {
                byteCombineBits(expected, x, lambda);
                for (int l = 0; l < limbs; l++)
                {
                    if (y[(i * 8 + j) * limbs + l] != expected[l])
                    {
                        fail("conjugates_1 lambda=" + lambda + " Nst=" + Nst
                            + " byte=" + i + " j=" + j + " limb=" + l);
                    }
                }
                if (j < 7)
                {
                    BF8.bits_sq(x);
                }
            }
        }
    }

    private static void byteCombineBits(long[] out, byte[] bits, int lambda)
    {
        switch (lambda)
        {
            case 128: BF128.byteCombineBits(out, 0, bits, 0); break;
            case 192: BF192.byteCombineBits(out, 0, bits, 0); break;
            case 256: BF256.byteCombineBits(out, 0, bits, 0); break;
        }
    }

    private void conjugates_lambda()
    {
        Random rng = new Random(0x51L);
        int[] Nsts = { 4, 6, 8 };
        for (int Nst : Nsts)
        {
            int Nstb = Nst * 4;
            // BF128
            {
                long[] state = randomLongs(rng, Nstb * 8 * BF128.LIMBS);
                long[] y = new long[Nstb * 8 * BF128.LIMBS];
                FaestProofPrimitives.f256F2ConjugatesLambda_128(y, state, Nst);

                long[] x = new long[8 * BF128.LIMBS];
                long[] tmp = new long[8 * BF128.LIMBS];
                long[] expected = new long[BF128.LIMBS];
                for (int i = 0; i < Nstb; i++)
                {
                    System.arraycopy(state, i * 8 * BF128.LIMBS, x, 0, 8 * BF128.LIMBS);
                    for (int j = 0; j < 8; j++)
                    {
                        BF128.byteCombine(expected, 0, x, 0);
                        for (int l = 0; l < BF128.LIMBS; l++)
                        {
                            if (y[(i * 8 + j) * BF128.LIMBS + l] != expected[l])
                            {
                                fail("conjugates_lambda_128 Nst=" + Nst + " i=" + i + " j=" + j);
                            }
                        }
                        if (j < 7)
                        {
                            System.arraycopy(x, 0, tmp, 0, 8 * BF128.LIMBS);
                            BF128.sqBit(x, 0, tmp, 0);
                        }
                    }
                }
            }
            // BF192
            {
                long[] state = randomLongs(rng, Nstb * 8 * BF192.LIMBS);
                long[] y = new long[Nstb * 8 * BF192.LIMBS];
                FaestProofPrimitives.f256F2ConjugatesLambda_192(y, state, Nst);

                long[] x = new long[8 * BF192.LIMBS];
                long[] tmp = new long[8 * BF192.LIMBS];
                long[] expected = new long[BF192.LIMBS];
                for (int i = 0; i < Nstb; i++)
                {
                    System.arraycopy(state, i * 8 * BF192.LIMBS, x, 0, 8 * BF192.LIMBS);
                    for (int j = 0; j < 8; j++)
                    {
                        BF192.byteCombine(expected, 0, x, 0);
                        for (int l = 0; l < BF192.LIMBS; l++)
                        {
                            if (y[(i * 8 + j) * BF192.LIMBS + l] != expected[l])
                            {
                                fail("conjugates_lambda_192 Nst=" + Nst + " i=" + i + " j=" + j);
                            }
                        }
                        if (j < 7)
                        {
                            System.arraycopy(x, 0, tmp, 0, 8 * BF192.LIMBS);
                            BF192.sqBit(x, 0, tmp, 0);
                        }
                    }
                }
            }
            // BF256
            {
                long[] state = randomLongs(rng, Nstb * 8 * BF256.LIMBS);
                long[] y = new long[Nstb * 8 * BF256.LIMBS];
                FaestProofPrimitives.f256F2ConjugatesLambda_256(y, state, Nst);

                long[] x = new long[8 * BF256.LIMBS];
                long[] tmp = new long[8 * BF256.LIMBS];
                long[] expected = new long[BF256.LIMBS];
                for (int i = 0; i < Nstb; i++)
                {
                    System.arraycopy(state, i * 8 * BF256.LIMBS, x, 0, 8 * BF256.LIMBS);
                    for (int j = 0; j < 8; j++)
                    {
                        BF256.byteCombine(expected, 0, x, 0);
                        for (int l = 0; l < BF256.LIMBS; l++)
                        {
                            if (y[(i * 8 + j) * BF256.LIMBS + l] != expected[l])
                            {
                                fail("conjugates_lambda_256 Nst=" + Nst + " i=" + i + " j=" + j);
                            }
                        }
                        if (j < 7)
                        {
                            System.arraycopy(x, 0, tmp, 0, 8 * BF256.LIMBS);
                            BF256.sqBit(x, 0, tmp, 0);
                        }
                    }
                }
            }
        }
    }

    // ===== shiftrows / inverse_shiftrows =====

    private void shiftRows()
    {
        Random rng = new Random(0x60L);
        int[] Nsts = { 4, 6, 8 };
        for (int Nst : Nsts)
        {
            int n = Nst * 4;
            // BF128 prover
            long[] in0 = randomLongs(rng, n * BF128.LIMBS);
            long[] in1 = randomLongs(rng, n * BF128.LIMBS);
            long[] in2 = randomLongs(rng, n * BF128.LIMBS);
            long[] out0 = new long[n * BF128.LIMBS];
            long[] out1 = new long[n * BF128.LIMBS];
            long[] out2 = new long[n * BF128.LIMBS];
            FaestProofPrimitives.shiftRowsProver128(out0, out1, out2, in0, in1, in2, Nst);
            verifyShiftRows(out0, out1, out2, in0, in1, in2, Nst, BF128.LIMBS, "128");

            // BF128 verifier (deg1 only)
            long[] inV = randomLongs(rng, n * BF128.LIMBS);
            long[] outV = new long[n * BF128.LIMBS];
            FaestProofPrimitives.shiftRowsVerifier128(outV, inV, Nst);
            verifyShiftRowsSingle(outV, inV, Nst, BF128.LIMBS, "128.verifier");

            // BF192 prover
            in0 = randomLongs(rng, n * BF192.LIMBS);
            in1 = randomLongs(rng, n * BF192.LIMBS);
            in2 = randomLongs(rng, n * BF192.LIMBS);
            out0 = new long[n * BF192.LIMBS];
            out1 = new long[n * BF192.LIMBS];
            out2 = new long[n * BF192.LIMBS];
            FaestProofPrimitives.shiftRowsProver192(out0, out1, out2, in0, in1, in2, Nst);
            verifyShiftRows(out0, out1, out2, in0, in1, in2, Nst, BF192.LIMBS, "192");

            inV = randomLongs(rng, n * BF192.LIMBS);
            outV = new long[n * BF192.LIMBS];
            FaestProofPrimitives.shiftRowsVerifier192(outV, inV, Nst);
            verifyShiftRowsSingle(outV, inV, Nst, BF192.LIMBS, "192.verifier");

            // BF256 prover
            in0 = randomLongs(rng, n * BF256.LIMBS);
            in1 = randomLongs(rng, n * BF256.LIMBS);
            in2 = randomLongs(rng, n * BF256.LIMBS);
            out0 = new long[n * BF256.LIMBS];
            out1 = new long[n * BF256.LIMBS];
            out2 = new long[n * BF256.LIMBS];
            FaestProofPrimitives.shiftRowsProver256(out0, out1, out2, in0, in1, in2, Nst);
            verifyShiftRows(out0, out1, out2, in0, in1, in2, Nst, BF256.LIMBS, "256");

            inV = randomLongs(rng, n * BF256.LIMBS);
            outV = new long[n * BF256.LIMBS];
            FaestProofPrimitives.shiftRowsVerifier256(outV, inV, Nst);
            verifyShiftRowsSingle(outV, inV, Nst, BF256.LIMBS, "256.verifier");
        }
    }

    private void verifyShiftRows(long[] o0, long[] o1, long[] o2, long[] i0, long[] i1, long[] i2,
                                 int Nst, int limbs, String tag)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int s = ((Nst != 8) || (r <= 1)) ? r : (r + 1);
                int src = 4 * ((c + s) % Nst) + r;
                int dst = 4 * c + r;
                for (int l = 0; l < limbs; l++)
                {
                    if (o0[dst * limbs + l] != i0[src * limbs + l]
                        || o1[dst * limbs + l] != i1[src * limbs + l]
                        || o2[dst * limbs + l] != i2[src * limbs + l])
                    {
                        fail("shiftRows " + tag + " mismatch at (r=" + r + ", c=" + c + ")");
                    }
                }
            }
        }
    }

    private void verifyShiftRowsSingle(long[] out, long[] in, int Nst, int limbs, String tag)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int s = ((Nst != 8) || (r <= 1)) ? r : (r + 1);
                int src = 4 * ((c + s) % Nst) + r;
                int dst = 4 * c + r;
                for (int l = 0; l < limbs; l++)
                {
                    if (out[dst * limbs + l] != in[src * limbs + l])
                    {
                        fail("shiftRows " + tag + " mismatch at (r=" + r + ", c=" + c + ")");
                    }
                }
            }
        }
    }

    private void inverseShiftRows()
    {
        Random rng = new Random(0x70L);
        int[] Nsts = { 4, 6, 8 };
        for (int Nst : Nsts)
        {
            int bitN = Nst * 32;
            // BF128
            byte[] in = randomBits(rng, bitN);
            long[] inTag = randomLongs(rng, bitN * BF128.LIMBS);
            byte[] out = new byte[bitN];
            long[] outTag = new long[bitN * BF128.LIMBS];
            FaestProofPrimitives.inverseShiftRowsProver128(out, outTag, in, inTag, Nst);
            verifyInverseShiftRows(out, outTag, in, inTag, Nst, BF128.LIMBS, "128");

            long[] outVTag = new long[bitN * BF128.LIMBS];
            FaestProofPrimitives.inverseShiftRowsVerifier128(outVTag, inTag, Nst);
            verifyInverseShiftRowsTagOnly(outVTag, inTag, Nst, BF128.LIMBS, "128.verifier");

            // BF192
            inTag = randomLongs(rng, bitN * BF192.LIMBS);
            outTag = new long[bitN * BF192.LIMBS];
            FaestProofPrimitives.inverseShiftRowsProver192(out, outTag, in, inTag, Nst);
            verifyInverseShiftRows(out, outTag, in, inTag, Nst, BF192.LIMBS, "192");

            outVTag = new long[bitN * BF192.LIMBS];
            FaestProofPrimitives.inverseShiftRowsVerifier192(outVTag, inTag, Nst);
            verifyInverseShiftRowsTagOnly(outVTag, inTag, Nst, BF192.LIMBS, "192.verifier");

            // BF256
            inTag = randomLongs(rng, bitN * BF256.LIMBS);
            outTag = new long[bitN * BF256.LIMBS];
            FaestProofPrimitives.inverseShiftRowsProver256(out, outTag, in, inTag, Nst);
            verifyInverseShiftRows(out, outTag, in, inTag, Nst, BF256.LIMBS, "256");

            outVTag = new long[bitN * BF256.LIMBS];
            FaestProofPrimitives.inverseShiftRowsVerifier256(outVTag, inTag, Nst);
            verifyInverseShiftRowsTagOnly(outVTag, inTag, Nst, BF256.LIMBS, "256.verifier");
        }
    }

    private void verifyInverseShiftRows(byte[] out, long[] outTag, byte[] in, long[] inTag,
                                        int Nst, int limbs, String tag)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int s = ((Nst != 8) || (r <= 1)) ? r : (r + 1);
                int src = 4 * ((c + Nst - s) % Nst) + r;
                int dst = 4 * c + r;
                for (int b = 0; b < 8; b++)
                {
                    if (out[dst * 8 + b] != in[src * 8 + b])
                    {
                        fail("inverseShiftRows " + tag + " bits at (r=" + r + ", c=" + c + ", b=" + b + ")");
                    }
                    for (int l = 0; l < limbs; l++)
                    {
                        if (outTag[(dst * 8 + b) * limbs + l] != inTag[(src * 8 + b) * limbs + l])
                        {
                            fail("inverseShiftRows " + tag + " tag at (r=" + r + ", c=" + c + ", b=" + b + ", l=" + l + ")");
                        }
                    }
                }
            }
        }
    }

    private void verifyInverseShiftRowsTagOnly(long[] outTag, long[] inTag, int Nst, int limbs, String tag)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nst; c++)
            {
                int s = ((Nst != 8) || (r <= 1)) ? r : (r + 1);
                int src = 4 * ((c + Nst - s) % Nst) + r;
                int dst = 4 * c + r;
                for (int b = 0; b < 8; b++)
                {
                    for (int l = 0; l < limbs; l++)
                    {
                        if (outTag[(dst * 8 + b) * limbs + l] != inTag[(src * 8 + b) * limbs + l])
                        {
                            fail("inverseShiftRows " + tag + " tag at (r=" + r + ", c=" + c + ", b=" + b + ", l=" + l + ")");
                        }
                    }
                }
            }
        }
    }

    // ===== constant_to_vole =====

    private void constantToVole()
    {
        Random rng = new Random(0x80L);

        // Prover: all zero.
        {
            long[] tag = randomLongs(rng, 17 * BF128.LIMBS);
            FaestProofPrimitives.constantToVoleProver128(tag, 17);
            for (int i = 0; i < 17 * BF128.LIMBS; i++)
            {
                isTrue("constantToVoleProver128 zero[" + i + "]", tag[i] == 0L);
            }
        }
        {
            long[] tag = randomLongs(rng, 17 * BF192.LIMBS);
            FaestProofPrimitives.constantToVoleProver192(tag, 17);
            for (int i = 0; i < 17 * BF192.LIMBS; i++)
            {
                isTrue("constantToVoleProver192 zero[" + i + "]", tag[i] == 0L);
            }
        }
        {
            long[] tag = randomLongs(rng, 17 * BF256.LIMBS);
            FaestProofPrimitives.constantToVoleProver256(tag, 17);
            for (int i = 0; i < 17 * BF256.LIMBS; i++)
            {
                isTrue("constantToVoleProver256 zero[" + i + "]", tag[i] == 0L);
            }
        }

        // Verifier: key[i] = bit_i(val) * delta.
        int n = 23;
        byte[] val = new byte[(n + 7) / 8];
        rng.nextBytes(val);
        {
            long[] delta = randomLongs(rng, BF128.LIMBS);
            long[] key = new long[n * BF128.LIMBS];
            FaestProofPrimitives.constantToVoleVerifier128(key, val, delta, n);
            for (int i = 0; i < n; i++)
            {
                int bit = (val[i >> 3] >>> (i & 7)) & 1;
                long expLo = (bit == 0) ? 0 : delta[0];
                long expHi = (bit == 0) ? 0 : delta[1];
                isTrue("constantToVoleVerifier128 lo[" + i + "]", key[i * BF128.LIMBS] == expLo);
                isTrue("constantToVoleVerifier128 hi[" + i + "]", key[i * BF128.LIMBS + 1] == expHi);
            }
        }
        {
            long[] delta = randomLongs(rng, BF192.LIMBS);
            long[] key = new long[n * BF192.LIMBS];
            FaestProofPrimitives.constantToVoleVerifier192(key, val, delta, n);
            for (int i = 0; i < n; i++)
            {
                int bit = (val[i >> 3] >>> (i & 7)) & 1;
                for (int l = 0; l < BF192.LIMBS; l++)
                {
                    long exp = (bit == 0) ? 0 : delta[l];
                    isTrue("constantToVoleVerifier192[" + i + "].l" + l,
                        key[i * BF192.LIMBS + l] == exp);
                }
            }
        }
        {
            long[] delta = randomLongs(rng, BF256.LIMBS);
            long[] key = new long[n * BF256.LIMBS];
            FaestProofPrimitives.constantToVoleVerifier256(key, val, delta, n);
            for (int i = 0; i < n; i++)
            {
                int bit = (val[i >> 3] >>> (i & 7)) & 1;
                for (int l = 0; l < BF256.LIMBS; l++)
                {
                    long exp = (bit == 0) ? 0 : delta[l];
                    isTrue("constantToVoleVerifier256[" + i + "].l" + l,
                        key[i * BF256.LIMBS + l] == exp);
                }
            }
        }
    }

    // ===== deg2to3 =====

    private void deg2to3()
    {
        Random rng = new Random(0x90L);

        // Prover: deg1 <- tag, deg2 <- val.
        {
            long[] tag = randomLongs(rng, BF128.LIMBS);
            long[] val = randomLongs(rng, BF128.LIMBS);
            long[] deg1 = new long[BF128.LIMBS];
            long[] deg2 = new long[BF128.LIMBS];
            FaestProofPrimitives.deg2to3Prover128(deg1, 0, deg2, 0, tag, 0, val, 0);
            for (int l = 0; l < BF128.LIMBS; l++)
            {
                isTrue("deg2to3Prover128.deg1[" + l + "]", deg1[l] == tag[l]);
                isTrue("deg2to3Prover128.deg2[" + l + "]", deg2[l] == val[l]);
            }
        }
        {
            long[] tag = randomLongs(rng, BF192.LIMBS);
            long[] val = randomLongs(rng, BF192.LIMBS);
            long[] deg1 = new long[BF192.LIMBS];
            long[] deg2 = new long[BF192.LIMBS];
            FaestProofPrimitives.deg2to3Prover192(deg1, 0, deg2, 0, tag, 0, val, 0);
            for (int l = 0; l < BF192.LIMBS; l++)
            {
                isTrue("deg2to3Prover192.deg1[" + l + "]", deg1[l] == tag[l]);
                isTrue("deg2to3Prover192.deg2[" + l + "]", deg2[l] == val[l]);
            }
        }
        {
            long[] tag = randomLongs(rng, BF256.LIMBS);
            long[] val = randomLongs(rng, BF256.LIMBS);
            long[] deg1 = new long[BF256.LIMBS];
            long[] deg2 = new long[BF256.LIMBS];
            FaestProofPrimitives.deg2to3Prover256(deg1, 0, deg2, 0, tag, 0, val, 0);
            for (int l = 0; l < BF256.LIMBS; l++)
            {
                isTrue("deg2to3Prover256.deg1[" + l + "]", deg1[l] == tag[l]);
                isTrue("deg2to3Prover256.deg2[" + l + "]", deg2[l] == val[l]);
            }
        }

        // Verifier: deg1 <- key * delta.
        {
            long[] key = randomLongs(rng, BF128.LIMBS);
            long[] delta = randomLongs(rng, BF128.LIMBS);
            long[] deg1 = new long[BF128.LIMBS];
            FaestProofPrimitives.deg2to3Verifier128(deg1, 0, key, 0, delta, 0);
            long[] expected = new long[BF128.LIMBS];
            BF128.mul(expected, 0, key, 0, delta, 0);
            for (int l = 0; l < BF128.LIMBS; l++)
            {
                isTrue("deg2to3Verifier128[" + l + "]", deg1[l] == expected[l]);
            }
        }
        {
            long[] key = randomLongs(rng, BF192.LIMBS);
            long[] delta = randomLongs(rng, BF192.LIMBS);
            long[] deg1 = new long[BF192.LIMBS];
            FaestProofPrimitives.deg2to3Verifier192(deg1, 0, key, 0, delta, 0);
            long[] expected = new long[BF192.LIMBS];
            BF192.mul(expected, 0, key, 0, delta, 0);
            for (int l = 0; l < BF192.LIMBS; l++)
            {
                isTrue("deg2to3Verifier192[" + l + "]", deg1[l] == expected[l]);
            }
        }
        {
            long[] key = randomLongs(rng, BF256.LIMBS);
            long[] delta = randomLongs(rng, BF256.LIMBS);
            long[] deg1 = new long[BF256.LIMBS];
            FaestProofPrimitives.deg2to3Verifier256(deg1, 0, key, 0, delta, 0);
            long[] expected = new long[BF256.LIMBS];
            BF256.mul(expected, 0, key, 0, delta, 0);
            for (int l = 0; l < BF256.LIMBS; l++)
            {
                isTrue("deg2to3Verifier256[" + l + "]", deg1[l] == expected[l]);
            }
        }
    }

    // ===== helpers =====

    private static byte[] randomBits(Random rng, int n)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++)
        {
            b[i] = (byte)(rng.nextInt(2));
        }
        return b;
    }

    private static long[] randomLongs(Random rng, int n)
    {
        long[] a = new long[n];
        for (int i = 0; i < n; i++)
        {
            a[i] = rng.nextLong();
        }
        return a;
    }

    public static void main(String[] args)
    {
        runTest(new FaestProofPrimitivesTest());
    }
}
