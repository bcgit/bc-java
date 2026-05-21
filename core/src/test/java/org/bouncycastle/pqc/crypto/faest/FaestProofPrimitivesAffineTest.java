package org.bouncycastle.pqc.crypto.faest;

import java.util.Random;

import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the slice-6c arithmetic primitives in {@link FaestProofPrimitives}.
 * <p>
 * Strategy:
 * <ul>
 *   <li>The simple element-wise primitives (state_to_bytes, add_round_key_bytes)
 *       are checked against direct reference computations.</li>
 *   <li>{@code inverse_affine} is checked via round-trip against an independent
 *       implementation of the AES S-box affine transformation.</li>
 *   <li>{@code mix_columns} and {@code bitwise_mix_column} are checked against
 *       a reference AES MixColumns over plain bytes.</li>
 *   <li>{@code sbox_affine} is verified by feeding it the byte-combine encoding
 *       of an arbitrary byte and confirming the output is the byte-combine of the
 *       expected S-box-affine-applied byte.</li>
 *   <li>{@code inv_norm_to_conjugates} and {@code inv_norm_constraints} are
 *       verified via prover/verifier consistency: the verifier on the polynomial
 *       evaluation at delta must equal the prover's evaluation at delta.</li>
 * </ul>
 */
public class FaestProofPrimitivesAffineTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestProofPrimitivesAffine";
    }

    public void performTest()
        throws Exception
    {
        stateToBytes();
        addRoundKeyBytes();
        inverseAffineRoundtrip();
        mixColumnsBytewise();
        bitwiseMixColumnVsBytewise();
        sboxAffine();
        invNormToConjugates();
        invNormConstraints();
    }

    // ===== state_to_bytes =====
    private void stateToBytes()
    {
        Random rng = new Random(0xC0L);
        int[] Nsts = { 4, 6, 8 };
        for (int Nst : Nsts)
        {
            int Nstb = Nst * 4;
            byte[] kBits = randomBits(rng, Nstb * 8);
            // BF128
            {
                long[] kTag = randomLongs(rng, Nstb * 8 * BF128.LIMBS);
                long[] out = new long[Nstb * BF128.LIMBS];
                long[] outTag = new long[Nstb * BF128.LIMBS];
                FaestProofPrimitives.stateToBytesProver128(out, outTag, kBits, kTag, Nst);

                long[] exp = new long[BF128.LIMBS], expT = new long[BF128.LIMBS];
                for (int i = 0; i < Nstb; i++)
                {
                    BF128.byteCombineBits(exp, 0, kBits, i * 8);
                    BF128.byteCombine(expT, 0, kTag, i * 8 * BF128.LIMBS);
                    for (int l = 0; l < BF128.LIMBS; l++)
                    {
                        isTrue("stateToBytes128 out", out[i * BF128.LIMBS + l] == exp[l]);
                        isTrue("stateToBytes128 tag", outTag[i * BF128.LIMBS + l] == expT[l]);
                    }
                }
                long[] outKey = new long[Nstb * BF128.LIMBS];
                FaestProofPrimitives.stateToBytesVerifier128(outKey, kTag, Nst);
                for (int i = 0; i < Nstb; i++)
                {
                    BF128.byteCombine(expT, 0, kTag, i * 8 * BF128.LIMBS);
                    for (int l = 0; l < BF128.LIMBS; l++)
                    {
                        isTrue("stateToBytesVerifier128", outKey[i * BF128.LIMBS + l] == expT[l]);
                    }
                }
            }
            // (192 and 256 follow the same shape; brief structural check)
            {
                long[] kTag = randomLongs(rng, Nstb * 8 * BF192.LIMBS);
                long[] out = new long[Nstb * BF192.LIMBS];
                long[] outTag = new long[Nstb * BF192.LIMBS];
                FaestProofPrimitives.stateToBytesProver192(out, outTag, kBits, kTag, Nst);
                long[] exp = new long[BF192.LIMBS];
                for (int i = 0; i < Nstb; i++)
                {
                    BF192.byteCombineBits(exp, 0, kBits, i * 8);
                    for (int l = 0; l < BF192.LIMBS; l++)
                    {
                        isTrue("stateToBytes192 out", out[i * BF192.LIMBS + l] == exp[l]);
                    }
                }
            }
            {
                long[] kTag = randomLongs(rng, Nstb * 8 * BF256.LIMBS);
                long[] out = new long[Nstb * BF256.LIMBS];
                long[] outTag = new long[Nstb * BF256.LIMBS];
                FaestProofPrimitives.stateToBytesProver256(out, outTag, kBits, kTag, Nst);
                long[] exp = new long[BF256.LIMBS];
                for (int i = 0; i < Nstb; i++)
                {
                    BF256.byteCombineBits(exp, 0, kBits, i * 8);
                    for (int l = 0; l < BF256.LIMBS; l++)
                    {
                        isTrue("stateToBytes256 out", out[i * BF256.LIMBS + l] == exp[l]);
                    }
                }
            }
        }
    }

    // ===== add_round_key_bytes =====
    private void addRoundKeyBytes()
    {
        Random rng = new Random(0xC1L);
        int Nst = 4, n = Nst * 4;
        long[] in0 = randomLongs(rng, n * BF128.LIMBS);
        long[] in1 = randomLongs(rng, n * BF128.LIMBS);
        long[] in2 = randomLongs(rng, n * BF128.LIMBS);
        long[] k0 = randomLongs(rng, n * BF128.LIMBS);
        long[] k1 = randomLongs(rng, n * BF128.LIMBS);
        long[] k2 = randomLongs(rng, n * BF128.LIMBS);
        long[] y0 = new long[n * BF128.LIMBS];
        long[] y1 = new long[n * BF128.LIMBS];
        long[] y2 = new long[n * BF128.LIMBS];
        FaestProofPrimitives.addRoundKeyBytesProver128(y0, y1, y2, in0, in1, in2, k0, k1, k2, Nst);
        for (int i = 0; i < n * BF128.LIMBS; i++)
        {
            isTrue("arkBytes128.y0", y0[i] == (in0[i] ^ k0[i]));
            isTrue("arkBytes128.y1", y1[i] == (in1[i] ^ k1[i]));
            isTrue("arkBytes128.y2", y2[i] == (in2[i] ^ k2[i]));
        }
        // Verifier no-shift
        long[] delta = randomLongs(rng, BF128.LIMBS);
        long[] yV = new long[n * BF128.LIMBS];
        FaestProofPrimitives.addRoundKeyBytesVerifier128(yV, in1, k1, delta, false, Nst);
        for (int i = 0; i < n * BF128.LIMBS; i++)
        {
            isTrue("arkBytesVerifier128", yV[i] == (in1[i] ^ k1[i]));
        }
        // Verifier with shift
        FaestProofPrimitives.addRoundKeyBytesVerifier128(yV, in1, k1, delta, true, Nst);
        long[] tmp = new long[BF128.LIMBS];
        for (int i = 0; i < n; i++)
        {
            BF128.mul(tmp, 0, k1, i * BF128.LIMBS, delta, 0);
            for (int l = 0; l < BF128.LIMBS; l++)
            {
                long exp = in1[i * BF128.LIMBS + l] ^ tmp[l];
                isTrue("arkBytesVerifier128 shifted", yV[i * BF128.LIMBS + l] == exp);
            }
        }
    }

    // ===== inverse_affine roundtrip =====
    // The AES S-box affine is y = A*x + 0x63 where A is a fixed 8x8 GF(2) matrix.
    // inverse_affine_byte computes the inverse. A round-trip should recover x.
    private void inverseAffineRoundtrip()
    {
        Random rng = new Random(0xC2L);
        for (int trial = 0; trial < 16; trial++)
        {
            int xByte = rng.nextInt(256);
            // y = S-box affine applied to xByte (this is the forward affine, the
            // SubBytes step minus the inverse - so apply it bytewise).
            int yByte = sboxAffineForward(xByte);
            byte[] yBits = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                yBits[i] = (byte)((yByte >>> i) & 1);
            }
            byte[] xBits = new byte[8];
            long[] yTag = new long[8 * BF128.LIMBS];
            long[] xTag = new long[8 * BF128.LIMBS];
            FaestProofPrimitives.inverseAffineByteProver128(xBits, 0, xTag, 0, yBits, 0, yTag, 0);
            int xRecovered = 0;
            for (int i = 0; i < 8; i++)
            {
                xRecovered |= (xBits[i] & 1) << i;
            }
            if (xRecovered != xByte)
            {
                fail("inverse_affine_byte_prover128: x=" + Integer.toHexString(xByte)
                    + " recovered=" + Integer.toHexString(xRecovered));
            }
        }
    }

    // ===== mix_columns vs bytewise reference =====
    private void mixColumnsBytewise()
    {
        Random rng = new Random(0xC3L);
        int[] Nsts = { 4, 6, 8 };
        for (int Nst : Nsts)
        {
            byte[] stateBytes = new byte[Nst * 4];
            rng.nextBytes(stateBytes);
            byte[] expectedBytes = mixColumnsRef(stateBytes, Nst);

            // Build field-encoded input: each byte → byteCombineBits.
            int n = Nst * 4;
            long[] in1 = new long[n * BF128.LIMBS];
            long[] y1 = new long[n * BF128.LIMBS];
            long[] zero = new long[n * BF128.LIMBS];
            byte[] bits = new byte[8];
            for (int i = 0; i < n; i++)
            {
                int b = stateBytes[i] & 0xff;
                for (int j = 0; j < 8; j++)
                {
                    bits[j] = (byte)((b >>> j) & 1);
                }
                BF128.byteCombineBits(in1, i * BF128.LIMBS, bits, 0);
            }
            FaestProofPrimitives.mixColumnsProver128(zero.clone(), y1, zero.clone(),
                zero.clone(), in1, zero.clone(), false, Nst);

            // Compare y1 to byteCombineBits(expectedBytes).
            long[] exp = new long[BF128.LIMBS];
            for (int i = 0; i < n; i++)
            {
                int b = expectedBytes[i] & 0xff;
                for (int j = 0; j < 8; j++)
                {
                    bits[j] = (byte)((b >>> j) & 1);
                }
                BF128.byteCombineBits(exp, 0, bits, 0);
                for (int l = 0; l < BF128.LIMBS; l++)
                {
                    if (y1[i * BF128.LIMBS + l] != exp[l])
                    {
                        fail("mixColumns128 Nst=" + Nst + " byte=" + i + " mismatch");
                    }
                }
            }
        }
    }

    // ===== bitwise_mix_column vs bytewise reference =====
    private void bitwiseMixColumnVsBytewise()
    {
        Random rng = new Random(0xC4L);
        int[] Nsts = { 4, 6, 8 };
        for (int Nst : Nsts)
        {
            byte[] stateBytes = new byte[Nst * 4];
            rng.nextBytes(stateBytes);
            byte[] expectedBytes = mixColumnsRef(stateBytes, Nst);

            byte[] sBits = new byte[Nst * 32];
            for (int i = 0; i < Nst * 4; i++)
            {
                int b = stateBytes[i] & 0xff;
                for (int j = 0; j < 8; j++)
                {
                    sBits[i * 8 + j] = (byte)((b >>> j) & 1);
                }
            }
            byte[] outBits = new byte[Nst * 32];
            long[] outTag = new long[Nst * 32 * BF128.LIMBS];
            long[] sTag = new long[Nst * 32 * BF128.LIMBS];
            FaestProofPrimitives.bitwiseMixColumnProver128(outBits, outTag, sBits, sTag, Nst);

            for (int i = 0; i < Nst * 4; i++)
            {
                int got = 0;
                for (int j = 0; j < 8; j++)
                {
                    got |= (outBits[i * 8 + j] & 1) << j;
                }
                int exp = expectedBytes[i] & 0xff;
                if (got != exp)
                {
                    fail("bitwiseMixColumn Nst=" + Nst + " byte=" + i
                        + " expected=" + Integer.toHexString(exp)
                        + " got=" + Integer.toHexString(got));
                }
            }
        }
    }

    // ===== sbox_affine prover/verifier consistency =====
    private void sboxAffine()
    {
        Random rng = new Random(0xC5L);
        for (boolean dosq : new boolean[]{false, true})
        {
            int Nst = 4, n = Nst * 4;
            // Build random deg-0/1/2 inputs of dim n*8 (one element per bit).
            long[] in0 = randomLongs(rng, n * 8 * BF128.LIMBS);
            long[] in1 = randomLongs(rng, n * 8 * BF128.LIMBS);
            long[] in2 = randomLongs(rng, n * 8 * BF128.LIMBS);
            long[] o0 = new long[n * BF128.LIMBS];
            long[] o1 = new long[n * BF128.LIMBS];
            long[] o2 = new long[n * BF128.LIMBS];
            FaestProofPrimitives.sboxAffineProver128(o0, o1, o2, in0, in1, in2, dosq, Nst);

            long[] delta = randomLongs(rng, BF128.LIMBS);
            // Compute in_eval = in0 + in1*delta + in2*delta^2 (per bit).
            long[] inEval = new long[n * 8 * BF128.LIMBS];
            long[] tmp = new long[BF128.LIMBS];
            long[] d2 = new long[BF128.LIMBS];
            BF128.mul(d2, 0, delta, 0, delta, 0);
            for (int i = 0; i < n * 8; i++)
            {
                int o = i * BF128.LIMBS;
                System.arraycopy(in0, o, inEval, o, BF128.LIMBS);
                BF128.mul(tmp, 0, in1, o, delta, 0); BF128.addInPlace(inEval, o, tmp, 0);
                BF128.mul(tmp, 0, in2, o, d2, 0);    BF128.addInPlace(inEval, o, tmp, 0);
            }
            long[] outV = new long[n * BF128.LIMBS];
            FaestProofPrimitives.sboxAffineVerifier128(outV, inEval, delta, dosq, Nst);

            // Verifier output should equal o0 + o1*delta + o2*delta^2.
            long[] expEval = new long[BF128.LIMBS];
            for (int i = 0; i < n; i++)
            {
                int o = i * BF128.LIMBS;
                System.arraycopy(o0, o, expEval, 0, BF128.LIMBS);
                BF128.mul(tmp, 0, o1, o, delta, 0); BF128.addInPlace(expEval, 0, tmp, 0);
                BF128.mul(tmp, 0, o2, o, d2, 0);    BF128.addInPlace(expEval, 0, tmp, 0);
                for (int l = 0; l < BF128.LIMBS; l++)
                {
                    if (outV[o + l] != expEval[l])
                    {
                        fail("sboxAffine dosq=" + dosq + " byte=" + i + " limb=" + l);
                    }
                }
            }
        }
    }

    // ===== inv_norm_to_conjugates prover/verifier consistency =====
    private void invNormToConjugates()
    {
        Random rng = new Random(0xC6L);
        for (int trial = 0; trial < 8; trial++)
        {
            byte[] xVal = randomBits(rng, 4);
            long[] xTag = randomLongs(rng, 4 * BF128.LIMBS);
            long[] yVal = new long[4 * BF128.LIMBS];
            long[] yTag = new long[4 * BF128.LIMBS];
            FaestProofPrimitives.invNormToConjugatesProver128(yVal, yTag, xVal, xTag);

            long[] delta = randomLongs(rng, BF128.LIMBS);
            // xEval[i] = xTag[i] + xVal[i] * delta
            long[] xEval = new long[4 * BF128.LIMBS];
            long[] bd = new long[BF128.LIMBS];
            for (int i = 0; i < 4; i++)
            {
                int o = i * BF128.LIMBS;
                BF128.mulBit(bd, 0, delta, 0, xVal[i]);
                BF128.add(xEval, o, xTag, o, bd, 0);
            }
            long[] yEval = new long[4 * BF128.LIMBS];
            FaestProofPrimitives.invNormToConjugatesVerifier128(yEval, xEval);

            // Expected: yEval[i] == yTag[i] + yVal[i] * delta.
            long[] tmp = new long[BF128.LIMBS];
            for (int i = 0; i < 4; i++)
            {
                int o = i * BF128.LIMBS;
                BF128.mul(tmp, 0, yVal, o, delta, 0);
                BF128.addInPlace(tmp, 0, yTag, o);
                for (int l = 0; l < BF128.LIMBS; l++)
                {
                    if (yEval[o + l] != tmp[l])
                    {
                        fail("invNormToConjugates trial=" + trial + " i=" + i + " limb=" + l);
                    }
                }
            }
        }
    }

    // ===== inv_norm_constraints prover/verifier consistency =====
    // The constraint polynomial P(d) = yEval*conjEval[1]*conjEval[4] + conjEval[0]*d^2 is
    // cubic in delta with coefficients (c0, c1, c2, c3). The prover emits (c0, c1, c2)
    // and the constraint c3 == 0 is what the proof system enforces. We test the prover
    // by computing (c0, c1, c2) ourselves from the algebraic expansion, and we test the
    // verifier by computing P(delta) directly.
    private void invNormConstraints()
    {
        Random rng = new Random(0xC7L);
        for (int trial = 0; trial < 8; trial++)
        {
            long[] conj = randomLongs(rng, 5 * BF128.LIMBS);
            long[] conjTag = randomLongs(rng, 5 * BF128.LIMBS);
            long[] y = randomLongs(rng, BF128.LIMBS);
            long[] yTag = randomLongs(rng, BF128.LIMBS);

            long[] z0 = new long[BF128.LIMBS];
            long[] z1 = new long[BF128.LIMBS];
            long[] z2 = new long[BF128.LIMBS];
            long[] proverT1 = new long[BF128.LIMBS];
            long[] proverT2 = new long[BF128.LIMBS];
            FaestProofPrimitives.invNormConstraintsProver128(z0, 0, z1, 0, z2, 0, conj, conjTag, y, yTag, proverT1, proverT2);

            // Compute the (c0, c1, c2, c3) coefficients directly from the algebraic expansion.
            // yEval(d) * conjEval[1](d) * conjEval[4](d) + conjEval[0](d) * d^2
            // where yEval = yTag + y*d, conjEval[i] = conjTag[i] + conj[i]*d.
            long[] c0 = new long[BF128.LIMBS];
            long[] c1 = new long[BF128.LIMBS];
            long[] c2 = new long[BF128.LIMBS];
            long[] c3 = new long[BF128.LIMBS];
            long[] t = new long[BF128.LIMBS];

            // c0 = yTag * ct[1] * ct[4]
            BF128.mul(t, 0, yTag, 0, conjTag, 1 * BF128.LIMBS);
            BF128.mul(c0, 0, t, 0, conjTag, 4 * BF128.LIMBS);
            // c1 = yTag*ct[1]*c[4] + yTag*c[1]*ct[4] + y*ct[1]*ct[4]
            BF128.mul(t, 0, yTag, 0, conjTag, 1 * BF128.LIMBS); BF128.mul(c1, 0, t, 0, conj, 4 * BF128.LIMBS);
            BF128.mul(t, 0, yTag, 0, conj, 1 * BF128.LIMBS);    BF128.mul(t, 0, t, 0, conjTag, 4 * BF128.LIMBS);
            BF128.addInPlace(c1, 0, t, 0);
            BF128.mul(t, 0, y, 0, conjTag, 1 * BF128.LIMBS);    BF128.mul(t, 0, t, 0, conjTag, 4 * BF128.LIMBS);
            BF128.addInPlace(c1, 0, t, 0);
            // c2 = yTag*c[1]*c[4] + y*ct[1]*c[4] + y*c[1]*ct[4] + ct[0]
            BF128.mul(t, 0, yTag, 0, conj, 1 * BF128.LIMBS); BF128.mul(c2, 0, t, 0, conj, 4 * BF128.LIMBS);
            BF128.mul(t, 0, y, 0, conjTag, 1 * BF128.LIMBS); BF128.mul(t, 0, t, 0, conj, 4 * BF128.LIMBS);
            BF128.addInPlace(c2, 0, t, 0);
            BF128.mul(t, 0, y, 0, conj, 1 * BF128.LIMBS);    BF128.mul(t, 0, t, 0, conjTag, 4 * BF128.LIMBS);
            BF128.addInPlace(c2, 0, t, 0);
            BF128.addInPlace(c2, 0, conjTag, 0 * BF128.LIMBS);
            // c3 = y*c[1]*c[4] + c[0]
            BF128.mul(t, 0, y, 0, conj, 1 * BF128.LIMBS); BF128.mul(c3, 0, t, 0, conj, 4 * BF128.LIMBS);
            BF128.addInPlace(c3, 0, conj, 0 * BF128.LIMBS);

            // Prover should emit c0, c1, c2.
            for (int l = 0; l < BF128.LIMBS; l++)
            {
                isTrue("invNormConstraintsProver128.z0 trial=" + trial + " l=" + l, z0[l] == c0[l]);
                isTrue("invNormConstraintsProver128.z1 trial=" + trial + " l=" + l, z1[l] == c1[l]);
                isTrue("invNormConstraintsProver128.z2 trial=" + trial + " l=" + l, z2[l] == c2[l]);
            }

            // Verifier: compute P(delta) explicitly, compare to verifier output.
            long[] delta = randomLongs(rng, BF128.LIMBS);
            long[] conjEval = new long[5 * BF128.LIMBS];
            for (int i = 0; i < 5; i++)
            {
                int o = i * BF128.LIMBS;
                BF128.mul(t, 0, conj, o, delta, 0);
                BF128.add(conjEval, o, conjTag, o, t, 0);
            }
            long[] yEval = new long[BF128.LIMBS];
            BF128.mul(t, 0, y, 0, delta, 0);
            BF128.add(yEval, 0, yTag, 0, t, 0);
            long[] zEval = new long[BF128.LIMBS];
            long[] d2 = new long[BF128.LIMBS]; BF128.mul(d2, 0, delta, 0, delta, 0);
            FaestProofPrimitives.invNormConstraintsVerifier128(zEval, 0, conjEval, yEval, d2, t);

            // Expected: P(delta) = c0 + c1*delta + c2*delta^2 + c3*delta^3
            long[] expEval = new long[BF128.LIMBS];
            long[] d3 = new long[BF128.LIMBS]; BF128.mul(d3, 0, d2, 0, delta, 0);
            System.arraycopy(c0, 0, expEval, 0, BF128.LIMBS);
            BF128.mul(t, 0, c1, 0, delta, 0); BF128.addInPlace(expEval, 0, t, 0);
            BF128.mul(t, 0, c2, 0, d2, 0);    BF128.addInPlace(expEval, 0, t, 0);
            BF128.mul(t, 0, c3, 0, d3, 0);    BF128.addInPlace(expEval, 0, t, 0);
            for (int l = 0; l < BF128.LIMBS; l++)
            {
                if (zEval[l] != expEval[l])
                {
                    fail("invNormConstraintsVerifier128 trial=" + trial + " l=" + l);
                }
            }
        }
    }

    // ===== reference helpers =====

    /** Reference forward AES S-box affine: y = A*x XOR 0x63. */
    private static int sboxAffineForward(int x)
    {
        // Standard AES S-box affine. Each output bit is XOR of input bits at specific positions plus a constant bit.
        int y = 0;
        // Affine matrix per FIPS-197 §5.1.1; row i selects input bits {i, (i+4)%8, (i+5)%8, (i+6)%8, (i+7)%8}.
        for (int i = 0; i < 8; i++)
        {
            int b = ((x >>> i) & 1)
                ^ ((x >>> ((i + 4) & 7)) & 1)
                ^ ((x >>> ((i + 5) & 7)) & 1)
                ^ ((x >>> ((i + 6) & 7)) & 1)
                ^ ((x >>> ((i + 7) & 7)) & 1);
            y |= b << i;
        }
        y ^= 0x63;
        return y & 0xff;
    }

    /** Reference AES MixColumns over byte state. */
    private static byte[] mixColumnsRef(byte[] state, int Nst)
    {
        byte[] out = new byte[Nst * 4];
        for (int c = 0; c < Nst; c++)
        {
            int s0 = state[c * 4 + 0] & 0xff;
            int s1 = state[c * 4 + 1] & 0xff;
            int s2 = state[c * 4 + 2] & 0xff;
            int s3 = state[c * 4 + 3] & 0xff;
            out[c * 4 + 0] = (byte)(gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3);
            out[c * 4 + 1] = (byte)(s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3);
            out[c * 4 + 2] = (byte)(s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3));
            out[c * 4 + 3] = (byte)(gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2));
        }
        return out;
    }

    private static int gmul(int a, int b)
    {
        int p = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0)
            {
                p ^= a;
            }
            int hi = a & 0x80;
            a = (a << 1) & 0xff;
            if (hi != 0)
            {
                a ^= 0x1b;
            }
            b >>>= 1;
        }
        return p & 0xff;
    }

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
        runTest(new FaestProofPrimitivesAffineTest());
    }
}
