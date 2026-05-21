package org.bouncycastle.pqc.crypto.faest;

import java.util.Random;

import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for {@link FaestProof} — the top-level FAEST AES prover/verifier.
 * <ul>
 *   <li>{@code dbl} algebraic: dbl(0)=0, dbl(1)=2, dbl(top-bit) = MODULUS.</li>
 *   <li>{@code sumPoly} with simple unit vectors.</li>
 *   <li>{@code columnToRowMajorAndShrinkV} reshape correctness.</li>
 *   <li>End-to-end {@code aesProve}/{@code aesVerify} consistency at {@code delta=0}.</li>
 * </ul>
 */
public class FaestProofTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestProof";
    }

    public void performTest()
        throws Exception
    {
        dblAlgebra();
        sumPolyUnitVectors();
        columnToRowMajor();
        proveVerifyConsistency128();
        proveVerifyConsistency192();
        proveVerifyConsistency256();
    }

    private void dblAlgebra()
    {
        // BF128: dbl(1) = x (= field element 2 in the low limb).
        long[] one = new long[BF128.LIMBS]; BF128.one(one, 0);
        long[] r = new long[BF128.LIMBS];
        BF128.dbl(r, 0, one, 0);
        isTrue("BF128 dbl(1) low limb = 2", r[0] == 2L);
        isTrue("BF128 dbl(1) high limb = 0", r[1] == 0L);

        // dbl(top-bit) = MODULUS (when the top bit was set, the shift overflows
        // and folds in MODULUS).
        long[] topBit = new long[]{0L, 1L << 63};
        BF128.dbl(r, 0, topBit, 0);
        isTrue("BF128 dbl(x^127) low limb = MODULUS", r[0] == BF128.MODULUS);
        isTrue("BF128 dbl(x^127) high limb = 0", r[1] == 0L);

        // Same checks for BF192 and BF256.
        long[] one192 = new long[BF192.LIMBS]; BF192.one(one192, 0);
        long[] r192 = new long[BF192.LIMBS];
        BF192.dbl(r192, 0, one192, 0);
        isTrue("BF192 dbl(1) = 2", r192[0] == 2L && r192[1] == 0L && r192[2] == 0L);

        long[] one256 = new long[BF256.LIMBS]; BF256.one(one256, 0);
        long[] r256 = new long[BF256.LIMBS];
        BF256.dbl(r256, 0, one256, 0);
        isTrue("BF256 dbl(1) = 2", r256[0] == 2L && r256[1] == 0L && r256[2] == 0L && r256[3] == 0L);
    }

    private void sumPolyUnitVectors()
    {
        // sum_poly with xs[lambda-1] = 1, others 0:
        //   ret = xs[lambda-1] = 1
        //   then dbl applied (lambda-1) times → x^(lambda-1)
        long[] xs128 = new long[128 * BF128.LIMBS];
        long[] one = new long[BF128.LIMBS]; BF128.one(one, 0);
        System.arraycopy(one, 0, xs128, (128 - 1) * BF128.LIMBS, BF128.LIMBS);
        long[] r = new long[BF128.LIMBS];
        BF128.sumPoly(r, 0, xs128, 0);
        // After (lambda-1) dbl steps from 1, we expect bit 127 set (assuming no
        // overflow during the run — for lambda=128 the high bit is reached exactly
        // at i=127 doublings; no wraparound).
        isTrue("BF128 sumPoly([0..0,1]) low=0", r[0] == 0L);
        isTrue("BF128 sumPoly([0..0,1]) high bit 127 set", r[1] == (1L << 63));

        // sum_poly with xs[0] = 1, others 0:
        //   ret = xs[lambda-1] = 0
        //   iterations: ret = dbl(0) + xs[lambda-1-i] = xs[lambda-1-i]
        //   final iter (i = lambda-1): ret = xs[0] = 1
        java.util.Arrays.fill(xs128, 0L);
        System.arraycopy(one, 0, xs128, 0, BF128.LIMBS);
        BF128.sumPoly(r, 0, xs128, 0);
        isTrue("BF128 sumPoly([1,0..0]) low=1", r[0] == 1L && r[1] == 0L);
    }

    private void columnToRowMajor()
    {
        // Synthetic: lambda=128, ell=4. Build V where column c has bit i = (i+c) & 1.
        int ell = 4;
        int rows = ell + 2 * 128;
        int rowBytes = (rows + 7) / 8;
        byte[][] V = new byte[128][rowBytes];
        for (int col = 0; col < 128; col++)
        {
            for (int i = 0; i < rows; i++)
            {
                int bit = (i + col) & 1;
                V[col][i >> 3] |= (byte)(bit << (i & 7));
            }
        }
        long[] out = new long[rows * BF128.LIMBS];
        FaestProof.columnToRowMajorAndShrinkV128(out, V, ell);

        // For row 0: bit col of result = bit 0 of V[col] = (0 + col) & 1 = col & 1.
        // So row 0 = 0xAAAA...AA pattern (every other bit set).
        long expectedLo = 0xAAAAAAAAAAAAAAAAL;
        long expectedHi = 0xAAAAAAAAAAAAAAAAL;
        isTrue("row 0 low", out[0] == expectedLo);
        isTrue("row 0 high", out[1] == expectedHi);

        // For row 1: bit col = (1 + col) & 1 = 1 if col is even, 0 if odd. So pattern 0x5555...
        isTrue("row 1 low", out[BF128.LIMBS] == 0x5555555555555555L);
        isTrue("row 1 high", out[BF128.LIMBS + 1] == 0x5555555555555555L);
    }

    // ----- end-to-end consistency at delta=0 -----

    private void proveVerifyConsistency128()
    {
        FaestParameters p = FaestParameters.faest_128s;
        Random rng = new Random(0xF0L);
        runProveVerifyAtDeltaZero128(p, rng);
        runProveVerifyAtDeltaZero128(FaestParameters.faest_em_128s, new Random(0xF1L));
    }

    private void runProveVerifyAtDeltaZero128(FaestParameters p, Random rng)
    {
        int lambda = p.getLambda();
        int ell = p.getEll();
        int rows = ell + 2 * lambda;
        int rowBytes = (rows + 7) / 8;

        byte[] wBits = randomBits(rng, ell);
        byte[] uBits = randomBits(rng, 2 * lambda);
        byte[][] V = new byte[lambda][rowBytes];
        for (int col = 0; col < lambda; col++)
        {
            rng.nextBytes(V[col]);
        }

        byte[] owfIn = new byte[p.getOwfInputSize()];
        rng.nextBytes(owfIn);
        byte[] owfOut = new byte[p.getOwfOutputSize()];
        rng.nextBytes(owfOut);

        byte[] chall2 = new byte[5 * lambda / 8];
        rng.nextBytes(chall2);

        byte[] a0 = new byte[BF128.BYTES];
        byte[] a1 = new byte[BF128.BYTES];
        byte[] a2 = new byte[BF128.BYTES];
        FaestProof.aesProve(a0, a1, a2, wBits, uBits, V, owfIn, owfOut, chall2, p);

        // Verifier at delta=0: Q = V (no XOR with delta), and any d_bits works.
        byte[] chall3 = new byte[BF128.BYTES];
        byte[] dBits = new byte[ell];
        for (int i = 0; i < ell; i++)
        {
            dBits[i] = (byte)((uBits[i % (2 * lambda)] ^ wBits[i]) & 1);
        }

        byte[] a0Check = FaestProof.aesVerify(dBits, V, chall2, chall3, a1, a2, owfIn, owfOut, p);

        for (int i = 0; i < BF128.BYTES; i++)
        {
            if (a0[i] != a0Check[i])
            {
                fail("aesProve/aesVerify 128 " + p.getName() + " mismatch at byte " + i);
            }
        }
    }

    private void proveVerifyConsistency192()
    {
        Random rng = new Random(0xF2L);
        runProveVerifyAtDeltaZero192(FaestParameters.faest_192s, rng);
        runProveVerifyAtDeltaZero192(FaestParameters.faest_em_192s, new Random(0xF3L));
    }

    private void runProveVerifyAtDeltaZero192(FaestParameters p, Random rng)
    {
        int lambda = p.getLambda();
        int ell = p.getEll();
        int rows = ell + 2 * lambda;
        int rowBytes = (rows + 7) / 8;
        byte[] wBits = randomBits(rng, ell);
        byte[] uBits = randomBits(rng, 2 * lambda);
        byte[][] V = new byte[lambda][rowBytes];
        for (int col = 0; col < lambda; col++)
        {
            rng.nextBytes(V[col]);
        }
        byte[] owfIn = new byte[p.getOwfInputSize()]; rng.nextBytes(owfIn);
        byte[] owfOut = new byte[p.getOwfOutputSize()]; rng.nextBytes(owfOut);
        byte[] chall2 = new byte[5 * lambda / 8]; rng.nextBytes(chall2);

        byte[] a0 = new byte[BF192.BYTES];
        byte[] a1 = new byte[BF192.BYTES];
        byte[] a2 = new byte[BF192.BYTES];
        FaestProof.aesProve(a0, a1, a2, wBits, uBits, V, owfIn, owfOut, chall2, p);

        byte[] chall3 = new byte[BF192.BYTES];
        byte[] dBits = new byte[ell];
        for (int i = 0; i < ell; i++)
        {
            dBits[i] = (byte)((uBits[i % (2 * lambda)] ^ wBits[i]) & 1);
        }
        byte[] a0Check = FaestProof.aesVerify(dBits, V, chall2, chall3, a1, a2, owfIn, owfOut, p);

        for (int i = 0; i < BF192.BYTES; i++)
        {
            if (a0[i] != a0Check[i])
            {
                fail("aesProve/aesVerify 192 " + p.getName() + " mismatch at byte " + i);
            }
        }
    }

    private void proveVerifyConsistency256()
    {
        Random rng = new Random(0xF4L);
        runProveVerifyAtDeltaZero256(FaestParameters.faest_256s, rng);
        runProveVerifyAtDeltaZero256(FaestParameters.faest_em_256s, new Random(0xF5L));
    }

    private void runProveVerifyAtDeltaZero256(FaestParameters p, Random rng)
    {
        int lambda = p.getLambda();
        int ell = p.getEll();
        int rows = ell + 2 * lambda;
        int rowBytes = (rows + 7) / 8;
        byte[] wBits = randomBits(rng, ell);
        byte[] uBits = randomBits(rng, 2 * lambda);
        byte[][] V = new byte[lambda][rowBytes];
        for (int col = 0; col < lambda; col++)
        {
            rng.nextBytes(V[col]);
        }
        byte[] owfIn = new byte[p.getOwfInputSize()]; rng.nextBytes(owfIn);
        byte[] owfOut = new byte[p.getOwfOutputSize()]; rng.nextBytes(owfOut);
        byte[] chall2 = new byte[5 * lambda / 8]; rng.nextBytes(chall2);

        byte[] a0 = new byte[BF256.BYTES];
        byte[] a1 = new byte[BF256.BYTES];
        byte[] a2 = new byte[BF256.BYTES];
        FaestProof.aesProve(a0, a1, a2, wBits, uBits, V, owfIn, owfOut, chall2, p);

        byte[] chall3 = new byte[BF256.BYTES];
        byte[] dBits = new byte[ell];
        for (int i = 0; i < ell; i++)
        {
            dBits[i] = (byte)((uBits[i % (2 * lambda)] ^ wBits[i]) & 1);
        }
        byte[] a0Check = FaestProof.aesVerify(dBits, V, chall2, chall3, a1, a2, owfIn, owfOut, p);

        for (int i = 0; i < BF256.BYTES; i++)
        {
            if (a0[i] != a0Check[i])
            {
                fail("aesProve/aesVerify 256 " + p.getName() + " mismatch at byte " + i);
            }
        }
    }

    private static byte[] randomBits(Random rng, int n)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++)
        {
            b[i] = (byte)rng.nextInt(2);
        }
        return b;
    }

    public static void main(String[] args)
    {
        runTest(new FaestProofTest());
    }
}
