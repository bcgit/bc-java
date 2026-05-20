package org.bouncycastle.pqc.crypto.faest;

import java.util.Random;

import org.bouncycastle.util.test.SimpleTest;

/**
 * Prover/verifier polynomial-consistency tests for {@link FaestAESConstraints}.
 * <p>
 * Each entry of the constraint polynomial is degree-3 in {@code delta}:
 *   {@code P_i(delta) = z_deg0[i] + z_deg1[i]*delta + z_deg2[i]*delta^2 + (residual)*delta^3}.
 * For a valid witness the residual vanishes; for a random witness it may not, so the
 * verifier evaluation at arbitrary delta cannot be directly compared to the prover
 * output. We use {@code delta = 0}, where the residual contribution drops out and
 * {@code zKey[i] == zDeg0[i]} for every entry.
 */
public class FaestAESConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestAESConstraints";
    }

    public void performTest()
        throws Exception
    {
        runOrchestratorAtDeltaZero128(FaestParameters.faest_128s);
        runOrchestratorAtDeltaZero128(FaestParameters.faest_em_128s);
        runOrchestratorAtDeltaZero192(FaestParameters.faest_192s);
        runOrchestratorAtDeltaZero192(FaestParameters.faest_em_192s);
        runOrchestratorAtDeltaZero256(FaestParameters.faest_256s);
        runOrchestratorAtDeltaZero256(FaestParameters.faest_em_256s);
    }

    private void runOrchestratorAtDeltaZero128(FaestParameters p)
    {
        Random rng = new Random(0xE0L);
        int ell = p.getEll();
        int blocksize = 32 * p.getNst();
        int beta = (p.getLambda() + blocksize - 1) / blocksize;
        int totalConstraints = 1 + 2 * p.getSke() + beta * (3 * p.getSenc() / 2);

        byte[] w = randomBits(rng, ell);
        long[] wTag = randomLongs(rng, ell * BF128.LIMBS);

        byte[] owfIn = new byte[p.getOwfInputSize()];
        rng.nextBytes(owfIn);
        byte[] owfOut = new byte[p.getOwfOutputSize()];
        rng.nextBytes(owfOut);

        long[] zDeg0 = new long[totalConstraints * BF128.LIMBS];
        long[] zDeg1 = new long[totalConstraints * BF128.LIMBS];
        long[] zDeg2 = new long[totalConstraints * BF128.LIMBS];
        FaestAESConstraints.constraintsProver128(zDeg0, zDeg1, zDeg2,
            w, wTag, owfIn, owfOut, p);

        long[] delta = new long[BF128.LIMBS]; // zero
        long[] wKey = new long[ell * BF128.LIMBS];
        // wKey[i] = wTag[i] + w[i]*delta; at delta=0, wKey[i] = wTag[i].
        System.arraycopy(wTag, 0, wKey, 0, ell * BF128.LIMBS);

        long[] zKey = new long[totalConstraints * BF128.LIMBS];
        FaestAESConstraints.constraintsVerifier128(zKey, wKey, owfIn, owfOut, delta, p);

        // At delta=0, zKey[i] must equal zDeg0[i].
        for (int i = 0; i < totalConstraints; i++)
        {
            for (int l = 0; l < BF128.LIMBS; l++)
            {
                if (zKey[i * BF128.LIMBS + l] != zDeg0[i * BF128.LIMBS + l])
                {
                    fail("constraints128 " + p.getName() + " idx=" + i + " limb=" + l
                        + " key=0x" + Long.toHexString(zKey[i * BF128.LIMBS + l])
                        + " deg0=0x" + Long.toHexString(zDeg0[i * BF128.LIMBS + l]));
                }
            }
        }
    }

    private void runOrchestratorAtDeltaZero192(FaestParameters p)
    {
        Random rng = new Random(0xE1L);
        int ell = p.getEll();
        int blocksize = 32 * p.getNst();
        int beta = (p.getLambda() + blocksize - 1) / blocksize;
        int totalConstraints = 1 + 2 * p.getSke() + beta * (3 * p.getSenc() / 2);

        byte[] w = randomBits(rng, ell);
        long[] wTag = randomLongs(rng, ell * BF192.LIMBS);

        byte[] owfIn = new byte[p.getOwfInputSize()];
        rng.nextBytes(owfIn);
        byte[] owfOut = new byte[p.getOwfOutputSize()];
        rng.nextBytes(owfOut);

        long[] zDeg0 = new long[totalConstraints * BF192.LIMBS];
        long[] zDeg1 = new long[totalConstraints * BF192.LIMBS];
        long[] zDeg2 = new long[totalConstraints * BF192.LIMBS];
        FaestAESConstraints.constraintsProver192(zDeg0, zDeg1, zDeg2, w, wTag, owfIn, owfOut, p);

        long[] delta = new long[BF192.LIMBS];
        long[] wKey = new long[ell * BF192.LIMBS];
        System.arraycopy(wTag, 0, wKey, 0, ell * BF192.LIMBS);

        long[] zKey = new long[totalConstraints * BF192.LIMBS];
        FaestAESConstraints.constraintsVerifier192(zKey, wKey, owfIn, owfOut, delta, p);
        for (int i = 0; i < totalConstraints; i++)
        {
            for (int l = 0; l < BF192.LIMBS; l++)
            {
                if (zKey[i * BF192.LIMBS + l] != zDeg0[i * BF192.LIMBS + l])
                {
                    fail("constraints192 " + p.getName() + " idx=" + i + " limb=" + l);
                }
            }
        }
    }

    private void runOrchestratorAtDeltaZero256(FaestParameters p)
    {
        Random rng = new Random(0xE2L);
        int ell = p.getEll();
        int blocksize = 32 * p.getNst();
        int beta = (p.getLambda() + blocksize - 1) / blocksize;
        int totalConstraints = 1 + 2 * p.getSke() + beta * (3 * p.getSenc() / 2);

        byte[] w = randomBits(rng, ell);
        long[] wTag = randomLongs(rng, ell * BF256.LIMBS);

        byte[] owfIn = new byte[p.getOwfInputSize()];
        rng.nextBytes(owfIn);
        byte[] owfOut = new byte[p.getOwfOutputSize()];
        rng.nextBytes(owfOut);

        long[] zDeg0 = new long[totalConstraints * BF256.LIMBS];
        long[] zDeg1 = new long[totalConstraints * BF256.LIMBS];
        long[] zDeg2 = new long[totalConstraints * BF256.LIMBS];
        FaestAESConstraints.constraintsProver256(zDeg0, zDeg1, zDeg2, w, wTag, owfIn, owfOut, p);

        long[] delta = new long[BF256.LIMBS];
        long[] wKey = new long[ell * BF256.LIMBS];
        System.arraycopy(wTag, 0, wKey, 0, ell * BF256.LIMBS);

        long[] zKey = new long[totalConstraints * BF256.LIMBS];
        FaestAESConstraints.constraintsVerifier256(zKey, wKey, owfIn, owfOut, delta, p);
        for (int i = 0; i < totalConstraints; i++)
        {
            for (int l = 0; l < BF256.LIMBS; l++)
            {
                if (zKey[i * BF256.LIMBS + l] != zDeg0[i * BF256.LIMBS + l])
                {
                    fail("constraints256 " + p.getName() + " idx=" + i + " limb=" + l);
                }
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
        runTest(new FaestAESConstraintsTest());
    }
}
