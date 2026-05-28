package org.bouncycastle.pqc.crypto.hqc;

import java.util.Random;

/**
 * Oracle test for {@link GF2x#sparseMul} vs the existing dense {@link GF2x#mul}.
 *
 * Standalone main() for fast iteration; not part of the JUnit suite.
 *
 * Compares the sparse path against the dense path for the three HQC moduli
 * (n = 17669 / 35851 / 57637) over many random low-weight supports and a battery
 * of edge cases: weight=1, support spanning the n-boundary, partialBits region, etc.
 */
public class GF2xSparseMulOracleTest
{
    public static void main(String[] args)
    {
        int seed = (args.length >= 1) ? Integer.parseInt(args[0]) : 0xC0FFEE;
        int trialsPerN = (args.length >= 2) ? Integer.parseInt(args[1]) : 50;

        int[] ns = { 17669, 35851, 57637 }; // hqc-128 / hqc-192 / hqc-256
        int[] weights = { 66, 100, 131 };

        long failures = 0;
        for (int idx = 0; idx < ns.length; ++idx)
        {
            int n = ns[idx];
            int w = weights[idx];
            Random rng = new Random((long)seed * 1000003L + idx);
            failures += runOne(n, w, rng, trialsPerN);
            failures += edgeCases(n, w);
        }

        if (failures != 0)
        {
            throw new IllegalStateException("oracle mismatches: " + failures);
        }
        System.out.println("GF2xSparseMulOracleTest: all good");
    }

    private static long runOne(int n, int w, Random rng, int trials)
    {
        GF2x gf2x = new GF2x(n);
        int size = sizeWords(n);
        long mismatches = 0;

        for (int t = 0; t < trials; ++t)
        {
            long[] dense = randomDense(rng, size, n);
            int[] support = randomSupport(rng, n, w);

            long[] denseSparse = new long[size];
            writeSupportToDense(denseSparse, support, w);

            long[] z1 = new long[size];
            long[] z2 = new long[size];
            gf2x.mul(denseSparse, dense, z1);
            gf2x.sparseMul(support, w, dense, z2);

            if (!equals(z1, z2))
            {
                System.err.println("n=" + n + " trial " + t + ": MISMATCH; weight=" + w
                    + " first-diff word " + firstDiff(z1, z2));
                mismatches++;
            }
        }
        return mismatches;
    }

    private static long edgeCases(int n, int wMax)
    {
        GF2x gf2x = new GF2x(n);
        int size = sizeWords(n);
        long mismatches = 0;

        // case 1: weight = 1 across every cardinal index (0, n-1, 63, 64, n-2, ...)
        int[] singles = {
            0, 1, 63, 64, 65, 127, 128, 191, 192,
            n / 4, n / 2, 3 * n / 4,
            n - 1, n - 2, n - 64, n - 65,
            // straddle the partial-top-word boundary
            n - (n & 63) - 1, n - (n & 63), n - (n & 63) + 1
        };
        Random det = new Random(1234567L * n);
        long[] dense = randomDense(det, size, n);
        for (int s : singles)
        {
            if (s < 0 || s >= n) continue;

            long[] denseSparse = new long[size];
            int[] support = new int[] { s };
            writeSupportToDense(denseSparse, support, 1);

            long[] z1 = new long[size];
            long[] z2 = new long[size];
            gf2x.mul(denseSparse, dense, z1);
            gf2x.sparseMul(support, 1, dense, z2);

            if (!equals(z1, z2))
            {
                System.err.println("n=" + n + " weight=1 s=" + s + ": MISMATCH; first-diff word " + firstDiff(z1, z2));
                mismatches++;
            }
        }

        // case 2: weight = 0 (must produce zero output)
        long[] z = new long[size];
        gf2x.sparseMul(new int[0], 0, dense, z);
        for (int i = 0; i < size; i++)
        {
            if (z[i] != 0L)
            {
                System.err.println("n=" + n + " weight=0: output non-zero at word " + i);
                mismatches++;
                break;
            }
        }

        // case 3: weight = wMax with support clustered around the n-boundary
        int[] supportTop = new int[wMax];
        for (int i = 0; i < wMax; i++)
        {
            supportTop[i] = (n - wMax) + i;
        }
        long[] denseTop = new long[size];
        writeSupportToDense(denseTop, supportTop, wMax);
        long[] zTop1 = new long[size];
        long[] zTop2 = new long[size];
        gf2x.mul(denseTop, dense, zTop1);
        gf2x.sparseMul(supportTop, wMax, dense, zTop2);
        if (!equals(zTop1, zTop2))
        {
            System.err.println("n=" + n + " support-near-n boundary: MISMATCH; first-diff word " + firstDiff(zTop1, zTop2));
            mismatches++;
        }

        // case 4: dense = single bit
        for (int singleBit : new int[]{0, 1, 63, 64, n - 1, n / 2})
        {
            if (singleBit < 0 || singleBit >= n) continue;
            long[] denseSingle = new long[size];
            denseSingle[singleBit >>> 6] = 1L << (singleBit & 63);
            int[] supp = randomSupport(det, n, Math.min(wMax, 5));
            int wLocal = Math.min(wMax, 5);

            long[] denseSparse = new long[size];
            writeSupportToDense(denseSparse, supp, wLocal);
            long[] z1 = new long[size];
            long[] z2 = new long[size];
            gf2x.mul(denseSparse, denseSingle, z1);
            gf2x.sparseMul(supp, wLocal, denseSingle, z2);
            if (!equals(z1, z2))
            {
                System.err.println("n=" + n + " dense=X^" + singleBit + ": MISMATCH");
                mismatches++;
            }
        }

        return mismatches;
    }

    private static int sizeWords(int n)
    {
        return (n + 63) >>> 6;
    }

    private static long[] randomDense(Random rng, int size, int n)
    {
        long[] r = new long[size];
        for (int i = 0; i < size; i++)
        {
            r[i] = rng.nextLong();
        }
        int partialBits = n & 63;
        if (partialBits != 0)
        {
            r[size - 1] &= (1L << partialBits) - 1L;
        }
        return r;
    }

    private static int[] randomSupport(Random rng, int n, int weight)
    {
        int[] support = new int[weight];
        boolean[] seen = new boolean[n];
        int picked = 0;
        while (picked < weight)
        {
            int idx = rng.nextInt(n);
            if (!seen[idx])
            {
                seen[idx] = true;
                support[picked++] = idx;
            }
        }
        return support;
    }

    private static void writeSupportToDense(long[] dense, int[] support, int weight)
    {
        for (int j = 0; j < weight; j++)
        {
            int s = support[j];
            dense[s >>> 6] |= 1L << (s & 63);
        }
    }

    private static boolean equals(long[] a, long[] b)
    {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    private static int firstDiff(long[] a, long[] b)
    {
        for (int i = 0; i < a.length; i++)
        {
            if (a[i] != b[i]) return i;
        }
        return -1;
    }
}
