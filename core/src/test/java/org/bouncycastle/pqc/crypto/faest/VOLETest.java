package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Round-trip test for the VOLE primitive. With {@code iDelta = [0, 0, ..., 0]}
 * the verifier never XOR-masks {@code c} into {@code q}, and the right-child
 * cascade in {@code ConvertToVole} is unaffected by the absence of seed 0,
 * so the resulting {@code q} matrix must equal the prover-side {@code v}
 * matrix bit-for-bit. The BAVC root hash {@code com} must also match.
 * <p>
 * Coverage limited here to small &lambda;=128 parameter sets for speed; the
 * full coverage check (with random {@code iDelta}) lands in the end-to-end
 * KAT runner.
 */
public class VOLETest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestVOLE";
    }

    public void performTest()
        throws Exception
    {
        zero_idelta_round_trip(FaestParameters.faest_128f, "faest_128f");
        zero_idelta_round_trip(FaestParameters.faest_em_128f, "faest_em_128f");
    }

    private void zero_idelta_round_trip(FaestParameters params, String label)
    {
        final int lambda = params.getLambda();
        final int lambdaBytes = params.getLambdaBytes();
        // ell_hat is what faest.c uses: ell + 3*lambda + UNIVERSAL_HASH_B*8 bits.
        final int ellhat = params.getEll() + 3 * lambda + 8 * FaestParameters.UNIVERSAL_HASH_B;
        final int ellhatBytes = (ellhat + 7) >>> 3;

        SecureRandom rng = fixedSeed(label + "-vole");
        byte[] rootKey = new byte[lambdaBytes]; rng.nextBytes(rootKey);
        byte[] iv = new byte[FaestParameters.IV_SIZE]; rng.nextBytes(iv);

        VOLE.Commit commit = VOLE.commit(rootKey, iv, ellhat, params);

        // Dimensions match expectations.
        isEquals(label + ": u length", ellhatBytes, commit.u.length);
        isEquals(label + ": v row count", lambda, commit.v.length);
        isEquals(label + ": v row width", ellhatBytes, commit.v[0].length);
        isEquals(label + ": c length",
            (params.getTau() - 1) * ellhatBytes, commit.c.length);

        // Build the all-zero iDelta and the BAVC decommitment that goes with it.
        int[] iDelta = new int[params.getTau()];
        byte[] decom = BAVC.open(commit.bavc, iDelta, params);
        isTrue(label + ": BAVC open succeeds with zero iDelta", decom != null);

        VOLE.Reconstruct rec = VOLE.reconstruct(decom, iDelta, iv, commit.c, ellhat, params);
        isTrue(label + ": VOLE reconstruct succeeds", rec != null);

        // com must equal the BAVC root hash.
        isTrue(label + ": com == bavc.h", Arrays.areEqual(rec.com, commit.bavc.h));

        // q == v row-by-row (no masking applied when iDelta = 0).
        isEquals(label + ": q row count", lambda, rec.q.length);
        for (int r = 0; r < lambda; r++)
        {
            if (!Arrays.areEqual(rec.q[r], commit.v[r]))
            {
                fail(label + ": q[" + r + "] != v[" + r + "]");
            }
        }
    }

    // ----- helpers -----

    private static SecureRandom fixedSeed(final String label)
    {
        return new SecureRandom()
        {
            private long state = seedFromLabel(label);

            @Override
            public void nextBytes(byte[] bytes)
            {
                for (int i = 0; i < bytes.length; i++)
                {
                    state ^= state << 13;
                    state ^= state >>> 7;
                    state ^= state << 17;
                    bytes[i] = (byte)state;
                }
            }
        };
    }

    private static long seedFromLabel(String label)
    {
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < label.length(); i++)
        {
            h ^= label.charAt(i);
            h *= 0x100000001b3L;
        }
        return h == 0L ? 1L : h;
    }

    public static void main(String[] args)
    {
        runTest(new VOLETest());
    }
}
