package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Round-trip test for the BAVC primitive: {@code commit / open / reconstruct}
 * must yield identical root hashes for any valid challenge.
 * <p>
 * Verified for representative parameter sets that exercise both the FAEST
 * (3&lambda;-byte commitments via {@code leaf_hash}) and FAEST-EM
 * (2&lambda;-byte commitments via PRG-only) variants. Larger &lambda; sets
 * are skipped here for speed &mdash; the full-spectrum check lands in the
 * end-to-end KAT runner.
 */
public class BAVCTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestBAVC";
    }

    public void performTest()
        throws Exception
    {
        round_trip(FaestParameters.faest_128f, "faest_128f");
        round_trip(FaestParameters.faest_em_128f, "faest_em_128f");
        bad_decommitment_rejected();
    }

    private void round_trip(FaestParameters params, String label)
    {
        int lambdaBytes = params.getLambdaBytes();

        // Deterministic seed and IV per parameter set so test failures are
        // reproducible.
        SecureRandom rng = fixedSeed(label + "-input");
        byte[] rootKey = new byte[lambdaBytes];
        rng.nextBytes(rootKey);
        byte[] iv = new byte[FaestParameters.IV_SIZE];
        rng.nextBytes(iv);

        BAVC.Commitment vc = BAVC.commit(rootKey, iv, params);

        // Construct a valid iDelta: iDelta[i] = i (mod maxNodeIndex(i, tau1, k)).
        int[] iDelta = new int[params.getTau()];
        for (int i = 0; i < iDelta.length; i++)
        {
            int ni = BAVC.maxNodeIndex(i, params.getTau1(), params.getK());
            iDelta[i] = i % ni;
        }

        byte[] decom = BAVC.open(vc, iDelta, params);
        isTrue(label + ": open() must succeed", decom != null);

        BAVC.Reconstruction rec = BAVC.reconstruct(decom, iDelta, iv, params);
        isTrue(label + ": reconstruct() must succeed", rec != null);

        isTrue(label + ": reconstructed h matches commit h", Arrays.areEqual(vc.h, rec.h));

        // Sanity on output dimensions.
        isEquals(label + ": h length", 2 * lambdaBytes, vc.h.length);
        isEquals(label + ": com length",
            params.getL() * BAVC.comSize(params), vc.com.length);
        isEquals(label + ": sd length",
            params.getL() * lambdaBytes, vc.sd.length);
        isEquals(label + ": k length", lambdaBytes, vc.k.length);
        isEquals(label + ": rec.s length",
            (params.getL() - params.getTau()) * lambdaBytes, rec.s.length);
    }

    /**
     * Flip a byte inside the decommitment's zero-padded tail. {@code reconstruct}
     * is required to reject this as a malformed seed-tail (the only place the
     * padding-zero check fires).
     */
    private void bad_decommitment_rejected()
    {
        FaestParameters params = FaestParameters.faest_128f;
        int lambdaBytes = params.getLambdaBytes();

        SecureRandom rng = fixedSeed("bad-decom");
        byte[] rootKey = new byte[lambdaBytes];
        rng.nextBytes(rootKey);
        byte[] iv = new byte[FaestParameters.IV_SIZE];
        rng.nextBytes(iv);

        BAVC.Commitment vc = BAVC.commit(rootKey, iv, params);
        int[] iDelta = new int[params.getTau()];
        for (int i = 0; i < iDelta.length; i++)
        {
            iDelta[i] = i % BAVC.maxNodeIndex(i, params.getTau1(), params.getK());
        }

        byte[] decom = BAVC.open(vc, iDelta, params);
        isTrue("open() must succeed", decom != null);

        // Corrupt the last byte (which must be zero in the genuine decommitment).
        byte original = decom[decom.length - 1];
        decom[decom.length - 1] = (byte)(original ^ 0x80);

        BAVC.Reconstruction rec = BAVC.reconstruct(decom, iDelta, iv, params);
        isTrue("reconstruct must reject non-zero tail padding", rec == null);

        // Restore and verify the round-trip still works after revert.
        decom[decom.length - 1] = original;
        BAVC.Reconstruction recOk = BAVC.reconstruct(decom, iDelta, iv, params);
        isTrue("reconstruct accepts restored decommitment", recOk != null);
        isTrue("restored decommitment yields original h",
            Arrays.areEqual(vc.h, recOk.h));
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
        runTest(new BAVCTest());
    }
}
