package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Structural and determinism tests for {@link AesWitnessExtension}.
 * <p>
 * Byte-level correctness against the reference is exercised by the end-to-end
 * {@code FaestKatTest}; here we cover the easily-verifiable invariants:
 * <ol>
 *   <li>Output length = {@code ell / 8} bytes for every parameter set.</li>
 *   <li>Output is deterministic for the same input.</li>
 *   <li>FAEST-mode first {@code lambda / 8} bytes match the input AES key.</li>
 *   <li>FAEST-EM-mode first {@code lambda / 8} bytes match the input secret key
 *       (because EM swaps key/input internally, but the witness records the
 *       <em>caller-supplied</em> {@code key} verbatim).</li>
 *   <li>Changing the key by one bit produces a different witness (avalanche
 *       sanity).</li>
 * </ol>
 */
public class AesWitnessExtensionTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestAesWitnessExtension";
    }

    public void performTest()
        throws Exception
    {
        // Cover all 12 parameter sets for length + determinism + avalanche.
        FaestParameters[] all = {
            FaestParameters.faest_128s, FaestParameters.faest_128f,
            FaestParameters.faest_192s, FaestParameters.faest_192f,
            FaestParameters.faest_256s, FaestParameters.faest_256f,
            FaestParameters.faest_em_128s, FaestParameters.faest_em_128f,
            FaestParameters.faest_em_192s, FaestParameters.faest_em_192f,
            FaestParameters.faest_em_256s, FaestParameters.faest_em_256f
        };

        for (FaestParameters p : all)
        {
            SecureRandom rng = fixedSeed(p.getName());
            byte[] key = new byte[p.getOwfOutputSize()];   // owfOutput size == key size (lambda/8)
            byte[] in  = new byte[p.getOwfInputSize()];
            rng.nextBytes(key);
            rng.nextBytes(in);

            byte[] w = AesWitnessExtension.extendWitness(key, in, p);
            isEquals(p.getName() + ": witness length", p.getEll() / 8, w.length);

            byte[] w2 = AesWitnessExtension.extendWitness(key, in, p);
            isTrue(p.getName() + ": deterministic", Arrays.areEqual(w, w2));

            // Front-of-witness check.
            //
            // FAEST mode: first lambda/8 bytes = the AES key (since the key-
            // schedule prefix opens with the original key columns).
            //
            // FAEST-EM mode: first lambda/8 bytes = the OWF secret key (the
            // `key` argument), per aes.c:486.
            int lambdaBytes = p.getLambda() / 8;
            byte[] frontExpected = new byte[lambdaBytes];
            System.arraycopy(key, 0, frontExpected, 0, lambdaBytes);
            byte[] frontGot = new byte[lambdaBytes];
            System.arraycopy(w, 0, frontGot, 0, lambdaBytes);
            isTrue(p.getName() + ": front-of-witness == key",
                Arrays.areEqual(frontExpected, frontGot));

            // Avalanche: flipping one bit of `key` must change the witness.
            byte[] keyMut = key.clone();
            keyMut[0] = (byte)(keyMut[0] ^ 0x01);
            byte[] wMut = AesWitnessExtension.extendWitness(keyMut, in, p);
            isTrue(p.getName() + ": flipping key changes witness",
                !Arrays.areEqual(w, wMut));
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
        runTest(new AesWitnessExtensionTest());
    }
}
