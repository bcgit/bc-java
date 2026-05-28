package org.bouncycastle.pqc.crypto.test;

import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Deterministic single-vector HQC probe used as the per-edit byte-identity gate
 * and as the steady-state driver for JFR profiling.
 *
 * Usage:
 *   java ... HQCKatProbe                 # one keygen+encap+decap per param set
 *   java ... HQCKatProbe all 60          # 60 iterations per param set, prints ms/iter at steady state
 *   java ... HQCKatProbe hqc-128 100     # 100 iterations of HQC-128 only
 */
public class HQCKatProbe
{
    private static final byte[] FIXED_SEED = new byte[48];
    static
    {
        for (int i = 0; i < FIXED_SEED.length; i++)
        {
            FIXED_SEED[i] = (byte)i;
        }
    }

    private static final HQCParameters[] ALL = new HQCParameters[]{
        HQCParameters.hqc128,
        HQCParameters.hqc192,
        HQCParameters.hqc256
    };

    public static void main(String[] args)
        throws Exception
    {
        String which = (args.length >= 1) ? args[0] : "all";
        int iters = (args.length >= 2) ? Integer.parseInt(args[1]) : 1;

        for (HQCParameters p : ALL)
        {
            if (!"all".equals(which) && !p.getName().equals(which))
            {
                continue;
            }
            runOne(p, iters);
        }
    }

    private static void runOne(HQCParameters parameters, int iters)
        throws Exception
    {
        String baseline = null;
        long[] iterNanos = new long[iters];

        for (int it = 0; it < iters; it++)
        {
            long t0 = System.nanoTime();

            SecureRandom kgRandom = new Shake256SecureRandom(FIXED_SEED);
            HQCKeyPairGenerator kpg = new HQCKeyPairGenerator();
            kpg.init(new HQCKeyGenerationParameters(kgRandom, parameters));
            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

            byte[] pk = ((HQCPublicKeyParameters)kp.getPublic()).getPublicKey();
            byte[] sk = ((HQCPrivateKeyParameters)kp.getPrivate()).getPrivateKey();

            SecureRandom encRandom = new Shake256SecureRandom(FIXED_SEED);
            HQCKEMGenerator gen = new HQCKEMGenerator(encRandom);
            SecretWithEncapsulation se = gen.generateEncapsulated(kp.getPublic());
            byte[] ct = se.getEncapsulation();
            byte[] ssEnc = se.getSecret();

            HQCKEMExtractor ext = new HQCKEMExtractor((HQCPrivateKeyParameters)kp.getPrivate());
            byte[] ssDec = ext.extractSecret(ct);

            if (!Arrays.areEqual(ssEnc, ssDec))
            {
                throw new IllegalStateException(parameters.getName() + ": encap/decap shared secret mismatch");
            }

            String hash = sha256OfAll(pk, sk, ct, ssEnc);
            if (baseline == null)
            {
                baseline = hash;
            }
            else if (!baseline.equals(hash))
            {
                throw new IllegalStateException(parameters.getName()
                    + ": non-deterministic probe output (iter " + it + ")");
            }

            iterNanos[it] = System.nanoTime() - t0;
        }

        System.out.println(parameters.getName() + " sha256(pk||sk||ct||ss) = " + baseline);

        if (iters > 1)
        {
            int skip = Math.max(1, iters / 5);
            long sum = 0;
            int n = 0;
            for (int i = skip; i < iters; i++)
            {
                sum += iterNanos[i];
                n++;
            }
            double msPerIter = (sum / (double)n) / 1_000_000.0;
            System.out.printf("%s: %d iters, steady-state %.2f ms/iter (skipped first %d for warmup)%n",
                parameters.getName(), iters, msPerIter, skip);
        }
    }

    private static String sha256OfAll(byte[]... parts)
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] p : parts)
        {
            md.update(p);
        }
        return Hex.toHexString(md.digest());
    }

    private static class Shake256SecureRandom
        extends SecureRandom
    {
        private final SHAKEDigest xof = new SHAKEDigest(256);

        Shake256SecureRandom(byte[] seed)
        {
            xof.update(seed, 0, seed.length);
            xof.update((byte)0);
        }

        public void nextBytes(byte[] bytes)
        {
            xof.doOutput(bytes, 0, bytes.length);
        }
    }
}
