package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Algebraic-invariant tests for {@link UniversalHashing}.
 * <p>
 * No byte-level cross-checks against the reference here &mdash; those land in
 * the end-to-end KAT runner (FaestTest). What this test covers:
 * <ol>
 *   <li>zk_hash invariants: empty finalize returns x1; single-update case
 *       reduces to a closed-form expression; two-update case agrees with the
 *       hand-derived expansion.</li>
 *   <li>vole_hash on an all-zero witness produces all-zero output.</li>
 *   <li>leaf_hash matches a direct BF384/576/768.mul + add.</li>
 *   <li>The lambda-dispatched wrappers route to the right specialisation.</li>
 * </ol>
 */
public class UniversalHashingTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestUniversalHashing";
    }

    public void performTest()
        throws Exception
    {
        zk_hash_empty_finalize_returns_x1();
        zk_hash_single_update_matches_closed_form();
        zk_hash_two_updates_match_closed_form();
        vole_hash_zero_witness_is_all_zero();
        leaf_hash_matches_direct_mul();
        lambda_dispatch_routes_correctly();
    }

    // ===== zk_hash =====

    private void zk_hash_empty_finalize_returns_x1()
    {
        // sd: 4 BFλ-sized blocks (r0, r1, s, t) — only the first two are used
        // at finalize time, and we initialise h0=h1=0, so the result must be x1.
        SecureRandom rng = fixedSeed("zk-empty");

        byte[] sd128 = new byte[4 * BF128.BYTES]; rng.nextBytes(sd128);
        long[] x1_128 = new long[BF128.LIMBS]; randomLimbs(rng, x1_128, BF128.LIMBS);

        byte[] h = new byte[BF128.BYTES];
        new UniversalHashing.ZkHash128(sd128, 0).finalize(h, 0, x1_128, 0);

        byte[] expected = new byte[BF128.BYTES];
        BF128.store(expected, 0, x1_128, 0);
        isTrue("zk_hash_128 empty finalize == x1", Arrays.areEqual(h, expected));

        // same for 192
        byte[] sd192 = new byte[4 * BF192.BYTES]; rng.nextBytes(sd192);
        long[] x1_192 = new long[BF192.LIMBS]; randomLimbs(rng, x1_192, BF192.LIMBS);
        byte[] h192 = new byte[BF192.BYTES];
        new UniversalHashing.ZkHash192(sd192, 0).finalize(h192, 0, x1_192, 0);
        byte[] expected192 = new byte[BF192.BYTES];
        BF192.store(expected192, 0, x1_192, 0);
        isTrue("zk_hash_192 empty finalize == x1", Arrays.areEqual(h192, expected192));

        // 256
        byte[] sd256 = new byte[4 * BF256.BYTES]; rng.nextBytes(sd256);
        long[] x1_256 = new long[BF256.LIMBS]; randomLimbs(rng, x1_256, BF256.LIMBS);
        byte[] h256 = new byte[BF256.BYTES];
        new UniversalHashing.ZkHash256(sd256, 0).finalize(h256, 0, x1_256, 0);
        byte[] expected256 = new byte[BF256.BYTES];
        BF256.store(expected256, 0, x1_256, 0);
        isTrue("zk_hash_256 empty finalize == x1", Arrays.areEqual(h256, expected256));
    }

    private void zk_hash_single_update_matches_closed_form()
    {
        // After init then update(v): h0 = v, h1 = v. Finalize(x1): r0*v + r1*v + x1.
        SecureRandom rng = fixedSeed("zk-one");

        byte[] sd = new byte[4 * BF128.BYTES]; rng.nextBytes(sd);
        long[] v  = new long[BF128.LIMBS]; randomLimbs(rng, v, BF128.LIMBS);
        long[] x1 = new long[BF128.LIMBS]; randomLimbs(rng, x1, BF128.LIMBS);

        UniversalHashing.ZkHash128 ctx = new UniversalHashing.ZkHash128(sd, 0);
        ctx.update(v, 0);
        byte[] got = new byte[BF128.BYTES];
        ctx.finalize(got, 0, x1, 0);

        // Reference: r0*v + r1*v + x1
        long[] r0 = new long[BF128.LIMBS]; BF128.load(r0, 0, sd, 0);
        long[] r1 = new long[BF128.LIMBS]; BF128.load(r1, 0, sd, BF128.BYTES);
        long[] expected = new long[BF128.LIMBS];
        long[] tmp = new long[BF128.LIMBS];
        BF128.mul(expected, 0, r0, 0, v, 0);
        BF128.mul(tmp, 0, r1, 0, v, 0);
        BF128.addInPlace(expected, 0, tmp, 0);
        BF128.addInPlace(expected, 0, x1, 0);
        byte[] expectedBytes = new byte[BF128.BYTES];
        BF128.store(expectedBytes, 0, expected, 0);

        isTrue("zk_hash_128 single update matches closed form",
            Arrays.areEqual(got, expectedBytes));
    }

    private void zk_hash_two_updates_match_closed_form()
    {
        // After update(v1) then update(v2):
        //   h0 = v1*s + v2
        //   h1 = v1*t + v2
        // Finalize(x1): r0 * (v1*s + v2) + r1 * (v1*t + v2) + x1.
        SecureRandom rng = fixedSeed("zk-two");

        byte[] sd = new byte[4 * BF192.BYTES]; rng.nextBytes(sd);
        long[] v1 = new long[BF192.LIMBS]; randomLimbs(rng, v1, BF192.LIMBS);
        long[] v2 = new long[BF192.LIMBS]; randomLimbs(rng, v2, BF192.LIMBS);
        long[] x1 = new long[BF192.LIMBS]; randomLimbs(rng, x1, BF192.LIMBS);

        UniversalHashing.ZkHash192 ctx = new UniversalHashing.ZkHash192(sd, 0);
        ctx.update(v1, 0);
        ctx.update(v2, 0);
        byte[] got = new byte[BF192.BYTES];
        ctx.finalize(got, 0, x1, 0);

        long[] r0 = new long[BF192.LIMBS]; BF192.load(r0, 0, sd, 0);
        long[] r1 = new long[BF192.LIMBS]; BF192.load(r1, 0, sd, BF192.BYTES);
        long[] s  = new long[BF192.LIMBS]; BF192.load(s,  0, sd, 2 * BF192.BYTES);
        long  t   = BF64.load(sd, 3 * BF192.BYTES);

        // h0 = v1*s + v2
        long[] h0 = new long[BF192.LIMBS];
        BF192.mul(h0, 0, v1, 0, s, 0);
        BF192.addInPlace(h0, 0, v2, 0);
        // h1 = v1*t + v2
        long[] h1 = new long[BF192.LIMBS];
        BF192.mul64(h1, 0, v1, 0, t);
        BF192.addInPlace(h1, 0, v2, 0);
        // expected = r0*h0 + r1*h1 + x1
        long[] expected = new long[BF192.LIMBS];
        long[] tmp = new long[BF192.LIMBS];
        BF192.mul(expected, 0, r0, 0, h0, 0);
        BF192.mul(tmp, 0, r1, 0, h1, 0);
        BF192.addInPlace(expected, 0, tmp, 0);
        BF192.addInPlace(expected, 0, x1, 0);
        byte[] expectedBytes = new byte[BF192.BYTES];
        BF192.store(expectedBytes, 0, expected, 0);

        isTrue("zk_hash_192 two updates match closed form",
            Arrays.areEqual(got, expectedBytes));
    }

    // ===== vole_hash =====

    private void vole_hash_zero_witness_is_all_zero()
    {
        // sd is random; witness is all zeros. h0 = 0 (sum over zero chunks),
        // h1 = 0 (compute_h1 over zero blocks), so h2 = h3 = 0. Then XORed
        // with x1 chunk of x (which is also zero). Output: all zeros.
        SecureRandom rng = fixedSeed("vole-zero");

        for (int lambda : new int[]{ 128, 192, 256 })
        {
            int bytes = lambda / 8;
            byte[] sd = new byte[6 * bytes]; rng.nextBytes(sd);
            int ell = 8 * bytes;     // small ell, single witness block
            // x1 starts at byte offset (ell + 2*lambdaBits)/8 from x, and the
            // final XOR reads bytes + UNIVERSAL_HASH_B beyond x1's start.
            int x1Off = (ell + 2 * bytes * 8) / 8;
            byte[] x = new byte[x1Off + bytes + FaestParameters.UNIVERSAL_HASH_B];
            byte[] h = new byte[bytes + FaestParameters.UNIVERSAL_HASH_B];

            UniversalHashing.voleHash(h, 0, sd, 0, x, 0, ell, lambda);

            isTrue("vole_hash lambda=" + lambda + " zero witness => zero output",
                Arrays.areEqual(h, new byte[h.length]));
        }
    }

    // ===== leaf_hash =====

    private void leaf_hash_matches_direct_mul()
    {
        SecureRandom rng = fixedSeed("leaf");

        // lambda=128: leafHash(h, u, x) = u * x0 + x1 (in BF384)
        {
            byte[] u  = new byte[BF384.BYTES]; rng.nextBytes(u);
            byte[] x  = new byte[BF128.BYTES + BF384.BYTES]; rng.nextBytes(x);
            byte[] h  = new byte[BF384.BYTES];
            UniversalHashing.leafHash128(h, 0, u, 0, x, 0);

            long[] uL  = new long[BF384.LIMBS]; BF384.load(uL,  0, u, 0);
            long[] x0L = new long[BF128.LIMBS]; BF128.load(x0L, 0, x, 0);
            long[] x1L = new long[BF384.LIMBS]; BF384.load(x1L, 0, x, BF128.BYTES);
            long[] expL = new long[BF384.LIMBS];
            BF384.mul128(expL, 0, uL, 0, x0L, 0);
            BF384.addInPlace(expL, 0, x1L, 0);
            byte[] exp = new byte[BF384.BYTES];
            BF384.store(exp, 0, expL, 0);
            isTrue("leaf_hash_128 matches direct BF384.mul128+add", Arrays.areEqual(h, exp));
        }

        // lambda=192
        {
            byte[] u  = new byte[BF576.BYTES]; rng.nextBytes(u);
            byte[] x  = new byte[BF192.BYTES + BF576.BYTES]; rng.nextBytes(x);
            byte[] h  = new byte[BF576.BYTES];
            UniversalHashing.leafHash192(h, 0, u, 0, x, 0);

            long[] uL  = new long[BF576.LIMBS]; BF576.load(uL,  0, u, 0);
            long[] x0L = new long[BF192.LIMBS]; BF192.load(x0L, 0, x, 0);
            long[] x1L = new long[BF576.LIMBS]; BF576.load(x1L, 0, x, BF192.BYTES);
            long[] expL = new long[BF576.LIMBS];
            BF576.mul192(expL, 0, uL, 0, x0L, 0);
            BF576.addInPlace(expL, 0, x1L, 0);
            byte[] exp = new byte[BF576.BYTES];
            BF576.store(exp, 0, expL, 0);
            isTrue("leaf_hash_192 matches direct BF576.mul192+add", Arrays.areEqual(h, exp));
        }

        // lambda=256
        {
            byte[] u  = new byte[BF768.BYTES]; rng.nextBytes(u);
            byte[] x  = new byte[BF256.BYTES + BF768.BYTES]; rng.nextBytes(x);
            byte[] h  = new byte[BF768.BYTES];
            UniversalHashing.leafHash256(h, 0, u, 0, x, 0);

            long[] uL  = new long[BF768.LIMBS]; BF768.load(uL,  0, u, 0);
            long[] x0L = new long[BF256.LIMBS]; BF256.load(x0L, 0, x, 0);
            long[] x1L = new long[BF768.LIMBS]; BF768.load(x1L, 0, x, BF256.BYTES);
            long[] expL = new long[BF768.LIMBS];
            BF768.mul256(expL, 0, uL, 0, x0L, 0);
            BF768.addInPlace(expL, 0, x1L, 0);
            byte[] exp = new byte[BF768.BYTES];
            BF768.store(exp, 0, expL, 0);
            isTrue("leaf_hash_256 matches direct BF768.mul256+add", Arrays.areEqual(h, exp));
        }
    }

    // ===== dispatch =====

    private void lambda_dispatch_routes_correctly()
    {
        SecureRandom rng = fixedSeed("dispatch");

        // vole_hash dispatch
        for (int lambda : new int[]{ 128, 192, 256 })
        {
            int bytes = lambda / 8;
            byte[] sd = new byte[6 * bytes]; rng.nextBytes(sd);
            int ell = 8 * bytes;
            int x1Off = (ell + 2 * bytes * 8) / 8;
            byte[] x = new byte[x1Off + bytes + FaestParameters.UNIVERSAL_HASH_B];
            rng.nextBytes(x);

            byte[] viaDispatch = new byte[bytes + FaestParameters.UNIVERSAL_HASH_B];
            byte[] viaDirect   = new byte[bytes + FaestParameters.UNIVERSAL_HASH_B];

            UniversalHashing.voleHash(viaDispatch, 0, sd, 0, x, 0, ell, lambda);
            switch (lambda)
            {
            case 128: UniversalHashing.voleHash128(viaDirect, 0, sd, 0, x, 0, ell); break;
            case 192: UniversalHashing.voleHash192(viaDirect, 0, sd, 0, x, 0, ell); break;
            case 256: UniversalHashing.voleHash256(viaDirect, 0, sd, 0, x, 0, ell); break;
            }
            isTrue("vole_hash dispatch lambda=" + lambda,
                Arrays.areEqual(viaDispatch, viaDirect));
        }

        // leaf_hash dispatch
        {
            byte[] u  = new byte[BF384.BYTES]; rng.nextBytes(u);
            byte[] x  = new byte[BF128.BYTES + BF384.BYTES]; rng.nextBytes(x);
            byte[] viaDispatch = new byte[BF384.BYTES];
            byte[] viaDirect   = new byte[BF384.BYTES];
            UniversalHashing.leafHash(viaDispatch, 0, u, 0, x, 0, 128);
            UniversalHashing.leafHash128(viaDirect, 0, u, 0, x, 0);
            isTrue("leaf_hash dispatch lambda=128", Arrays.areEqual(viaDispatch, viaDirect));
        }
    }

    // ===== helpers =====

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

    private static void randomLimbs(SecureRandom rng, long[] dst, int limbs)
    {
        byte[] buf = new byte[limbs * 8];
        rng.nextBytes(buf);
        for (int i = 0; i < limbs; i++)
        {
            long v = 0;
            for (int j = 0; j < 8; j++)
            {
                v |= ((long)(buf[i * 8 + j] & 0xff)) << (j * 8);
            }
            dst[i] = v;
        }
    }

    public static void main(String[] args)
    {
        runTest(new UniversalHashingTest());
    }
}
