package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Cross-checks the FAEST {@link RandomOracle} entry points produce bytes
 * identical to a direct SHAKE128 / SHAKE256 absorb-then-squeeze with the
 * domain-separation byte injected in the same position. Plus a copy()
 * invariant: cloned oracles squeeze the same bytes from the same absorbed
 * transcript.
 */
public class RandomOracleTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestRandomOracle";
    }

    public void performTest()
        throws Exception
    {
        h0_matches_raw_shake();
        h1_matches_raw_shake();
        h3_matches_raw_shake();
        h4_matches_raw_shake();
        domain_separation_changes_output();
        copy_clones_absorb_state();
        squeeze_is_incremental();
    }

    private void h0_matches_raw_shake()
    {
        byte[] src = Hex.decode("00112233445566778899aabbccddeeff");

        for (int lambda : new int[]{ 128, 192, 256 })
        {
            byte[] seed = new byte[lambda / 8];
            byte[] commit = new byte[2 * lambda / 8];

            RandomOracle.H0(lambda, src, 0, src.length,
                seed, 0, seed.length,
                commit, 0, commit.length);

            byte[] expected = directShake(lambda, src, RandomOracle.DOMAIN_H0,
                seed.length + commit.length);

            isTrue("H0 lambda=" + lambda + " seed mismatch",
                Arrays.areEqual(seed,
                    Arrays.copyOfRange(expected, 0, seed.length)));
            isTrue("H0 lambda=" + lambda + " commit mismatch",
                Arrays.areEqual(commit,
                    Arrays.copyOfRange(expected, seed.length, expected.length)));
        }
    }

    private void h1_matches_raw_shake()
    {
        byte[] src = "hello FAEST H1".getBytes();

        for (int lambda : new int[]{ 128, 192, 256 })
        {
            byte[] digest = new byte[2 * lambda / 8];
            RandomOracle.H1(lambda, src, 0, src.length, digest, 0, digest.length);

            byte[] expected = directShake(lambda, src, RandomOracle.DOMAIN_H1,
                digest.length);
            isTrue("H1 lambda=" + lambda, Arrays.areEqual(digest, expected));
        }
    }

    private void h3_matches_raw_shake()
    {
        byte[] src = Hex.decode("deadbeef00010203040506070809");

        for (int lambda : new int[]{ 128, 192, 256 })
        {
            byte[] digest = new byte[lambda / 8];
            byte[] iv = new byte[FaestParameters.IV_SIZE];

            RandomOracle.H3(lambda, src, 0, src.length,
                digest, 0, digest.length, iv, 0);

            byte[] expected = directShake(lambda, src, RandomOracle.DOMAIN_H3,
                digest.length + FaestParameters.IV_SIZE);
            isTrue("H3 lambda=" + lambda + " digest",
                Arrays.areEqual(digest,
                    Arrays.copyOfRange(expected, 0, digest.length)));
            isTrue("H3 lambda=" + lambda + " iv",
                Arrays.areEqual(iv,
                    Arrays.copyOfRange(expected, digest.length, expected.length)));
        }
    }

    private void h4_matches_raw_shake()
    {
        byte[] preIv = Hex.decode("000102030405060708090a0b0c0d0e0f");
        isEquals("preIv length matches IV_SIZE", FaestParameters.IV_SIZE, preIv.length);

        for (int lambda : new int[]{ 128, 192, 256 })
        {
            byte[] iv = new byte[FaestParameters.IV_SIZE];
            RandomOracle.H4(lambda, preIv, 0, iv, 0);

            byte[] expected = directShake(lambda, preIv, RandomOracle.DOMAIN_H4,
                FaestParameters.IV_SIZE);
            isTrue("H4 lambda=" + lambda, Arrays.areEqual(iv, expected));
        }
    }

    private void domain_separation_changes_output()
    {
        // Same input, different domain-sep tags must produce different output.
        byte[] src = Hex.decode("0011223344556677");
        byte[] h0 = new byte[32];
        byte[] h1 = new byte[32];
        RandomOracle.H0(128, src, 0, src.length, h0, 0, 16, h0, 16, 16);
        RandomOracle.H1(128, src, 0, src.length, h1, 0, 32);
        isTrue("H0 vs H1 must differ on same input",
            !Arrays.areEqual(h0, h1));
    }

    private void copy_clones_absorb_state()
    {
        // Absorb a transcript, copy() the oracle, absorb different bytes on each,
        // and verify the squeezes diverge — but if we copy() and then do the same
        // post-absorb on both, squeezes match.
        byte[] common = "common prefix".getBytes();
        byte[] branchA = "branch A".getBytes();
        byte[] branchB = "branch B".getBytes();

        for (int lambda : new int[]{ 128, 192, 256 })
        {
            RandomOracle ro = new RandomOracle(lambda);
            ro.absorb(common);
            RandomOracle clone = ro.copy();

            ro.absorb(branchA);
            ro.absorbByte(RandomOracle.DOMAIN_H1);
            byte[] outA = new byte[32];
            ro.squeeze(outA, 0, outA.length);

            clone.absorb(branchB);
            clone.absorbByte(RandomOracle.DOMAIN_H1);
            byte[] outB = new byte[32];
            clone.squeeze(outB, 0, outB.length);

            isTrue("copy() then divergent absorb must produce different output",
                !Arrays.areEqual(outA, outB));

            // Same-branch reproducibility through copy: build two fresh oracles,
            // copy each at the same point, do identical post-absorbs, expect equal.
            RandomOracle ro2 = new RandomOracle(lambda);
            ro2.absorb(common);
            RandomOracle clone2 = ro2.copy();

            ro2.absorb(branchA);
            ro2.absorbByte(RandomOracle.DOMAIN_H1);
            byte[] outA2 = new byte[32];
            ro2.squeeze(outA2, 0, outA2.length);

            clone2.absorb(branchA);
            clone2.absorbByte(RandomOracle.DOMAIN_H1);
            byte[] outAClone = new byte[32];
            clone2.squeeze(outAClone, 0, outAClone.length);

            isTrue("copy() with same post-absorb must match",
                Arrays.areEqual(outA2, outAClone));
        }
    }

    private void squeeze_is_incremental()
    {
        // squeeze() may be called multiple times; output must concatenate as
        // if it were a single large squeeze of the same total length.
        byte[] src = "incremental squeeze".getBytes();

        RandomOracle ro1 = new RandomOracle(128);
        ro1.absorb(src);
        ro1.absorbByte(RandomOracle.DOMAIN_H0);
        byte[] big = new byte[64];
        ro1.squeeze(big, 0, big.length);

        RandomOracle ro2 = new RandomOracle(128);
        ro2.absorb(src);
        ro2.absorbByte(RandomOracle.DOMAIN_H0);
        byte[] small = new byte[64];
        ro2.squeeze(small, 0, 16);
        ro2.squeeze(small, 16, 24);
        ro2.squeeze(small, 40, 24);

        isTrue("squeeze in chunks must equal one big squeeze",
            Arrays.areEqual(big, small));
    }

    /**
     * Reference squeeze: do absorb, absorb domain-sep, then squeeze totalLen
     * bytes using BC's SHAKEDigest directly. The {@link RandomOracle} class
     * should produce bytewise identical output.
     */
    private static byte[] directShake(int lambda, byte[] src, byte domainSep, int totalLen)
    {
        SHAKEDigest s = new SHAKEDigest(lambda == 128 ? 128 : 256);
        s.update(src, 0, src.length);
        s.update(domainSep);
        byte[] out = new byte[totalLen];
        s.doOutput(out, 0, totalLen);
        return out;
    }

    public static void main(String[] args)
    {
        runTest(new RandomOracleTest());
    }
}
