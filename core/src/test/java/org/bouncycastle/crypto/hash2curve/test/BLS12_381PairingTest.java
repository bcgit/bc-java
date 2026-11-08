package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381Pairing;
import org.bouncycastle.crypto.bls.Fp12Element;
import org.bouncycastle.crypto.bls.Fp2Element;
import org.bouncycastle.crypto.bls.Fp6Element;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Bilinearity-based correctness tests for the BLS12-381 optimal ate pairing.
 * <p>
 * Without external KAT vectors at hand, these tests validate the pairing
 * via its defining algebraic properties:
 * <ul>
 *   <li>Identity: {@code e(O, Q) == 1} and {@code e(P, O) == 1}.</li>
 *   <li>Non-degeneracy: {@code e(G1, G2) != 1}.</li>
 *   <li>Subgroup membership: {@code e(P, Q)^r == 1} (output is in GT, the
 *       order-r subgroup of Fp^12).</li>
 *   <li>Bilinearity in G1: {@code e(a*P, Q) == e(P, Q)^a}.</li>
 *   <li>Bilinearity in G2: {@code e(P, b*Q) == e(P, Q)^b}.</li>
 *   <li>Full bilinearity: {@code e(a*P, b*Q) == e(P, Q)^(a*b)}.</li>
 *   <li>Symmetry of the bilinear pairing in this swap pattern:
 *       {@code e(a*P, Q) == e(P, a*Q)}.</li>
 * </ul>
 * Together these uniquely identify a non-degenerate bilinear pairing on
 * G1 x G2 -> GT up to a constant factor; correctness of the constant factor
 * (which depends on the twist convention) requires comparing against an
 * external reference and is left to a follow-on slice that adds KAT
 * vectors.
 */
public class BLS12_381PairingTest
    extends TestCase
{
    private static ECPoint g1Generator()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        return BLS12_381G1.getGenerator(curve);
    }

    public void testIdentityG1()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint o = curve.getInfinity();
        Fp12Element e = BLS12_381Pairing.pair(o, BLS12_381G2.getGenerator());
        assertEquals(Fp12Element.ONE, e);
    }

    public void testIdentityG2()
    {
        Fp12Element e = BLS12_381Pairing.pair(g1Generator(), BLS12_381G2Point.INFINITY);
        assertEquals(Fp12Element.ONE, e);
    }

    public void testNonDegeneracy()
    {
        Fp12Element e = BLS12_381Pairing.pair(g1Generator(), BLS12_381G2.getGenerator());
        assertFalse("e(G1, G2) must not be 1 (pairing is non-degenerate)", Fp12Element.ONE.equals(e));
    }

    public void testGtSubgroupMembership()
    {
        // e(G1, G2)^r == 1 — output of the pairing lives in the order-r
        // subgroup GT of Fp^12. This is the strongest single-pairing test
        // of the final exponentiation.
        Fp12Element e = BLS12_381Pairing.pair(g1Generator(), BLS12_381G2.getGenerator());
        Fp12Element ePowR = e.modPow(BLS12_381G1.ORDER);
        assertEquals("e(G1, G2)^r must be 1 (pairing output is in GT)",
            Fp12Element.ONE, ePowR);
    }

    /**
     * Confirms the Hayashida-Hayasaka-Teruya {@code /3} hard-part chain
     * produces the canonical {@code f^((p^4 - p^2 + 1) / r)} (no cube
     * factor), by direct comparison against a naive
     * {@link Fp12Element#modPow} on the full hard exponent. Catches any
     * algebra error in the chain that would otherwise hide behind
     * bilinearity (which holds even when the pairing differs from
     * canonical by a fixed power coprime to r).
     */
    public void testHardPartMatchesNaiveModPow()
    {
        // Apply the easy part first so the input lives in the cyclotomic
        // subgroup, then compare chain vs. modPow on the hard exponent.
        // Use a fixed pseudorandom Fp12 element so the test is reproducible.
        java.security.SecureRandom rng = new java.security.SecureRandom(new byte[]{77});
        java.math.BigInteger p = org.bouncycastle.crypto.bls.Fp2Element.P;
        org.bouncycastle.crypto.bls.Fp2Element a0 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a1 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a2 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp6Element c0 = org.bouncycastle.crypto.bls.Fp6Element.of(a0, a1, a2);
        org.bouncycastle.crypto.bls.Fp2Element a3 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a4 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp2Element a5 = org.bouncycastle.crypto.bls.Fp2Element.of(
            new java.math.BigInteger(p.bitLength(), rng).mod(p),
            new java.math.BigInteger(p.bitLength(), rng).mod(p));
        org.bouncycastle.crypto.bls.Fp6Element c1 = org.bouncycastle.crypto.bls.Fp6Element.of(a3, a4, a5);
        Fp12Element raw = Fp12Element.of(c0, c1);

        // Apply easy part: raw^(p^6 - 1)(p^2 + 1).
        Fp12Element f1 = raw.conjugate().mul(raw.inverse());
        Fp12Element easy = f1.frobeniusSquared().mul(f1);

        Fp12Element chain = BLS12_381Pairing.hardPart(easy);
        Fp12Element direct = easy.modPow(BLS12_381Pairing.HARD_EXPONENT);
        assertEquals("hardPart chain must produce canonical f^hard_exp", direct, chain);
    }

    /**
     * The identity compresses to all zeros, so the compressed (Karabina)
     * powers in the hard part cannot decompress it and must fall back to
     * plain cyclotomic squaring.
     */
    public void testHardPartOfIdentity()
    {
        assertEquals(Fp12Element.ONE, BLS12_381Pairing.hardPart(Fp12Element.ONE));
    }

    public void testBilinearityInG1()
    {
        BigInteger a = BigInteger.valueOf(7);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p.multiply(a), q);
        Fp12Element rhs = BLS12_381Pairing.pair(p, q).modPow(a);
        assertEquals("e(a*P, Q) must equal e(P, Q)^a", rhs, lhs);
    }

    public void testBilinearityInG2()
    {
        BigInteger b = BigInteger.valueOf(11);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p, q.multiply(b));
        Fp12Element rhs = BLS12_381Pairing.pair(p, q).modPow(b);
        assertEquals("e(P, b*Q) must equal e(P, Q)^b", rhs, lhs);
    }

    public void testFullBilinearity()
    {
        BigInteger a = BigInteger.valueOf(5);
        BigInteger b = BigInteger.valueOf(13);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p.multiply(a), q.multiply(b));
        Fp12Element rhs = BLS12_381Pairing.pair(p, q).modPow(a.multiply(b));
        assertEquals("e(a*P, b*Q) must equal e(P, Q)^(a*b)", rhs, lhs);
    }

    public void testScalarSwap()
    {
        // e(a*P, Q) == e(P, a*Q) — both equal e(P, Q)^a.
        BigInteger a = BigInteger.valueOf(17);
        ECPoint p = g1Generator();
        BLS12_381G2Point q = BLS12_381G2.getGenerator();

        Fp12Element lhs = BLS12_381Pairing.pair(p.multiply(a), q);
        Fp12Element rhs = BLS12_381Pairing.pair(p, q.multiply(a));
        assertEquals("e(a*P, Q) must equal e(P, a*Q)", rhs, lhs);
    }

    // ---------------------------------------------------------------------
    // multiPair edge cases (review gap G11).
    //
    // The verify paths transitively exercise multiPair with one or two
    // (g1, g2) pairs, but the documented edge cases (length mismatch,
    // all inputs infinity, mixed infinity) aren't tested directly.
    // Each affects whether aggregate-verify produces correct results
    // for malformed or degenerate input lists.
    // ---------------------------------------------------------------------

    public void testMultiPairRejectsLengthMismatch()
    {
        ECPoint g1 = g1Generator();
        BLS12_381G2Point g2 = BLS12_381G2.getGenerator();
        try
        {
            BLS12_381Pairing.multiPair(
                new ECPoint[]{g1, g1},
                new BLS12_381G2Point[]{g2});
            fail("g1/g2 length mismatch must throw");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testMultiPairAllInfinityReturnsOne()
    {
        // Per BLS12_381Pairing.multiPair javadoc: pairs whose G1 or G2
        // component is the point at infinity are skipped, and an
        // all-infinity input list returns the GT identity.
        ECCurve curve = BLS12_381G1.createCurve();
        Fp12Element result = BLS12_381Pairing.multiPair(
            new ECPoint[]{curve.getInfinity(), curve.getInfinity()},
            new BLS12_381G2Point[]{BLS12_381G2Point.INFINITY, BLS12_381G2Point.INFINITY});
        assertEquals("all-infinity multiPair must return GT identity",
            Fp12Element.ONE, result);
    }

    public void testMultiPairMixedInfinitySkips()
    {
        // (g1, g2) + (infinity, q) + (p, infinity) should equal e(g1, g2)
        // alone, because the two infinity pairs are skipped.
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g1 = g1Generator();
        BLS12_381G2Point g2 = BLS12_381G2.getGenerator();

        Fp12Element pure = BLS12_381Pairing.pair(g1, g2);
        Fp12Element padded = BLS12_381Pairing.multiPair(
            new ECPoint[]{g1, curve.getInfinity(), g1.multiply(BigInteger.valueOf(3))},
            new BLS12_381G2Point[]{g2, g2, BLS12_381G2Point.INFINITY});
        assertEquals("interleaved-infinity multiPair must equal the non-infinity-only product",
            pure, padded);
    }

    /**
     * Pairing values computed by the original affine Fp^12 Miller loop (before
     * the Jacobian / sparse-line rewrite), as the twelve Fp coefficients
     * {@code c0.c0.c0, c0.c0.c1, c0.c1.c0, ..., c1.c2.c1} in hex. Bilinearity
     * alone would not notice a pairing raised to a constant power, or a line
     * scaling that the final exponentiation does not remove; these would.
     */
    private static final String E_G1_G2 =
        "11619b45f61edfe3b47a15fac19442526ff489dcda25e59121d9931438907dfd448299a87dde3a649bdba96e84d54558,153ce14a76a53e205ba8f275ef1137c56a566f638b52d34ba3bf3bf22f277d70f76316218c0dfd583a394b8448d2be7f;" +
        "95668fb4a02fe930ed44767834c915b283b1c6ca98c047bd4c272e9ac3f3ba6ff0b05a93e59c71fba77bce995f04692,16deedaa683124fe7260085184d88f7d036b86f53bb5b7f1fc5e248814782065413e7d958d17960109ea006b2afdeb5f;" +
        "9c92cf02f3cd3d2f9d34bc44eee0dd50314ed44ca5d30ce6a9ec0539be7a86b121edc61839ccc908c4bdde256cd6048,111061f398efc2a97ff825b04d21089e24fd8b93a47e41e60eae7e9b2a38d54fa4dedced0811c34ce528781ab9e929c7;" +
        "1ecfcf31c86257ab00b4709c33f1c9c4e007659dd5ffc4a735192167ce197058cfb4c94225e7f1b6c26ad9ba68f63bc,8890726743a1f94a8193a166800b7787744a8ad8e2f9365db76863e894b7a11d83f90d873567e9d645ccf725b32d26f;" +
        "e61c752414ca5dfd258e9606bac08daec29b3e2c57062669556954fb227d3f1260eedf25446a086b0844bcd43646c10,fe63f185f56dd29150fc498bbeea78969e7e783043620db33f75a05a0a2ce5c442beaff9da195ff15164c00ab66bdde;" +
        "10900338a92ed0b47af211636f7cfdec717b7ee43900eee9b5fc24f0000c5874d4801372db478987691c566a8c474978,1454814f3085f0e6602247671bc408bbce2007201536818c901dbd4d2095dd86c1ec8b888e59611f60a301af7776be3d;";

    private static final String E_SG1_TG2 =
        "4ee3da5f8f9053f5c58c5ba5d66bf9ae9ca7e00ecfabfe42e4ad1478a4fb661eaa05771a520ec4021d19d97851cf06d,9b09a080869abf3731cf2cf8b00b9c98d9ae061e43e97a971b8e713f29f3d75255add89aadafb2a711fa63385d26ba9;" +
        "1494d2e80b036dbe10bb7a61a76adc602f60b59e841d6d2fac96d4b6000557f1879a1f95c83d1aef16887b778e4f1ee6,8b5ac794e7a4b76fd6375ae2eef5cd7309c947971a189c106a1244e6350ab13a6bbb0ac2a15d0b04d9a2646169ffdc;" +
        "6a2a6d69cd169c0f7d7d0a3c53270c7e5e7cce2a17150bbc2971d514f5280fda9d01ab22290c25553dd13a29f2d7479,10d107c74dbfe53f21409578541ab5f2ba44d432a7ad6f05bad07445d012a7187304c2ad177f503019fe1c95eba380b1;" +
        "9e6a345059e99d2faa8dd2d195805a8805415c83710198c934b09dee68249b51f623b2083201779daaeae8a05834b39,b0dfbf7767f9f3b13959832bfa185b65f669da53c91a6688a452cfaeb51b8b8c054f7f4dd18a7dea471c717b0a49f0e;" +
        "f495f9224b666829b3b94c70283c9a19d4b315a8a2e3cb8769f2a2ddda62d015d3cb94b0efec8ed1bdbd3be72fc3e1c,b9a7b22dcbf2425b1e0801fd0c4f1773c44afa0c9b51f0bd450dcfc262e055835a2557c5dd7bce5ee5cdc9abfb0f960;" +
        "76d6c7280f7c259bcd307af655e41b5272a6ab4a4fefb95e29c1d43488b45a4410b922b9d6fffd4b81562becc59aade,1949fa2f155b045be0d3aadf2dfc130fb4576636f7672a47ed2c644d6546d8a5bb7dd8d05d5c034f80e7d329410ea366;";

    private static final String E_MULTI =
        "3513e16ff7b23dfdf54885ba01d619f78f570a3245bc612a0983880050cb36d960fac0e8b4199056ca21424d9fa4ac6,18849da5b6110508c67409685021c4f7720a156cd93adc921d1537db4c130b0868d1ee23e13dd70a1cf7bc8b39216462;" +
        "6fa6b1897880f124569490a31858daeb493f83b829eebc2de48c9c377f72805d740fd235235420a85349f07654183a6,171fa4abd8c7e1b681020fb4d988028c7642d51690b7cefed4099854c2136e99f2e5cc39e05a56fe8b5138cca065fad8;" +
        "b84e83cb21f33f9f250e01d3f8a8e6a4568aafd49a0be474c5b4fa5050d3c596a0dd80e556fc9ce42f673e2ee190282,f6c78e37197be9c49bbd4a124c68404b5f1fc173418c66bb9c5d6cf3586113573a9db73646e12374e043576392d0f09;" +
        "974170e16b16d8a76c9c12f4bdd09f7883dfd6714c440fd076eed071098d62dac2b5aefe921c58d7b25cfbdaf436979,48421a4a44a2b6ba894e1bbfa37556e0307cd07560b97a36374660922a95b4a1fe23cc56ca2761f83b4fbbe9307c59e;" +
        "783287595e5b47a19a9bdf69ce5766041c2ff0f3098c0d4790a10e76b97bf13ba82fec68f63aa1b73a1dcb5ac03e4e3,106d87a32380e319259c81e42ae43b5d77f06984cd8e81adfd49e8479ab9800b3ba01ef5c481698eb577c0a64da9fc7c;" +
        "34ee22ae652af04104f9dd678ce83ab78166908d6c92bcc1670c5d1f0ec4d9ca6ca5d35552e52e6b360567c89e2560b,1091588987ff6fba19958d5091aaec4884aaa94964b0d29529d601c9760253e281a50789b5b1c873aac8c5e4f6db886b;";

    private static final BigInteger S_SCALAR = new BigInteger("2b5c1e8d9f3a7b6c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0", 16);
    private static final BigInteger T_SCALAR = new BigInteger("13579bdf2468ace013579bdf2468ace013579bdf2468ace013579bdf2468ace", 16);

    public void testKnownAnswers()
    {
        ECPoint g1 = BLS12_381G1.getGenerator(BLS12_381G1.createCurve());
        BLS12_381G2Point g2 = BLS12_381G2.getGenerator();
        assertEquals(fp12(E_G1_G2), BLS12_381Pairing.pair(g1, g2));
        assertEquals(fp12(E_SG1_TG2), BLS12_381Pairing.pair(g1.multiply(S_SCALAR), g2.multiply(T_SCALAR)));
        assertEquals(fp12(E_MULTI), BLS12_381Pairing.multiPair(
            new ECPoint[]{ g1.multiply(T_SCALAR), g1.multiply(S_SCALAR).negate() },
            new BLS12_381G2Point[]{ g2.multiply(S_SCALAR), g2 }));
    }

    private static Fp12Element fp12(String hex)
    {
        String[] parts = hex.split(";");
        Fp2Element[] e = new Fp2Element[6];
        for (int i = 0; i < 6; ++i)
        {
            String[] c = parts[i].split(",");
            e[i] = Fp2Element.of(new BigInteger(c[0], 16), new BigInteger(c[1], 16));
        }
        return Fp12Element.of(Fp6Element.of(e[0], e[1], e[2]), Fp6Element.of(e[3], e[4], e[5]));
    }
}
