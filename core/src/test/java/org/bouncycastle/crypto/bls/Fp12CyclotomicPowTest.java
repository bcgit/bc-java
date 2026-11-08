package org.bouncycastle.crypto.bls;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;

/**
 * The package-private cyclotomic powers of {@link Fp12Element} against the
 * generic {@link Fp12Element#modPow}, on a pairing value (which lies in the
 * cyclotomic subgroup). The pairing only calls them with fixed exponents, so
 * the known answers reach only the branches those exponents need; this covers
 * the rest of the width-4 NAF recoding: e = 0, top digits 1, 3, 5 and 7,
 * negative digits including -1, and partial precomputation tables.
 */
public class Fp12CyclotomicPowTest
    extends TestCase
{
    private static final Fp12Element G = BLS12_381Pairing.pair(
        BLS12_381G1.getGenerator(BLS12_381G1.createCurve()), BLS12_381G2.getGenerator());

    public void testSmallExponents()
    {
        for (int e = 0; e <= 64; ++e)
        {
            BigInteger be = BigInteger.valueOf(e);
            assertEquals("e = " + e, G.modPow(be), G.cyclotomicPow(be));
            assertEquals("e = " + e, G.modPow(be), G.cyclotomicPowCompressed(be));
        }
    }

    public void testRandomExponents()
    {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 10; ++i)
        {
            BigInteger e = new BigInteger(64 + 32 * i, random);
            assertEquals(G.modPow(e), G.cyclotomicPow(e));
        }
    }
}
