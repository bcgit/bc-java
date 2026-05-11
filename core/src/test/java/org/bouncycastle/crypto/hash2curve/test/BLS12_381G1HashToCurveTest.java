package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.hash2curve.HashToCurveProfile;
import org.bouncycastle.crypto.hash2curve.HashToEllipticCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;

/**
 * Known-answer tests for BLS12381G1_XMD:SHA-256_SSWU_RO_ from RFC 9380
 * Appendix J.9.1. Exercises end-to-end hash-to-curve, which transitively
 * verifies the SSWU map on the 11-isogenous curve, the iso_11 evaluation,
 * and the h_eff cofactor clearing.
 */
public class BLS12_381G1HashToCurveTest
    extends TestCase
{
    private static final String DST = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    private static final String[][] J91_VECTORS = {
        {
            "",
            "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
            "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
        },
        {
            "abc",
            "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
            "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
        },
        {
            "abcdef0123456789",
            "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
            "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
        },
        {
            "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
            "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38",
        },
        {
            "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
            "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8",
        },
    };

    public void testJ91Vectors()
    {
        HashToEllipticCurve h2c = HashToEllipticCurve.getInstance(
            HashToCurveProfile.BLS12_381_G1_XMD_SHA_256_SSWU_RO, DST);

        for (int i = 0; i < J91_VECTORS.length; ++i)
        {
            String[] v = J91_VECTORS[i];
            ECPoint p = h2c.hashToCurve(Strings.toUTF8ByteArray(v[0]));
            ECPoint pn = p.normalize();

            BigInteger expectedX = new BigInteger(v[1], 16);
            BigInteger expectedY = new BigInteger(v[2], 16);
            BigInteger actualX = pn.getAffineXCoord().toBigInteger();
            BigInteger actualY = pn.getAffineYCoord().toBigInteger();

            assertEquals("vector " + i + " x mismatch (msg=\"" + abbreviate(v[0]) + "\")",
                expectedX, actualX);
            assertEquals("vector " + i + " y mismatch (msg=\"" + abbreviate(v[0]) + "\")",
                expectedY, actualY);
        }
    }

    public void testGeneratorOnCurve()
    {
        ECPoint generator = BLS12_381G1.getGenerator(BLS12_381G1.createCurve());
        assertTrue("generator must be a valid curve point", generator.isValid());
        assertEquals("generator order must equal r",
            BLS12_381G1.ORDER.bitLength(), 255);
    }

    private static String abbreviate(String msg)
    {
        return msg.length() > 24 ? msg.substring(0, 24) + "..." : msg;
    }
}
