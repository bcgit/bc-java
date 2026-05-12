package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381Serialization;
import org.bouncycastle.crypto.bls.Fp2Element;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tests for the Zcash-format compressed serialization of BLS12-381 G1 and
 * G2 points. The G1 generator hex is the well-known constant published in
 * the Zcash spec (and reused by Eth2 / Filecoin / IETF
 * draft-irtf-cfrg-pairing-friendly-curves).
 */
public class BLS12_381SerializationTest
    extends TestCase
{
    /**
     * Zcash-format compressed encoding of the BLS12-381 G1 generator. Top
     * byte 0x97 = 0b10010111: compressed=1, infinity=0, sign=0, then the
     * top 5 bits of the x-coordinate which start with 0x17.
     */
    private static final byte[] G1_GEN_COMPRESSED = Hex.decode(
        "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");

    public void testG1GeneratorVector()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        byte[] encoded = BLS12_381Serialization.compressG1(g);
        assertEquals("G1 generator must serialise to the published Zcash hex",
            Hex.toHexString(G1_GEN_COMPRESSED), Hex.toHexString(encoded));

        ECPoint decoded = BLS12_381Serialization.decompressG1(G1_GEN_COMPRESSED, curve);
        assertTrue("decoded G1 generator must equal the canonical generator",
            decoded.equals(g));
    }

    public void testG1Infinity()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        byte[] enc = BLS12_381Serialization.compressG1(curve.getInfinity());
        assertEquals("G1 infinity byte 0 must be 0xC0", 0xC0, enc[0] & 0xff);
        for (int i = 1; i < enc.length; ++i)
        {
            assertEquals("G1 infinity body must be zero", 0, enc[i]);
        }
        ECPoint decoded = BLS12_381Serialization.decompressG1(enc, curve);
        assertTrue("infinity must round-trip", decoded.isInfinity());
    }

    public void testG1RoundTripScalarMultiples()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        for (int k = 1; k <= 5; ++k)
        {
            ECPoint p = g.multiply(BigInteger.valueOf(k)).normalize();
            byte[] enc = BLS12_381Serialization.compressG1(p);
            ECPoint decoded = BLS12_381Serialization.decompressG1(enc, curve);
            assertTrue("k*G1 must round-trip for k=" + k, decoded.equals(p));
        }
    }

    public void testG1DecompressRejectsCompressedFlagClear()
    {
        byte[] bad = new byte[48];  // top bit 0 — compressed flag clear
        try
        {
            BLS12_381Serialization.decompressG1(bad, BLS12_381G1.createCurve());
            fail("compressed flag clear should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG1DecompressRejectsBadLength()
    {
        try
        {
            BLS12_381Serialization.decompressG1(new byte[47], BLS12_381G1.createCurve());
            fail("47-byte input should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2Infinity()
    {
        byte[] enc = BLS12_381Serialization.compressG2(BLS12_381G2Point.INFINITY);
        assertEquals("G2 infinity byte 0 must be 0xC0", 0xC0, enc[0] & 0xff);
        BLS12_381G2Point decoded = BLS12_381Serialization.decompressG2(enc);
        assertTrue("G2 infinity must round-trip", decoded.isInfinity());
    }

    public void testG2GeneratorRoundTrip()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        byte[] enc = BLS12_381Serialization.compressG2(g);
        assertEquals("G2 compressed encoding must be 96 bytes", 96, enc.length);
        BLS12_381G2Point decoded = BLS12_381Serialization.decompressG2(enc);
        assertTrue("G2 generator must round-trip", decoded.equals(g));
    }

    public void testG2RoundTripScalarMultiples()
    {
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        for (int k = 1; k <= 4; ++k)
        {
            BLS12_381G2Point p = g.multiply(BigInteger.valueOf(k));
            byte[] enc = BLS12_381Serialization.compressG2(p);
            BLS12_381G2Point decoded = BLS12_381Serialization.decompressG2(enc);
            assertTrue("k*G2 must round-trip for k=" + k, decoded.equals(p));
        }
    }

    public void testG2DecompressRejectsBadLength()
    {
        try
        {
            BLS12_381Serialization.decompressG2(new byte[95]);
            fail("95-byte input should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testCompressedPubkeyCanBeDecompressedAndUsed()
    {
        // Round-trip a JCE-style serialized public key through compression
        // and confirm we can verify a signature against it. This is the
        // headline use case for the new serializer.
        BigInteger sk = BLS12_381BasicScheme.keyGen(makeIkm(), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] pkBytes = BLS12_381Serialization.compressG1(pk);

        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk, "hi".getBytes());
        byte[] sigBytes = BLS12_381Serialization.compressG2(sig);

        // Reconstruct from bytes only.
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint pkRestored = BLS12_381Serialization.decompressG1(pkBytes, curve);
        BLS12_381G2Point sigRestored = BLS12_381Serialization.decompressG2(sigBytes);

        assertTrue("signature must verify after compress/decompress round-trip",
            BLS12_381BasicScheme.verify(pkRestored, "hi".getBytes(), sigRestored));
    }

    private static byte[] makeIkm()
    {
        byte[] ikm = new byte[32];
        for (int i = 0; i < ikm.length; ++i)
        {
            ikm[i] = (byte)(i + 1);
        }
        return ikm;
    }

    // ---------------------------------------------------------------------
    // Malformed-decompress rejection tests (review gap G1).
    //
    // Flag byte layout (top byte of the compressed encoding):
    //   bit 7 (0x80): compressed (must be 1)
    //   bit 6 (0x40): infinity   (1 iff this encodes the point at infinity)
    //   bit 5 (0x20): y-sign     (1 iff y > -y lexicographically)
    //   bits 4-0   : top 5 bits of the x-coordinate (or x.c1 for G2)
    //
    // Before these tests, only "compressed bit clear" (G1) and bad length
    // (G1=47, G2=95) were exercised. The decompressors guard several
    // additional malformed-input branches; each is a security boundary
    // (an attacker controls the wire bytes the verifier feeds in), so
    // each gets a focused test. See BLS12_381Serialization.decompressG1
    // / decompressG2 source for the exact checks.
    // ---------------------------------------------------------------------

    public void testG1DecompressRejectsLength49()
    {
        // The G1 decompressor takes exactly 48 bytes; one byte too many
        // must be rejected just like one too few.
        try
        {
            BLS12_381Serialization.decompressG1(new byte[49], BLS12_381G1.createCurve());
            fail("49-byte input should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG1DecompressRejectsInfinityWithSignFlag()
    {
        // Spec: when the infinity bit is set, the sign bit MUST be 0.
        // A non-conforming encoder might set both; we must not silently
        // interpret it as plain infinity.
        byte[] bad = new byte[48];
        bad[0] = (byte)(0x80 | 0x40 | 0x20);  // C | I | S
        try
        {
            BLS12_381Serialization.decompressG1(bad, BLS12_381G1.createCurve());
            fail("infinity encoding with sign flag set must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG1DecompressRejectsInfinityWithNonZeroByte0Bits()
    {
        // Infinity encoding requires every non-flag bit of byte 0 to be
        // zero. Setting the low bit smuggles a 0x01 into what would be
        // the x-coordinate top.
        byte[] bad = new byte[48];
        bad[0] = (byte)(0x80 | 0x40 | 0x01);
        try
        {
            BLS12_381Serialization.decompressG1(bad, BLS12_381G1.createCurve());
            fail("infinity encoding with non-zero non-flag bits in byte 0 must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG1DecompressRejectsInfinityWithNonZeroBody()
    {
        // Infinity encoding requires bytes 1..47 to be all zero.
        byte[] bad = new byte[48];
        bad[0] = (byte)(0x80 | 0x40);
        bad[20] = (byte)0xff;
        try
        {
            BLS12_381Serialization.decompressG1(bad, BLS12_381G1.createCurve());
            fail("infinity encoding with non-zero body must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG1DecompressRejectsXGeP()
    {
        // x must satisfy 0 <= x < p. Encode x = p exactly and confirm
        // rejection. (p has 381 bits so the top 3 bits of its 48-byte
        // big-endian encoding are 000, leaving the flag bits free.)
        BigInteger p = BLS12_381G1.Q;
        byte[] enc = BigIntegers.asUnsignedByteArray(48, p);
        enc[0] |= (byte)0x80;  // set compressed flag; sign/infinity stay clear
        try
        {
            BLS12_381Serialization.decompressG1(enc, BLS12_381G1.createCurve());
            fail("G1 x == p must be rejected as out of range");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG1DecompressRejectsNonCurveX()
    {
        // The decompressor computes y = sqrt(x^3 + 4) mod p. If x^3 + 4
        // is not a quadratic residue mod p (Legendre symbol = -1), there
        // is no point on the curve with that x — the decompressor's
        // "y * y != ySquared" branch must reject. Search for such an x
        // among small naturals; by Hasse-Weil ~half of all x's qualify.
        BigInteger p = BLS12_381G1.Q;
        BigInteger pMinus1Over2 = p.subtract(BigInteger.ONE).shiftRight(1);
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger x = BigInteger.ONE;
        boolean found = false;
        for (int attempt = 0; attempt < 200; ++attempt)
        {
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
                .add(BigInteger.valueOf(4)).mod(p);
            BigInteger legendre = rhs.modPow(pMinus1Over2, p);
            if (legendre.equals(pMinus1))
            {
                found = true;
                break;
            }
            x = x.add(BigInteger.ONE);
        }
        if (!found)
        {
            fail("could not find an x in [1, 200] with non-residue x^3 + 4");
        }
        byte[] enc = BigIntegers.asUnsignedByteArray(48, x);
        enc[0] |= (byte)0x80;
        try
        {
            BLS12_381Serialization.decompressG1(enc, BLS12_381G1.createCurve());
            fail("G1 x with no corresponding y on the curve must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG1DecompressYSignFlipDecodesNegate()
    {
        // Flipping only the y-sign bit of a valid encoding must produce
        // the negate of the original point on decode. This isolates the
        // sign-bit interpretation from the round-trip test (which always
        // re-encodes with the canonical sign).
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        byte[] enc = BLS12_381Serialization.compressG1(g);
        enc[0] ^= (byte)0x20;
        ECPoint decoded = BLS12_381Serialization.decompressG1(enc, curve);
        assertEquals("y-sign bit flip must decode to the negate",
            g.negate().normalize(), decoded.normalize());
    }

    public void testG2DecompressRejectsLength97()
    {
        try
        {
            BLS12_381Serialization.decompressG2(new byte[97]);
            fail("97-byte input should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2DecompressRejectsCompressedFlagClear()
    {
        // Symmetric to the existing G1 compressed-flag-clear test.
        byte[] bad = new byte[96];  // top bit 0
        try
        {
            BLS12_381Serialization.decompressG2(bad);
            fail("G2 compressed flag clear must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2DecompressRejectsInfinityWithSignFlag()
    {
        byte[] bad = new byte[96];
        bad[0] = (byte)(0x80 | 0x40 | 0x20);
        try
        {
            BLS12_381Serialization.decompressG2(bad);
            fail("G2 infinity with sign flag set must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2DecompressRejectsInfinityWithNonZeroByte0Bits()
    {
        byte[] bad = new byte[96];
        bad[0] = (byte)(0x80 | 0x40 | 0x01);
        try
        {
            BLS12_381Serialization.decompressG2(bad);
            fail("G2 infinity with non-zero non-flag bits in byte 0 must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2DecompressRejectsInfinityWithNonZeroBody()
    {
        byte[] bad = new byte[96];
        bad[0] = (byte)(0x80 | 0x40);
        bad[50] = (byte)0xff;
        try
        {
            BLS12_381Serialization.decompressG2(bad);
            fail("G2 infinity with non-zero body must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2DecompressRejectsXC1GeP()
    {
        // Zcash convention: x.c1 occupies the first 48 bytes. Encode
        // x.c1 = p exactly (top 3 bits zero, leaving flag bits free)
        // and confirm the c1 >= p branch trips.
        BigInteger p = BLS12_381G1.Q;
        byte[] bad = new byte[96];
        byte[] pBytes = BigIntegers.asUnsignedByteArray(48, p);
        System.arraycopy(pBytes, 0, bad, 0, 48);
        bad[0] |= (byte)0x80;
        try
        {
            BLS12_381Serialization.decompressG2(bad);
            fail("G2 x.c1 == p must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2DecompressRejectsXC0GeP()
    {
        // x.c0 occupies bytes [48, 96). Set x.c0 = p with x.c1 = 0 and
        // the compressed flag set. Confirms the c0 >= p branch.
        BigInteger p = BLS12_381G1.Q;
        byte[] bad = new byte[96];
        bad[0] = (byte)0x80;  // compressed flag; rest of c1 is zero
        byte[] pBytes = BigIntegers.asUnsignedByteArray(48, p);
        System.arraycopy(pBytes, 0, bad, 48, 48);
        try
        {
            BLS12_381Serialization.decompressG2(bad);
            fail("G2 x.c0 == p must be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testG2DecompressRejectsNonCurveX()
    {
        // G2 analog of testG1DecompressRejectsNonCurveX: pick random x
        // in Fp^2 where x^3 + 4(1+I) is not a square. The G2 cofactor is
        // huge so the curve density is low — only ~half of x's in Fp^2
        // yield curve points. 32 attempts comfortably finds one.
        SecureRandom rng = new SecureRandom(new byte[]{42});
        BigInteger p = BLS12_381G1.Q;
        for (int attempt = 0; attempt < 32; ++attempt)
        {
            BigInteger c0 = new BigInteger(p.bitLength(), rng).mod(p);
            BigInteger c1 = new BigInteger(p.bitLength(), rng).mod(p);
            Fp2Element x = Fp2Element.of(c0, c1);
            Fp2Element rhs = x.square().mul(x).add(BLS12_381G2Point.B);
            if (rhs.isSquare())
            {
                continue;
            }
            byte[] enc = new byte[96];
            byte[] c1Bytes = BigIntegers.asUnsignedByteArray(48, c1);
            byte[] c0Bytes = BigIntegers.asUnsignedByteArray(48, c0);
            System.arraycopy(c1Bytes, 0, enc, 0, 48);
            System.arraycopy(c0Bytes, 0, enc, 48, 48);
            enc[0] |= (byte)0x80;  // compressed
            try
            {
                BLS12_381Serialization.decompressG2(enc);
                fail("non-curve G2 x in Fp^2 must be rejected");
            }
            catch (IllegalArgumentException expected)
            {
            }
            return;
        }
        fail("could not find an x in Fp^2 with non-square x^3 + 4(1+I) in 32 attempts");
    }

    public void testG2DecompressYSignFlipDecodesNegate()
    {
        // G2 analog of testG1DecompressYSignFlipDecodesNegate.
        BLS12_381G2Point g = BLS12_381G2.getGenerator();
        byte[] enc = BLS12_381Serialization.compressG2(g);
        enc[0] ^= (byte)0x20;
        BLS12_381G2Point decoded = BLS12_381Serialization.decompressG2(enc);
        assertEquals("G2 y-sign bit flip must decode to the negate", g.negate(), decoded);
    }
}
