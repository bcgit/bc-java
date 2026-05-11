package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381Serialization;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
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
}
