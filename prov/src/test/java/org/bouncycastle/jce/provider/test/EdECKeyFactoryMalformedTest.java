package org.bouncycastle.jce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for R-KEYFAC-1. The edec KeyFactorySpi fast path in
 * {@code engineGeneratePublic(X509EncodedKeySpec)} read the algorithm discriminator and the
 * AlgorithmIdentifier parameters at the fixed offsets {@code enc[8..10]} with no length guard, so:
 * <ul>
 *   <li>a short X509EncodedKeySpec ({@code < 11} bytes) threw an ArrayIndexOutOfBoundsException; and</li>
 *   <li>a full-length key whose 32/57-byte point is not on the curve threw an
 *       IllegalArgumentException from the underlying point parser.</li>
 * </ul>
 * Both are RuntimeExceptions that escaped the declared {@code throws InvalidKeySpecException}
 * contract. This test asserts every such malformed input is now reported as an
 * InvalidKeySpecException, while a valid key still decodes through the same fast path.
 */
public class EdECKeyFactoryMalformedTest
    extends SimpleTest
{
    // 302a300506032b6570032100 = the Ed25519 SubjectPublicKeyInfo prefix (SEQ / AlgorithmIdentifier /
    // BIT STRING header); the trailing 32 bytes are 0xFF, giving y >= p so the point is invalid.
    private static final byte[] INVALID_ED25519_SPKI = Hex.decode(
        "302a300506032b6570032100"
      + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    public String getName()
    {
        return "EdECKeyFactoryMalformed";
    }

    public void performTest()
        throws Exception
    {
        // too short to hold the discriminator byte enc[8] (was AIOOBE)
        checkRejected("Ed25519", new byte[]{ 0x30, 0x00 });
        checkRejected("Ed25519", new byte[]{ 0x30, 0x06, 0x30, 0x03, 0x06, 0x01, 0x00, 0x00 });

        // the generic (specificBase == 0) factories enter the fast path regardless of enc[8] and
        // then read enc[9]/enc[10] before the switch - exercise those reads too (was AIOOBE)
        checkRejected("XDH", new byte[]{ 0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e });
        checkRejected("EdDSA", new byte[]{ 0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x2b, 0x65, 0x70, 0x05 });

        // well-formed length and prefix, but the encoded point is not on the curve (was IAE)
        checkRejected("Ed25519", INVALID_ED25519_SPKI);

        // a valid key must still decode through the optimised path unchanged
        checkValidRoundTrip();
    }

    private void checkRejected(String algorithm, byte[] enc)
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(algorithm, "BC");
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(enc));
            fail("malformed " + algorithm + " public key not rejected");
        }
        catch (InvalidKeySpecException e)
        {
            // expected: the declared engineGeneratePublic contract
        }
    }

    private void checkValidRoundTrip()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
        byte[] enc = kp.getPublic().getEncoded();

        PublicKey decoded = KeyFactory.getInstance("Ed25519", "BC").generatePublic(new X509EncodedKeySpec(enc));

        if (!Arrays.areEqual(enc, decoded.getEncoded()))
        {
            fail("valid Ed25519 public key did not round-trip through KeyFactory");
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new EdECKeyFactoryMalformedTest());
    }
}
