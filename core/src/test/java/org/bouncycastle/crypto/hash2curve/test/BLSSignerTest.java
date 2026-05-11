package org.bouncycastle.crypto.hash2curve.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.bls.BLS12_381ProofOfPossession;
import org.bouncycastle.crypto.generators.BLSKeyPairGenerator;
import org.bouncycastle.crypto.params.BLSKeyGenerationParameters;
import org.bouncycastle.crypto.params.BLSParameters;
import org.bouncycastle.crypto.signers.BLSSigner;
import org.bouncycastle.util.Strings;

public class BLSSignerTest
    extends TestCase
{
    private static AsymmetricCipherKeyPair makeKeyPair(int seed)
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        gen.init(new BLSKeyGenerationParameters(
            new SecureRandom(new byte[]{(byte)seed}), BLSParameters.bls12_381));
        return gen.generateKeyPair();
    }

    public void testSignVerifyRoundTrip()
        throws CryptoException
    {
        AsymmetricCipherKeyPair kp = makeKeyPair(1);
        byte[] msg = Strings.toUTF8ByteArray("hello, BLS Signer");

        BLSSigner signer = new BLSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();
        assertEquals("compressed G2 signature is 96 bytes", 96, sig.length);

        BLSSigner verifier = new BLSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(msg, 0, msg.length);
        assertTrue(verifier.verifySignature(sig));
    }

    public void testStreamingUpdate()
        throws CryptoException
    {
        AsymmetricCipherKeyPair kp = makeKeyPair(2);
        byte[] msg = Strings.toUTF8ByteArray("multipart message via update() calls");

        BLSSigner signer = new BLSSigner();
        signer.init(true, kp.getPrivate());
        // Feed the message byte-by-byte
        for (int i = 0; i < msg.length; ++i)
        {
            signer.update(msg[i]);
        }
        byte[] sig = signer.generateSignature();

        BLSSigner verifier = new BLSSigner();
        verifier.init(false, kp.getPublic());
        // Feed in two chunks
        int half = msg.length / 2;
        verifier.update(msg, 0, half);
        verifier.update(msg, half, msg.length - half);
        assertTrue("any decomposition of update() calls must verify",
            verifier.verifySignature(sig));
    }

    public void testVerifyRejectsWrongMessage()
        throws CryptoException
    {
        AsymmetricCipherKeyPair kp = makeKeyPair(3);
        byte[] original = Strings.toUTF8ByteArray("original");

        BLSSigner signer = new BLSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(original, 0, original.length);
        byte[] sig = signer.generateSignature();

        byte[] tampered = Strings.toUTF8ByteArray("tampered");
        BLSSigner verifier = new BLSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(tampered, 0, tampered.length);
        assertFalse(verifier.verifySignature(sig));
    }

    public void testVerifyRejectsWrongKey()
        throws CryptoException
    {
        AsymmetricCipherKeyPair kp1 = makeKeyPair(4);
        AsymmetricCipherKeyPair kp2 = makeKeyPair(5);
        byte[] msg = Strings.toUTF8ByteArray("test");

        BLSSigner signer = new BLSSigner();
        signer.init(true, kp1.getPrivate());
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();

        BLSSigner verifier = new BLSSigner();
        verifier.init(false, kp2.getPublic());
        verifier.update(msg, 0, msg.length);
        assertFalse(verifier.verifySignature(sig));
    }

    public void testVerifyRejectsMalformedSignature()
    {
        AsymmetricCipherKeyPair kp = makeKeyPair(6);
        BLSSigner verifier = new BLSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(new byte[]{1, 2, 3}, 0, 3);
        assertFalse("non-96-byte input must be rejected, not throw",
            verifier.verifySignature(new byte[]{0, 1, 2}));
    }

    public void testCustomDstSelectsPopSuite()
        throws CryptoException
    {
        // With the POP DST, BLSSigner should byte-match
        // BLS12_381ProofOfPossession.sign output.
        AsymmetricCipherKeyPair kp = makeKeyPair(7);
        byte[] msg = Strings.toUTF8ByteArray("pop-suite signer");

        BLSSigner signer = new BLSSigner(BLS12_381ProofOfPossession.DST);
        signer.init(true, kp.getPrivate());
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();

        // Verify under matching POP DST.
        BLSSigner verifier = new BLSSigner(BLS12_381ProofOfPossession.DST);
        verifier.init(false, kp.getPublic());
        verifier.update(msg, 0, msg.length);
        assertTrue(verifier.verifySignature(sig));

        // Same sig must NOT verify under BasicScheme DST.
        BLSSigner crossVerifier = new BLSSigner();
        crossVerifier.init(false, kp.getPublic());
        crossVerifier.update(msg, 0, msg.length);
        assertFalse("POP-signed sig must not verify under BasicScheme DST",
            crossVerifier.verifySignature(sig));
    }

    public void testResetClearsBufferBetweenSigns()
        throws CryptoException
    {
        AsymmetricCipherKeyPair kp = makeKeyPair(8);
        BLSSigner signer = new BLSSigner();
        signer.init(true, kp.getPrivate());

        // First sign of message A.
        byte[] msgA = Strings.toUTF8ByteArray("aaaa");
        signer.update(msgA, 0, msgA.length);
        byte[] sigA = signer.generateSignature();  // implicitly resets

        // Second sign of message B — must NOT include leftover A bytes.
        byte[] msgB = Strings.toUTF8ByteArray("bbbb");
        signer.update(msgB, 0, msgB.length);
        byte[] sigB = signer.generateSignature();

        // sigB should verify as a signature on msgB alone.
        BLSSigner verifier = new BLSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(msgB, 0, msgB.length);
        assertTrue("sigB must verify on msgB after generateSignature reset",
            verifier.verifySignature(sigB));

        // sigB must NOT verify under msgA + msgB concatenation.
        BLSSigner negVerifier = new BLSSigner();
        negVerifier.init(false, kp.getPublic());
        negVerifier.update(msgA, 0, msgA.length);
        negVerifier.update(msgB, 0, msgB.length);
        assertFalse(negVerifier.verifySignature(sigB));
    }

    public void testInitRejectsWrongKeyType()
    {
        AsymmetricCipherKeyPair kp = makeKeyPair(9);
        BLSSigner signer = new BLSSigner();
        try
        {
            // Public key for signing should be rejected.
            signer.init(true, kp.getPublic());
            fail("signing init with public key should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
        try
        {
            // Private key for verification should be rejected.
            new BLSSigner().init(false, kp.getPrivate());
            fail("verifying init with private key should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testGenerateBeforeInitFails()
    {
        BLSSigner signer = new BLSSigner();
        try
        {
            signer.generateSignature();
            fail("generateSignature before init should fail");
        }
        catch (IllegalStateException expected)
        {
        }
        catch (CryptoException unexpected)
        {
            fail("expected IllegalStateException, got CryptoException");
        }
    }
}
