package org.bouncycastle.crypto.signers.lms;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.HSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.params.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.signers.HSSSigner;
import org.bouncycastle.crypto.signers.LMSSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * Coverage of the message buffer LMSSigner / HSSSigner carry as org.bouncycastle.crypto.Signer
 * implementations, and of the rule that the buffered and one-shot forms must not be mixed.
 */
public class BufferedMessageTests
    extends TestCase
{
    private static final byte[] MSG = Strings.toByteArray("the quick brown fox");
    private static final byte[] A = Strings.toByteArray("A");
    private static final byte[] B = Strings.toByteArray("B");

    // ---------------------------------------------------------------- helpers

    private static byte[] seedFor(int n)
    {
        byte[] seed = new byte[64];
        for (int i = 0; i != seed.length; i++)
        {
            seed[i] = (byte)(n * 31 + i);
        }
        return seed;
    }

    private static SecureRandom fixedRandom(byte[] seed)
    {
        return new FixedSecureRandom(new FixedSecureRandom.Source[]
            { new FixedSecureRandom.Data(Arrays.concatenate(seed, seed, seed, seed)) });
    }

    private static LMSParameters lmsParams()
    {
        return new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1);
    }

    private static AsymmetricCipherKeyPair lmsKeyPair(int n)
    {
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(new LMSKeyGenerationParameters(lmsParams(), fixedRandom(seedFor(n))));
        return gen.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair hssKeyPair(int n)
    {
        HSSKeyPairGenerator gen = new HSSKeyPairGenerator();
        gen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{ lmsParams(), lmsParams() }, fixedRandom(seedFor(n))));
        return gen.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair singleLevelHssKeyPair(int n)
    {
        HSSKeyPairGenerator gen = new HSSKeyPairGenerator();
        gen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{ lmsParams() }, fixedRandom(seedFor(n))));
        return gen.generateKeyPair();
    }

    private static long indexOf(AsymmetricCipherKeyPair kp)
    {
        return kp.getPrivate() instanceof HSSPrivateKeyParameters
            ? ((HSSPrivateKeyParameters)kp.getPrivate()).getIndex()
            : ((LMSPrivateKeyParameters)kp.getPrivate()).getIndex();
    }

    // ------------------------------------------------- case 1: streaming == one-shot

    public void testStreamingMatchesOneShotLMS()
    {
        // two identical keys, so the one-time key each signature spends is the same one
        LMSSigner streamed = new LMSSigner();
        streamed.init(true, lmsKeyPair(1).getPrivate());
        streamed.update(MSG, 0, MSG.length);

        LMSSigner oneShot = new LMSSigner();
        oneShot.init(true, lmsKeyPair(1).getPrivate());

        assertTrue("streamed and one-shot signatures differ",
            Arrays.areEqual(streamed.generateSignature(), oneShot.generateSignature(MSG)));
    }

    public void testStreamingMatchesOneShotHSS()
    {
        HSSSigner streamed = new HSSSigner();
        streamed.init(true, hssKeyPair(2).getPrivate());
        streamed.update(MSG, 0, MSG.length);

        HSSSigner oneShot = new HSSSigner();
        oneShot.init(true, hssKeyPair(2).getPrivate());

        assertTrue("streamed and one-shot signatures differ",
            Arrays.areEqual(streamed.generateSignature(), oneShot.generateSignature(MSG)));
    }

    // ------------------------------------------- case 2: update(byte) == update(byte[],off,len)

    public void testSingleByteUpdateMatchesLMS()
    {
        LMSSigner byByte = new LMSSigner();
        byByte.init(true, lmsKeyPair(3).getPrivate());
        for (int i = 0; i != MSG.length; i++)
        {
            byByte.update(MSG[i]);
        }

        LMSSigner byBlock = new LMSSigner();
        byBlock.init(true, lmsKeyPair(3).getPrivate());
        byBlock.update(MSG, 0, MSG.length);

        assertTrue("update(byte) and update(byte[],off,len) disagree",
            Arrays.areEqual(byByte.generateSignature(), byBlock.generateSignature()));
    }

    public void testSingleByteUpdateMatchesHSS()
    {
        HSSSigner byByte = new HSSSigner();
        byByte.init(true, hssKeyPair(4).getPrivate());
        for (int i = 0; i != MSG.length; i++)
        {
            byByte.update(MSG[i]);
        }

        HSSSigner byBlock = new HSSSigner();
        byBlock.init(true, hssKeyPair(4).getPrivate());
        byBlock.update(MSG, 0, MSG.length);

        assertTrue("update(byte) and update(byte[],off,len) disagree",
            Arrays.areEqual(byByte.generateSignature(), byBlock.generateSignature()));
    }

    // ------------------------------------------------------ case 3: split updates concatenate

    public void testSplitUpdatesConcatenateLMS()
    {
        LMSSigner split = new LMSSigner();
        split.init(true, lmsKeyPair(5).getPrivate());
        split.update(A, 0, A.length);
        split.update(B, 0, B.length);

        LMSSigner whole = new LMSSigner();
        whole.init(true, lmsKeyPair(5).getPrivate());

        assertTrue("split updates did not concatenate", Arrays.areEqual(
            split.generateSignature(), whole.generateSignature(Arrays.concatenate(A, B))));
    }

    public void testSplitUpdatesConcatenateHSS()
    {
        HSSSigner split = new HSSSigner();
        split.init(true, hssKeyPair(6).getPrivate());
        split.update(A, 0, A.length);
        split.update(B, 0, B.length);

        HSSSigner whole = new HSSSigner();
        whole.init(true, hssKeyPair(6).getPrivate());

        assertTrue("split updates did not concatenate", Arrays.areEqual(
            split.generateSignature(), whole.generateSignature(Arrays.concatenate(A, B))));
    }

    // ---------------------------------------------------------- case 4: sub-range update

    public void testSubRangeUpdateLMS()
    {
        byte[] padded = Arrays.concatenate(A, MSG, B);

        LMSSigner sub = new LMSSigner();
        sub.init(true, lmsKeyPair(7).getPrivate());
        sub.update(padded, A.length, MSG.length);

        LMSSigner exact = new LMSSigner();
        exact.init(true, lmsKeyPair(7).getPrivate());

        assertTrue("sub-range update did not sign the sub-range alone",
            Arrays.areEqual(sub.generateSignature(), exact.generateSignature(MSG)));
    }

    public void testSubRangeUpdateHSS()
    {
        byte[] padded = Arrays.concatenate(A, MSG, B);

        HSSSigner sub = new HSSSigner();
        sub.init(true, hssKeyPair(8).getPrivate());
        sub.update(padded, A.length, MSG.length);

        HSSSigner exact = new HSSSigner();
        exact.init(true, hssKeyPair(8).getPrivate());

        assertTrue("sub-range update did not sign the sub-range alone",
            Arrays.areEqual(sub.generateSignature(), exact.generateSignature(MSG)));
    }

    // -------------------------------------------------------------- case 5: empty message

    public void testEmptyMessageLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(9);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature();          // nothing absorbed

        LMSSigner reference = new LMSSigner();
        reference.init(true, lmsKeyPair(9).getPrivate());
        assertTrue("empty buffer did not sign the empty message",
            Arrays.areEqual(sig, reference.generateSignature(new byte[0])));

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("empty-message signature did not verify", verifier.verifySignature(sig));
    }

    public void testEmptyMessageHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(10);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature();

        HSSSigner reference = new HSSSigner();
        reference.init(true, hssKeyPair(10).getPrivate());
        assertTrue("empty buffer did not sign the empty message",
            Arrays.areEqual(sig, reference.generateSignature(new byte[0])));

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("empty-message signature did not verify", verifier.verifySignature(sig));
    }

    // ------------------------------------------------------------ case 6: reset() discards

    public void testResetDiscardsLMS()
    {
        LMSSigner signer = new LMSSigner();
        signer.init(true, lmsKeyPair(11).getPrivate());
        signer.update(A, 0, A.length);
        signer.reset();
        signer.update(B, 0, B.length);

        LMSSigner reference = new LMSSigner();
        reference.init(true, lmsKeyPair(11).getPrivate());

        assertTrue("reset() did not discard the buffered message",
            Arrays.areEqual(signer.generateSignature(), reference.generateSignature(B)));
    }

    public void testResetDiscardsHSS()
    {
        HSSSigner signer = new HSSSigner();
        signer.init(true, hssKeyPair(12).getPrivate());
        signer.update(A, 0, A.length);
        signer.reset();
        signer.update(B, 0, B.length);

        HSSSigner reference = new HSSSigner();
        reference.init(true, hssKeyPair(12).getPrivate());

        assertTrue("reset() did not discard the buffered message",
            Arrays.areEqual(signer.generateSignature(), reference.generateSignature(B)));
    }

    // ------------------------------------------------- case 7: generateSignature() consumes

    public void testGenerateSignatureConsumesLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(13);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);
        signer.generateSignature();
        byte[] second = signer.generateSignature();       // nothing added since

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("second signature was not over the empty message",
            verifier.verifySignature(new byte[0], second));
        verifier.init(false, kp.getPublic());
        assertFalse("second signature repeated the consumed message",
            verifier.verifySignature(A, second));
    }

    public void testVerifySignatureConsumesLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(14);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sigA = signer.generateSignature(A);

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(A, 0, A.length);
        assertTrue("streamed verify of A failed", verifier.verifySignature(sigA));
        // the buffer is consumed, so this is now a verify of sigA against the empty message
        assertFalse("verify did not consume the buffered message", verifier.verifySignature(sigA));
    }

    public void testGenerateSignatureConsumesHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(15);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);
        signer.generateSignature();
        byte[] second = signer.generateSignature();

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("second signature was not over the empty message",
            verifier.verifySignature(new byte[0], second));
        verifier.init(false, kp.getPublic());
        assertFalse("second signature repeated the consumed message",
            verifier.verifySignature(A, second));
    }

    // ----------------------------------------------------- case 8: init() clears the buffer

    public void testInitClearsBufferForSigningLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(16);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);                    // abandoned attempt
        signer.init(true, kp.getPrivate());
        signer.update(B, 0, B.length);
        byte[] sig = signer.generateSignature();

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("signature was not over B alone", verifier.verifySignature(B, sig));
        verifier.init(false, kp.getPublic());
        assertFalse("init() did not clear the buffer",
            verifier.verifySignature(Arrays.concatenate(A, B), sig));
    }

    public void testInitClearsBufferForVerificationLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(17);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature(B);

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(A, 0, A.length);                  // abandoned attempt
        verifier.init(false, kp.getPublic());
        verifier.update(B, 0, B.length);
        assertTrue("init() did not clear the buffer on a verification init",
            verifier.verifySignature(sig));
    }

    public void testInitClearsBufferForSigningHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(18);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);
        signer.init(true, kp.getPrivate());
        signer.update(B, 0, B.length);
        byte[] sig = signer.generateSignature();

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("signature was not over B alone", verifier.verifySignature(B, sig));
        verifier.init(false, kp.getPublic());
        assertFalse("init() did not clear the buffer",
            verifier.verifySignature(Arrays.concatenate(A, B), sig));
    }

    public void testInitClearsBufferForVerificationHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(19);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature(B);

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(A, 0, A.length);
        verifier.init(false, kp.getPublic());
        verifier.update(B, 0, B.length);
        assertTrue("init() did not clear the buffer on a verification init",
            verifier.verifySignature(sig));
    }

    // -------------------------------------------------------- case 9: mixing is refused

    public void testMixingRefusedOnSignLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(20);
        long index = indexOf(kp);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);

        try
        {
            signer.generateSignature(B);
            fail("one-shot sign with a buffered message present was not refused");
        }
        catch (IllegalStateException e)
        {
            assertEquals("buffered message present: call reset() or use generateSignature()", e.getMessage());
        }

        // the security-relevant half: a refused call must not spend a one-time key
        assertEquals("refused sign rolled the index", index, indexOf(kp));

        signer.reset();
        assertNotNull("one-shot sign refused after an explicit reset()", signer.generateSignature(B));
    }

    public void testMixingRefusedOnVerifyLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(21);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature(B);

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(A, 0, A.length);

        try
        {
            verifier.verifySignature(B, sig);
            fail("one-shot verify with a buffered message present was not refused");
        }
        catch (IllegalStateException e)
        {
            assertEquals("buffered message present: call reset() or use verifySignature(byte[])", e.getMessage());
        }

        verifier.reset();
        assertTrue("one-shot verify refused after an explicit reset()", verifier.verifySignature(B, sig));
    }

    public void testMixingRefusedOnSignHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(22);
        long index = indexOf(kp);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);

        try
        {
            signer.generateSignature(B);
            fail("one-shot sign with a buffered message present was not refused");
        }
        catch (IllegalStateException e)
        {
            assertEquals("buffered message present: call reset() or use generateSignature()", e.getMessage());
        }

        assertEquals("refused sign rolled the index", index, indexOf(kp));

        signer.reset();
        assertNotNull("one-shot sign refused after an explicit reset()", signer.generateSignature(B));
    }

    public void testMixingRefusedOnVerifyHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(23);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature(B);

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(A, 0, A.length);

        try
        {
            verifier.verifySignature(B, sig);
            fail("one-shot verify with a buffered message present was not refused");
        }
        catch (IllegalStateException e)
        {
            assertEquals("buffered message present: call reset() or use verifySignature(byte[])", e.getMessage());
        }

        verifier.reset();
        assertTrue("one-shot verify refused after an explicit reset()", verifier.verifySignature(B, sig));
    }

    // ------------------------------------- case 10: a failed streaming verify leaves no residue

    public void testFailedVerifyLeavesBufferEmptyLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(24);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature(B);

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(A, 0, A.length);
        assertFalse("verify of the wrong message succeeded", verifier.verifySignature(sig));

        // if the failed verify had left 'A' behind, this would verify B against "AB"
        verifier.update(B, 0, B.length);
        assertTrue("a failed verify poisoned the next one", verifier.verifySignature(sig));
    }

    public void testFailedVerifyLeavesBufferEmptyHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(25);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature(B);

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(A, 0, A.length);
        assertFalse("verify of the wrong message succeeded", verifier.verifySignature(sig));

        verifier.update(B, 0, B.length);
        assertTrue("a failed verify poisoned the next one", verifier.verifySignature(sig));
    }

    // ------------------------- case 11: buffer operations do not disturb the stateful index

    public void testBufferOperationsDoNotRollIndexLMS()
    {
        AsymmetricCipherKeyPair kp = lmsKeyPair(26);
        long index = indexOf(kp);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);
        signer.update(B[0]);
        signer.reset();
        signer.init(true, kp.getPrivate());
        signer.update(MSG, 0, MSG.length);

        assertEquals("buffering rolled the index", index, indexOf(kp));

        signer.generateSignature();
        assertEquals("signing did not roll the index by one", index + 1, indexOf(kp));
    }

    public void testBufferOperationsDoNotRollIndexHSS()
    {
        AsymmetricCipherKeyPair kp = hssKeyPair(27);
        long index = indexOf(kp);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);
        signer.update(B[0]);
        signer.reset();
        signer.init(true, kp.getPrivate());
        signer.update(MSG, 0, MSG.length);

        assertEquals("buffering rolled the index", index, indexOf(kp));

        signer.generateSignature();
        assertEquals("signing did not roll the index by one", index + 1, indexOf(kp));
    }

    // ------------- the single-level HSS key LMSSigner accepts drives the same buffer

    public void testSingleLevelHssThroughLmsSigner()
    {
        AsymmetricCipherKeyPair kp = singleLevelHssKeyPair(28);
        long index = indexOf(kp);

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(A, 0, A.length);

        try
        {
            signer.generateSignature(B);
            fail("one-shot sign with a buffered message present was not refused");
        }
        catch (IllegalStateException e)
        {
            assertEquals("buffered message present: call reset() or use generateSignature()", e.getMessage());
        }

        assertEquals("refused sign rolled the index", index, indexOf(kp));

        signer.init(true, kp.getPrivate());               // init clears the abandoned 'A'
        signer.update(B, 0, B.length);
        byte[] sig = signer.generateSignature();

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("signature was not over B alone", verifier.verifySignature(B, sig));
    }
}
