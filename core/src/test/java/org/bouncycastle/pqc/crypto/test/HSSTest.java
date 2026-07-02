package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSSigner;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

public class HSSTest
    extends TestCase
{
    public void testOneLevelKeyGenAndSign()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        AsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

        kpGen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        HSSSigner signer = new HSSSigner();

        signer.init(true, kp.getPrivate());
       
        byte[] sig = signer.generateSignature(msg);

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg, sig));

        HSSPublicKeyParameters hssPubKey = (HSSPublicKeyParameters)kp.getPublic();

        hssPubKey.generateLMSContext(sig);
    }

    public void testKeyGenAndSign()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        AsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

        kpGen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        HSSSigner signer = new HSSSigner();

        signer.init(true, kp.getPrivate());

        byte[] sig = signer.generateSignature(msg);

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg, sig));
    }

    public void testHssKeyGenAndSign()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        AsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

        kpGen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4),
                new LMSParameters(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4)
            }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        HSSSigner signer = new HSSSigner();

        signer.init(true, kp.getPrivate());

        byte[] sig = signer.generateSignature(msg);

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg, sig));
    }

    public void testKeyGenAndUsage()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        AsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

        kpGen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            }, new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        HSSPrivateKeyParameters privKey = (HSSPrivateKeyParameters)kp.getPrivate();

        HSSPublicKeyParameters pubKey = (HSSPublicKeyParameters)kp.getPublic();
        
        LMSParameters lmsParam = pubKey.getLMSPublicKey().getLMSParameters();

        assertEquals(LMSigParameters.lms_sha256_n32_h5, lmsParam.getLMSigParam());
        assertEquals(LMOtsParameters.sha256_n32_w4, lmsParam.getLMOTSParam());

        HSSSigner signer = new HSSSigner();

        signer.init(true, privKey);

        assertEquals(1024, privKey.getUsagesRemaining());
        assertEquals(2, privKey.getLMSParameters().length);

        for (int i = 1; i <= 1024; i++)
        {
            signer.generateSignature(msg);

            assertEquals(i, privKey.getIndex());
            assertEquals(1024 - i, privKey.getUsagesRemaining());
        }
    }

    public void testKeyGenAndSignTwoSigsWithShard()
        throws Exception
    {
        byte[] msg1 = Strings.toByteArray("Hello, world!");
        byte[] msg2 = Strings.toByteArray("Now is the time");

        AsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();

        kpGen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            }, new SecureRandom()));
        
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        HSSPrivateKeyParameters privKey = ((HSSPrivateKeyParameters)kp.getPrivate()).extractKeyShard(2);

        assertEquals(2, ((HSSPrivateKeyParameters)kp.getPrivate()).getIndex());

        HSSSigner signer = new HSSSigner();

        assertEquals(0, privKey.getIndex());

        signer.init(true, privKey);

        byte[] sig1 = signer.generateSignature(msg1);

        assertEquals(1, privKey.getIndex());

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg1, sig1));

        signer.init(true, privKey);

        byte[] sig = signer.generateSignature(msg2);

        assertEquals(2, privKey.getIndex());

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg2, sig));

        try
        {
            sig = signer.generateSignature(msg2);
            fail("no exception");
        }
        catch (ExhaustedPrivateKeyException e)
        {
            assertEquals("hss private key shard is exhausted", e.getMessage());
        }

        signer.init(true, ((HSSPrivateKeyParameters)kp.getPrivate()));

        sig = signer.generateSignature(msg1);

        assertEquals(3, ((HSSPrivateKeyParameters)kp.getPrivate()).getIndex());

        assertFalse(Arrays.areEqual(sig1, sig));

        signer.init(false, kp.getPublic());

        assertTrue(signer.verifySignature(msg1, sig1));
    }

    /**
     * RFC 8554 / NIST SP 800-208: HSSPublicKeyParameters.generateLMSContext is the public
     * verify-prep reached from the JCA Signature.verify path and the lightweight HSS verify. A
     * malformed HSS signature whose embedded LM-OTS type code is unknown must be rejected with a
     * clean parse failure, not an unchecked NullPointerException (a remote denial-of-service). See
     * COVERAGE_BUGS_HANDOVER.md finding #17.
     */
    public void testMalformedSignatureUnknownLmOtsType()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpGen = new HSSKeyPairGenerator();
        kpGen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)
            }, new SecureRandom()));
        HSSPublicKeyParameters pubKey = (HSSPublicKeyParameters)kpGen.generateKeyPair().getPublic();

        // lminus (= L-1, so the level-count check passes) || q || unknown LM-OTS type code.
        byte[] malformed = new byte[12];
        Pack.intToBigEndian(pubKey.getL() - 1, malformed, 0);
        Pack.intToBigEndian(0x7FFFFFFF, malformed, 8);

        try
        {
            pubKey.generateLMSContext(malformed);
            fail("malformed signature accepted");
        }
        catch (NullPointerException e)
        {
            fail("unknown LM-OTS type code threw NullPointerException instead of a clean parse failure");
        }
        catch (IllegalStateException e)
        {
            // expected: generateLMSContext wraps the parse IOException as an IllegalStateException.
            assertTrue(e.getCause() instanceof IOException);
        }
    }
}
