package org.bouncycastle.jcajce.provider.kdf.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;

import javax.crypto.KDF;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator;
import org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters;
import org.bouncycastle.crypto.params.KDFFeedbackParameters;
import org.bouncycastle.jcajce.spec.KBKDFParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * The SP 800-108 KBKDF services: a CAVP counter-mode vector (KDFCTR_gen.rsp, HMAC_SHA256, counter before
 * the fixed input, 8-bit counter), the standard fixed-input layout, and each mode against the light-weight
 * generators the CAVP suites already verify.
 */
public class KBKDFTest
    extends TestCase
{
    // CAVS 14.4 KDFCTR_gen.rsp [PRF=HMAC_SHA256] [CTRLOCATION=BEFORE_FIXED] [RLEN=8_BITS] COUNT=0
    private static final byte[] CAVP_KI = Hex.decode("3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83");
    private static final byte[] CAVP_FIXED = Hex.decode("98e9988bb4cc8b34d7922e1c68ad692ba2a1d9ae15149571675f17a77ad49e80c8d2a85e831a26445b1f0ff44d7084a17206b4896c8112daad18605a");
    private static final byte[] CAVP_KO = Hex.decode("6c037652990674a07844732d0ad985f9");

    private static final byte[] KI = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] LABEL = Strings.toByteArray("KBKDF test label");
    private static final byte[] CONTEXT = Strings.toByteArray("KBKDF test context");
    private static final byte[] IV = Hex.decode("deadbeefcafebabe");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testCounterCavpVector()
        throws Exception
    {
        KDF kdf = KDF.getInstance("KBKDF-COUNTER-HMACSHA256", "BC");

        assertTrue(Arrays.areEqual(CAVP_KO, kdf.deriveData(new KBKDFParameterSpec(CAVP_KI, CAVP_FIXED, 16, 8))));
    }

    public void testStandardLayout()
        throws Exception
    {
        KDF kdf = KDF.getInstance("KBKDF-COUNTER-HMACSHA256", "BC");

        byte[] fixed = Arrays.concatenate(LABEL, new byte[1], CONTEXT, Pack.intToBigEndian(40 * 8));

        byte[] viaLayout = kdf.deriveData(new KBKDFParameterSpec(KI, LABEL, CONTEXT, 40));
        byte[] viaRaw = kdf.deriveData(new KBKDFParameterSpec(KI, fixed, 40, 32));

        assertTrue(Arrays.areEqual(viaLayout, viaRaw));

        KDFCounterBytesGenerator ref = new KDFCounterBytesGenerator(new HMac(new SHA256Digest()));
        ref.init(new KDFCounterParameters(KI, null, fixed, 32));
        byte[] expected = new byte[40];
        ref.generateBytes(expected, 0, 40);

        assertTrue(Arrays.areEqual(expected, viaLayout));

        // L is part of the fixed input, so a different output length is not a prefix
        assertFalse(Arrays.areEqual(Arrays.copyOf(viaLayout, 32), kdf.deriveData(new KBKDFParameterSpec(KI, LABEL, CONTEXT, 32))));
    }

    public void testFeedbackAndPipeline()
        throws Exception
    {
        byte[] fixed = Arrays.concatenate(LABEL, new byte[1], CONTEXT, Pack.intToBigEndian(64 * 8));

        KDFFeedbackBytesGenerator fb = new KDFFeedbackBytesGenerator(new HMac(new SHA512Digest()));
        fb.init(KDFFeedbackParameters.createWithCounter(KI, IV, fixed, 32));
        byte[] expected = new byte[64];
        fb.generateBytes(expected, 0, 64);
        assertTrue(Arrays.areEqual(expected, KDF.getInstance("KBKDF-FEEDBACK-HMACSHA512", "BC").deriveData(new KBKDFParameterSpec(KI, LABEL, CONTEXT, 64).withIV(IV))));

        fb.init(KDFFeedbackParameters.createWithoutCounter(KI, IV, fixed));
        fb.generateBytes(expected, 0, 64);
        assertTrue(Arrays.areEqual(expected, KDF.getInstance("KBKDF-FEEDBACK-HMACSHA512", "BC").deriveData(new KBKDFParameterSpec(KI, fixed, 64, 0).withIV(IV))));

        KDFDoublePipelineIterationBytesGenerator dp = new KDFDoublePipelineIterationBytesGenerator(new HMac(new SHA256Digest()));
        dp.init(KDFDoublePipelineIterationParameters.createWithCounter(KI, fixed, 32));
        dp.generateBytes(expected, 0, 64);
        assertTrue(Arrays.areEqual(expected, KDF.getInstance("KBKDF-PIPELINE-HMACSHA256", "BC").deriveData(new KBKDFParameterSpec(KI, LABEL, CONTEXT, 64))));

        dp.init(KDFDoublePipelineIterationParameters.createWithoutCounter(KI, fixed));
        dp.generateBytes(expected, 0, 64);
        assertTrue(Arrays.areEqual(expected, KDF.getInstance("KBKDF-PIPELINE-HMACSHA256", "BC").deriveData(new KBKDFParameterSpec(KI, fixed, 64, 0))));

        assertEquals(24, KDF.getInstance("KBKDF-COUNTER-HMACSHA384", "BC").deriveKey("AES", new KBKDFParameterSpec(KI, LABEL, CONTEXT, 24)).getEncoded().length);
        assertEquals(24, KDF.getInstance("KBKDF-FEEDBACK-HMACSHA384", "BC").deriveKey("AES", new KBKDFParameterSpec(KI, LABEL, CONTEXT, 24)).getEncoded().length);
        assertEquals(24, KDF.getInstance("KBKDF-PIPELINE-HMACSHA384", "BC").deriveKey("AES", new KBKDFParameterSpec(KI, LABEL, CONTEXT, 24)).getEncoded().length);
        assertEquals(24, KDF.getInstance("KBKDF-COUNTER-HMACSHA512", "BC").deriveKey("AES", new KBKDFParameterSpec(KI, LABEL, CONTEXT, 24)).getEncoded().length);
        assertEquals(24, KDF.getInstance("KBKDF-FEEDBACK-HMACSHA256", "BC").deriveKey("AES", new KBKDFParameterSpec(KI, LABEL, CONTEXT, 24)).getEncoded().length);
        assertEquals(24, KDF.getInstance("KBKDF-PIPELINE-HMACSHA512", "BC").deriveKey("AES", new KBKDFParameterSpec(KI, LABEL, CONTEXT, 24)).getEncoded().length);
    }

    public void testErrors()
        throws Exception
    {
        try
        {
            KDF.getInstance("KBKDF-COUNTER-HMACSHA256", "BC").deriveData(new KBKDFParameterSpec(KI, LABEL, 32, 0));
            fail("counter mode without a counter accepted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // javax.crypto.KDF replaces the SPI's message with its own when the provider was named
        }

        try
        {
            new KBKDFParameterSpec(KI, LABEL, 32, 12);
            fail("12-bit counter accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("counterBits must be 0, 8, 16, 24 or 32", e.getMessage());
        }
    }
}
