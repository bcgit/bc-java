package org.bouncycastle.jcajce.provider.kdf.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.OneStepKDFBytesGenerator;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jcajce.spec.OneStepKDFParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * The SP 800-56C Rev. 2 one-step KDF services, against the values the light-weight OneStepKDFTest checks
 * (independently computed for the HMAC option) and against the light-weight generator for the rest.
 */
public class OneStepKDFTest
    extends TestCase
{
    private static final byte[] Z = Hex.decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    private static final byte[] SALT = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private static final byte[] INFO = Strings.toByteArray("ONESTEP-HMAC test fixed info");

    private static final byte[] HMAC_SHA256 = Hex.decode("24bc85145ba62bec777fc9a700e424d284e090b7dbee40a2a4041f11ef0d73d82e9eca8093eb6ffed2861e4a4c9678cf038024607c4dfe0d5e6824717d45a5017f3a6a0a029c03fef1cfd5f12ccaceb5");
    private static final byte[] HMAC_SHA384 = Hex.decode("fbc8983c68d755a513e7007edb9b8991e0c1039d65d1ff926a260f51ea7599db857d619286c478d2c6e26afef7e92542e0b8c67eff9ee9e09212551f86acbea93b94c344776e667439dfe00dae008f99");
    private static final byte[] HMAC_SHA512 = Hex.decode("34006a6bc2f593e5beefb2c79015a3fe465bcf3b4eaaca318d86c744f91d7ad78d38b445295f2b08da210788fae4eebc667b2f801f69faf81619bc36d8e437b7a98b0cd01beaeadfd762afcb5ad9d973");
    private static final byte[] HMAC_SHA256_NO_SALT = Hex.decode("3de80767ff8a7287ec5110d11862cbcaa1dd6a56806f802e3e9a14d50f7908096053e9e8eb10b5e327b1");
    private static final byte[] HASH_SHA256 = Hex.decode("71156349bad7af2f1890a3b350cec4d54a53f438518b755a219dd258c57022fe82371bf374324fe8f46c505f00d9b4fb");
    private static final byte[] HASH_SHA512 = Hex.decode("d1bb4796ff535e390ff9c3b054317f4383e91327da899b706b9ba865a50cd44e8af451b01f5f6c7dc28311007cd5bf59aa6bd5cc539d0a1d2f2f8c8c05498e8c9d32079a829aca3201f0a178c7eb57cdf01e33d5bd2058607ca25095a9383c93753a4eb5");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testHashOption()
        throws Exception
    {
        assertTrue(Arrays.areEqual(HASH_SHA256, KDF.getInstance("ONESTEP-SHA256", "BC").deriveData(new OneStepKDFParameterSpec(Z, INFO, 48))));
        assertTrue(Arrays.areEqual(HASH_SHA512, KDF.getInstance("ONESTEP-SHA512", "BC").deriveData(new OneStepKDFParameterSpec(Z, INFO, 100))));

        // the hash option ignores a salt
        assertTrue(Arrays.areEqual(HASH_SHA256, KDF.getInstance("ONESTEP-SHA256", "BC").deriveData(new OneStepKDFParameterSpec(Z, SALT, INFO, 48))));

        OneStepKDFBytesGenerator ref = new OneStepKDFBytesGenerator(new SHA256Digest());
        ref.init(new KDFParameters(Z, null));
        byte[] expected = new byte[20];
        ref.generateBytes(expected, 0, 20);
        assertTrue(Arrays.areEqual(expected, KDF.getInstance("ONESTEP-SHA256", "BC").deriveData(new OneStepKDFParameterSpec(Z, null, 20))));

        assertNotNull(KDF.getInstance("ONESTEP-SHA384", "BC").deriveData(new OneStepKDFParameterSpec(Z, INFO, 7)));
    }

    public void testHmacOption()
        throws Exception
    {
        assertTrue(Arrays.areEqual(HMAC_SHA256, KDF.getInstance("ONESTEP-HMACSHA256", "BC").deriveData(new OneStepKDFParameterSpec(Z, SALT, INFO, 80))));
        assertTrue(Arrays.areEqual(HMAC_SHA384, KDF.getInstance("ONESTEP-HMACSHA384", "BC").deriveData(new OneStepKDFParameterSpec(Z, SALT, INFO, 80))));
        assertTrue(Arrays.areEqual(HMAC_SHA512, KDF.getInstance("ONESTEP-HMACSHA512", "BC").deriveData(new OneStepKDFParameterSpec(Z, SALT, INFO, 80))));
        assertTrue(Arrays.areEqual(HMAC_SHA256_NO_SALT, KDF.getInstance("ONESTEP-HMACSHA256", "BC").deriveData(new OneStepKDFParameterSpec(Z, INFO, 42))));
    }

    public void testKmacOption()
        throws Exception
    {
        for (int bits : new int[]{ 128, 256 })
        {
            KDF kdf = KDF.getInstance("ONESTEP-KMAC" + bits, "BC");

            OneStepKDFBytesGenerator ref = new OneStepKDFBytesGenerator(new KMAC(bits, Strings.toByteArray("KDF")), SALT);
            ref.init(new KDFParameters(Z, INFO));
            byte[] expected = new byte[70];
            ref.generateBytes(expected, 0, 70);

            assertTrue(Arrays.areEqual(expected, kdf.deriveData(new OneStepKDFParameterSpec(Z, SALT, INFO, 70))));

            // default salt differs from the explicit one
            assertFalse(Arrays.areEqual(expected, kdf.deriveData(new OneStepKDFParameterSpec(Z, INFO, 70))));
        }
    }

    public void testDeriveKeyAndErrors()
        throws Exception
    {
        KDF kdf = KDF.getInstance("ONESTEP-HMACSHA256", "BC");

        SecretKey key = kdf.deriveKey("AES", new OneStepKDFParameterSpec(Z, SALT, INFO, 32));

        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertTrue(Arrays.areEqual(Arrays.copyOf(HMAC_SHA256, 32), key.getEncoded()));

        try
        {
            kdf.deriveData(HKDFParameterSpec.ofExtract().addIKM(Z).thenExpand(INFO, 32));
            fail("foreign spec accepted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // javax.crypto.KDF replaces the SPI's message with its own when the provider was named
        }

        try
        {
            new OneStepKDFParameterSpec(null, INFO, 32);
            fail("null Z accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }
}
