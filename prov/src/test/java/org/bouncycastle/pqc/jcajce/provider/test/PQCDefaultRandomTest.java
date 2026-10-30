package org.bouncycastle.pqc.jcajce.provider.test;

import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Checks the ML-DSA, ML-KEM and SLH-DSA key pair generators draw from the provider's DEFAULT DRBG
 * on every path where the caller gives no SecureRandom (ML-DSA-44 is only NIST category 2 with an
 * RBG of at least 192 bits of security, NIST IR 8547, Table 3, note 2), and that the documented
 * signing behaviour holds: deterministic without a SecureRandom, hedged with one.
 */
public class PQCDefaultRandomTest
    extends TestCase
{
    private static final String[] NAMED = new String[]{
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-DSA-44-WITH-SHA512",
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128F", "SLH-DSA-SHA2-128S-WITH-SHA256"
    };

    private static final String[] FAMILIES = new String[]{
        "ML-DSA", "HASH-ML-DSA", "ML-KEM", "SLH-DSA", "HASH-SLH-DSA"
    };

    protected void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testNamedGeneratorUsesDefaultDRBG()
        throws Exception
    {
        for (int i = 0; i != NAMED.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(NAMED[i], "BC");

            assertDefaultDRBG(NAMED[i], kpg);
            assertEquals(NAMED[i], Strings.toUpperCase(kpg.generateKeyPair().getPrivate().getAlgorithm()));
        }
    }

    public void testUninitialisedGeneratorUsesDefaultDRBG()
        throws Exception
    {
        for (int i = 0; i != FAMILIES.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(FAMILIES[i], "BC");

            kpg.generateKeyPair();

            assertDefaultDRBG(FAMILIES[i], kpg);
        }
    }

    public void testInitializeWithoutRandomUsesDefaultDRBG()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        assertDefaultDRBG("ML-DSA", kpg);

        kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512);
        assertDefaultDRBG("ML-KEM", kpg);

        kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        assertDefaultDRBG("SLH-DSA", kpg);

        kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", "BC");
        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        assertDefaultDRBG("SLH-DSA-SHA2-128S", kpg);
    }

    public void testInitializeWithRandomUsesCallerRandom()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, random);
        assertSame(random, getKeyGenParams(kpg).getRandom());

        kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s, random);
        assertSame(random, getKeyGenParams(kpg).getRandom());
    }

    public void testSigningDeterministicWithoutRandom()
        throws Exception
    {
        String[] algs = new String[]{ "ML-DSA", "HASH-ML-DSA", "SLH-DSA", "HASH-SLH-DSA" };
        byte[] msg = Strings.toByteArray("hello, world!");

        for (int i = 0; i != algs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algs[i], "BC");
            KeyPair kp = kpg.generateKeyPair();

            Signature sig = Signature.getInstance(algs[i], "BC");

            sig.initSign(kp.getPrivate());
            sig.update(msg);
            byte[] s1 = sig.sign();

            sig.initSign(kp.getPrivate());
            sig.update(msg);
            byte[] s2 = sig.sign();

            assertTrue(algs[i] + " not deterministic", Arrays.areEqual(s1, s2));

            sig.initSign(kp.getPrivate(), new SecureRandom());
            sig.update(msg);
            byte[] h1 = sig.sign();

            sig.initSign(kp.getPrivate(), new SecureRandom());
            sig.update(msg);
            byte[] h2 = sig.sign();

            assertFalse(algs[i] + " not hedged", Arrays.areEqual(h1, h2));
            assertFalse(algs[i] + " hedged equals deterministic", Arrays.areEqual(s1, h1));

            sig.initVerify(kp.getPublic());
            sig.update(msg);
            assertTrue(sig.verify(s1));
            sig.initVerify(kp.getPublic());
            sig.update(msg);
            assertTrue(sig.verify(h1));
        }
    }

    private static void assertDefaultDRBG(String label, KeyPairGenerator kpg)
        throws Exception
    {
        SecureRandom random = getKeyGenParams(kpg).getRandom();

        assertNotNull(label, random);
        assertEquals(label, "DEFAULT", random.getAlgorithm());
        assertEquals(label, BouncyCastleProvider.PROVIDER_NAME, random.getProvider().getName());
    }

    // the BC generator SPIs extend KeyPairGenerator, so getInstance returns the SPI itself
    private static KeyGenerationParameters getKeyGenParams(KeyPairGenerator kpg)
        throws Exception
    {
        for (Class c = kpg.getClass(); c != null; c = c.getSuperclass())
        {
            try
            {
                Field f = c.getDeclaredField("param");
                f.setAccessible(true);
                return (KeyGenerationParameters)f.get(kpg);
            }
            catch (NoSuchFieldException e)
            {
                // try the superclass
            }
        }
        throw new IllegalStateException("no param field on " + kpg.getClass());
    }
}
