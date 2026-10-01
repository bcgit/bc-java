package org.bouncycastle.jcajce.provider.test;

import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * java.security.DrbgParameters support in the DEFAULT and NONCEANDIV SecureRandoms, which the
 * jdk1.9 overlay provides, exercised against the multi-release jar.
 */
public class DRBGParametersMRTest
    extends TestCase
{
    private static final String BC = "BC";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testUnparameterisedDefaults()
        throws Exception
    {
        checkInstantiation(SecureRandom.getInstance("DEFAULT", BC), 256, DrbgParameters.Capability.PR_AND_RESEED, null);
        checkInstantiation(SecureRandom.getInstance("NONCEANDIV", BC), 256, DrbgParameters.Capability.RESEED_ONLY, null);

        SecureRandom random = SecureRandom.getInstance("DEFAULT", BC);
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        random.nextBytes(bytes, DrbgParameters.nextBytes(256, true, Strings.toByteArray("extra")));
        random.reseed();
        random.reseed(DrbgParameters.reseed(true, Strings.toByteArray("extra")));
    }

    public void testInstantiation()
        throws Exception
    {
        byte[] ps = Strings.toByteArray("personalization");
        String[] algorithms = new String[]{ "DEFAULT", "NONCEANDIV" };

        for (int i = 0; i != algorithms.length; i++)
        {
            SecureRandom random = SecureRandom.getInstance(algorithms[i],
                DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, ps), BC);

            checkInstantiation(random, 128, DrbgParameters.Capability.RESEED_ONLY, ps);

            byte[] b1 = new byte[64];
            byte[] b2 = new byte[64];
            random.nextBytes(b1);
            random.nextBytes(b2);
            assertFalse(algorithms[i] + " repeated output", Arrays.areEqual(b1, b2));
        }
    }

    public void testDRBGAlias()
        throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", BC);

        assertEquals(BC, random.getProvider().getName());
        checkInstantiation(random, 256, DrbgParameters.Capability.PR_AND_RESEED, null);

        byte[] ps = Strings.toByteArray("personalization");
        random = SecureRandom.getInstance("DRBG", DrbgParameters.instantiation(192, DrbgParameters.Capability.RESEED_ONLY, ps), BC);

        checkInstantiation(random, 192, DrbgParameters.Capability.RESEED_ONLY, ps);
        random.nextBytes(new byte[32], DrbgParameters.nextBytes(192, false, Strings.toByteArray("extra")));

        // the alias and the name it stands for, fetched from a fresh provider in either order.
        checkNames(new String[]{ "DRBG", "DEFAULT", "DRBG" });
        checkNames(new String[]{ "DEFAULT", "DRBG", "DEFAULT" });
    }

    private static void checkNames(String[] names)
        throws Exception
    {
        BouncyCastleProvider provider = new BouncyCastleProvider();

        for (int i = 0; i != names.length; i++)
        {
            SecureRandom random = SecureRandom.getInstance(names[i], provider);

            checkInstantiation(random, 256, DrbgParameters.Capability.PR_AND_RESEED, null);
        }
    }

    public void testStrength()
        throws Exception
    {
        checkStrength(-1, 256);
        checkStrength(0, 112);
        checkStrength(112, 112);
        checkStrength(113, 128);
        checkStrength(129, 192);
        checkStrength(193, 256);
        checkStrength(256, 256);

        try
        {
            SecureRandom.getInstance("DEFAULT", DrbgParameters.instantiation(257, DrbgParameters.Capability.NONE, null), BC);
            fail("strength 257 accepted");
        }
        catch (NoSuchAlgorithmException e)
        {
            // expected
        }
    }

    public void testNextBytesParameters()
        throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DEFAULT",
            DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null), BC);
        byte[] bytes = new byte[32];

        random.nextBytes(bytes, DrbgParameters.nextBytes(128, false, Strings.toByteArray("extra")));
        random.nextBytes(bytes, DrbgParameters.nextBytes(-1, false, null));

        try
        {
            random.nextBytes(bytes, DrbgParameters.nextBytes(192, false, null));
            fail("strength above the DRBG's accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("requested strength 192 exceeds DRBG strength of 128", e.getMessage());
        }

        try
        {
            random.nextBytes(bytes, DrbgParameters.nextBytes(128, true, null));
            fail("prediction resistance accepted without the capability");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("prediction resistance not available", e.getMessage());
        }

        try
        {
            random.nextBytes(bytes, DrbgParameters.reseed(false, null));
            fail("reseed parameters accepted by nextBytes");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        SecureRandom prRandom = SecureRandom.getInstance("DEFAULT",
            DrbgParameters.instantiation(256, DrbgParameters.Capability.PR_AND_RESEED, null), BC);
        prRandom.nextBytes(bytes, DrbgParameters.nextBytes(256, true, null));
    }

    public void testReseedParameters()
        throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("NONCEANDIV",
            DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null), BC);

        random.reseed();
        random.reseed(DrbgParameters.reseed(false, Strings.toByteArray("extra")));

        try
        {
            random.reseed(DrbgParameters.reseed(true, null));
            fail("prediction resistance accepted without the capability");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("prediction resistance not available", e.getMessage());
        }

        SecureRandom noReseed = SecureRandom.getInstance("NONCEANDIV",
            DrbgParameters.instantiation(128, DrbgParameters.Capability.NONE, null), BC);
        byte[] bytes = new byte[32];
        noReseed.nextBytes(bytes);

        try
        {
            noReseed.reseed();
            fail("reseed accepted without the capability");
        }
        catch (UnsupportedOperationException e)
        {
            assertEquals("DRBG does not support reseeding", e.getMessage());
        }
    }

    /**
     * With a fixed entropy source two DRBGs instantiated alike produce the same output, so the
     * personalization string and additional input can be seen to reach the DRBG.
     */
    public void testInputsReachDRBG()
        throws Exception
    {
        // create the shared DRBGs first, so the fixed entropy source can only reach the instances below.
        SecureRandom.getInstance("DEFAULT", BC).nextBytes(new byte[1]);
        SecureRandom.getInstance("NONCEANDIV", BC).nextBytes(new byte[1]);

        System.setProperty(Properties.DRBG_ENTROPY_SOURCE, FixedEntropySourceProvider.class.getName());
        try
        {
            byte[] ps = Strings.toByteArray("personalization");
            byte[] additionalInput = Strings.toByteArray("additional input");

            byte[] plain1 = generate(ps, null);
            byte[] plain2 = generate(ps, null);
            assertTrue("fixed entropy not deterministic", Arrays.areEqual(plain1, plain2));

            assertFalse("personalization string ignored", Arrays.areEqual(plain1, generate(Strings.toByteArray("other"), null)));
            assertFalse("additional input ignored", Arrays.areEqual(plain1, generate(ps, additionalInput)));
            assertTrue("additional input not deterministic", Arrays.areEqual(generate(ps, additionalInput), generate(ps, additionalInput)));
        }
        finally
        {
            System.clearProperty(Properties.DRBG_ENTROPY_SOURCE);
        }
    }

    private static byte[] generate(byte[] personalizationString, byte[] additionalInput)
        throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DEFAULT",
            DrbgParameters.instantiation(256, DrbgParameters.Capability.RESEED_ONLY, personalizationString), BC);
        byte[] bytes = new byte[64];

        random.nextBytes(bytes, DrbgParameters.nextBytes(256, false, additionalInput));

        return bytes;
    }

    private static void checkStrength(int requested, int expected)
        throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DEFAULT",
            DrbgParameters.instantiation(requested, DrbgParameters.Capability.NONE, null), BC);

        checkInstantiation(random, expected, DrbgParameters.Capability.NONE, null);
    }

    private static void checkInstantiation(SecureRandom random, int strength, DrbgParameters.Capability capability,
        byte[] personalizationString)
    {
        SecureRandomParameters params = random.getParameters();

        assertTrue("not an Instantiation: " + params, params instanceof DrbgParameters.Instantiation);

        DrbgParameters.Instantiation instantiation = (DrbgParameters.Instantiation)params;

        assertEquals(strength, instantiation.getStrength());
        assertEquals(capability, instantiation.getCapability());
        assertTrue("personalization string", Arrays.areEqual(personalizationString, instantiation.getPersonalizationString()));
    }

    public static class FixedEntropySourceProvider
        implements EntropySourceProvider
    {
        private int counter = 0;

        public EntropySource get(final int bitsRequired)
        {
            return new EntropySource()
            {
                public boolean isPredictionResistant()
                {
                    return false;
                }

                public byte[] getEntropy()
                {
                    byte[] entropy = new byte[(bitsRequired + 7) / 8];
                    for (int i = 0; i != entropy.length; i++)
                    {
                        entropy[i] = (byte)(counter++);
                    }
                    return entropy;
                }

                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }
}
