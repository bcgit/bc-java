package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.MayoKey;
import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;

public class MayoKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    public static void main(String[] args)
        throws Exception
    {
        MayoKeyPairGeneratorTest test = new MayoKeyPairGeneratorTest();
        test.setUp();
        test.testKeyFactory();
        test.testKeyPairEncoding();
    }

    protected void setUp()
    {
        super.setUp();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Mayo", "BCPQC");
        KeyFactory kf1 = KeyFactory.getInstance("MAYO-1", "BCPQC");
        KeyFactory kf2 = KeyFactory.getInstance("MAYO-2", "BCPQC");
        KeyFactory kf3 = KeyFactory.getInstance("MAYO-3", "BCPQC");
        KeyFactory kf5 = KeyFactory.getInstance("MAYO-5", "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        MayoParameterSpec[] specs =
            new MayoParameterSpec[]
                {
                    MayoParameterSpec.mayo1,
                    MayoParameterSpec.mayo2,
                    MayoParameterSpec.mayo3,
                    MayoParameterSpec.mayo5
                };
        kf = KeyFactory.getInstance("Mayo", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(specs[i].getName(), kpg.generateKeyPair());
        }
    }

    /**
     * A generator selected by parameter set name must default to that parameter set, not to
     * the generic generator's default of MAYO-1.
     */
    public void testNamedKeyPairGenDefaults()
        throws Exception
    {
        MayoParameterSpec[] specs =
            new MayoParameterSpec[]
                {
                    MayoParameterSpec.mayo1,
                    MayoParameterSpec.mayo2,
                    MayoParameterSpec.mayo3,
                    MayoParameterSpec.mayo5
                };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(specs[i].getName(), "BCPQC");

            KeyPair kp = kpg.generateKeyPair();

            assertEquals(specs[i].getName(), ((MayoKey)kp.getPublic()).getParameterSpec().getName());
            assertEquals(specs[i].getName(), ((MayoKey)kp.getPrivate()).getParameterSpec().getName());
        }
    }

    public void testUnnamedKeyPairGenDefault()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("Mayo", "BCPQC").generateKeyPair();

        assertEquals(MayoParameterSpec.mayo1.getName(), ((MayoKey)kp.getPublic()).getParameterSpec().getName());
    }

    public void testNamedKeyPairGenLocked()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(MayoParameterSpec.mayo5.getName(), "BCPQC");

        try
        {
            kpg.initialize(MayoParameterSpec.mayo1, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key pair generator locked to " + kpg.getAlgorithm(), e.getMessage());
        }

        kpg.initialize(MayoParameterSpec.mayo5, new SecureRandom());

        assertEquals(MayoParameterSpec.mayo5.getName(),
            ((MayoKey)kpg.generateKeyPair().getPublic()).getParameterSpec().getName());
    }
}
