package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.interfaces.HQCKey;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for HQC with BCPQC provider.
 */
public class HQCKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("HQC", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_hqc.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        HQCParameterSpec[] specs =
            new HQCParameterSpec[]
                {
                    HQCParameterSpec.hqc128,
                    HQCParameterSpec.hqc192,
                    HQCParameterSpec.hqc256
                };
        kf = KeyFactory.getInstance("HQC", "BCPQC");

        kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

    /**
     * A generator selected by parameter set name must default to that parameter set, not to
     * the generic generator's default of hqc-128.
     */
    public void testNamedKeyPairGenDefaults()
        throws Exception
    {
        HQCParameterSpec[] specs =
            new HQCParameterSpec[]
                {
                    HQCParameterSpec.hqc128,
                    HQCParameterSpec.hqc192,
                    HQCParameterSpec.hqc256
                };
        String[] algNames = new String[]{ "HQC-128", "HQC-192", "HQC-256" };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algNames[i], "BCPQC");

            KeyPair kp = kpg.generateKeyPair();

            assertEquals(algNames[i], kp.getPublic().getAlgorithm());
            assertEquals(algNames[i], kp.getPrivate().getAlgorithm());
            assertEquals(specs[i].getName(), ((HQCKey)kp.getPublic()).getParameterSpec().getName());
            assertEquals(specs[i].getName(), ((HQCKey)kp.getPrivate()).getParameterSpec().getName());
        }
    }

    public void testUnnamedKeyPairGenDefault()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("HQC", "BCPQC").generateKeyPair();

        assertEquals(HQCParameterSpec.hqc128.getName(), ((HQCKey)kp.getPublic()).getParameterSpec().getName());
    }

    public void testNamedKeyPairGenLocked()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC-256", "BCPQC");

        try
        {
            kpg.initialize(HQCParameterSpec.hqc128, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key pair generator locked to HQC-256", e.getMessage());
        }

        kpg.initialize(HQCParameterSpec.hqc256, new SecureRandom());

        assertEquals(HQCParameterSpec.hqc256.getName(),
            ((HQCKey)kpg.generateKeyPair().getPublic()).getParameterSpec().getName());
    }
}
