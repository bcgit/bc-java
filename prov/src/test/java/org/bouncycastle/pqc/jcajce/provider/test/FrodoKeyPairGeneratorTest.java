package org.bouncycastle.pqc.jcajce.provider.test;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * KeyFactory/KeyPairGenerator tests for Frodo with BCPQC provider.
 */
public class FrodoKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFacory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Frodo", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_frodo.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        FrodoParameterSpec[] specs =
            new FrodoParameterSpec[]
                {
                        FrodoParameterSpec.frodokem19888r3,
                        FrodoParameterSpec.frodokem19888shaker3,
                        FrodoParameterSpec.frodokem31296r3,
                        FrodoParameterSpec.frodokem31296shaker3,
                        FrodoParameterSpec.frodokem43088r3,
                        FrodoParameterSpec.frodokem43088shaker3
                };
        kf = KeyFactory.getInstance("Frodo", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Frodo", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
