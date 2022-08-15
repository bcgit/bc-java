package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for Dilithium with BCPQC provider.
 */
public class DilithiumKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Dilithium", "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        DilithiumParameterSpec[] specs =
            new DilithiumParameterSpec[]
                {
                        DilithiumParameterSpec.dilithium2,
                        DilithiumParameterSpec.dilithium3,
                        DilithiumParameterSpec.dilithium5,
                };
        kf = KeyFactory.getInstance("Dilithium", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
