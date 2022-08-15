package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for Falcon with BCPQC provider.
 */
public class FalconKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Falcon", "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        FalconParameterSpec[] specs =
            new FalconParameterSpec[]
                {
                        FalconParameterSpec.falcon_512,
                        FalconParameterSpec.falcon_1024,
                };
        kf = KeyFactory.getInstance("Falcon", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Falcon", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
