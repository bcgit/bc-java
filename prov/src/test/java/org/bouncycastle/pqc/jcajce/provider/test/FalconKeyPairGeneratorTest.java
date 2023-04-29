package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for Falcon with BC provider.
 */
public class FalconKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
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
        kf = KeyFactory.getInstance("Falcon", "BC");
        KeyFactory kf1 = KeyFactory.getInstance("Falcon-512", "BC");
        KeyFactory kf2 = KeyFactory.getInstance("Falcon-1024", "BC");

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
        kf = KeyFactory.getInstance("Falcon", "BC");

        kpg = KeyPairGenerator.getInstance("Falcon", "BC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(specs[i].getName(), kpg.generateKeyPair());
        }
    }

}
