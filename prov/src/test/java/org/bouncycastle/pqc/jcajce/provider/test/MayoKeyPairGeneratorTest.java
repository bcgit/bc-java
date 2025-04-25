package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
        KeyFactory kf1 = KeyFactory.getInstance("MAYO_1", "BCPQC");
        KeyFactory kf2 = KeyFactory.getInstance("MAYO_2", "BCPQC");
        KeyFactory kf3 = KeyFactory.getInstance("MAYO_3", "BCPQC");
        KeyFactory kf5 = KeyFactory.getInstance("MAYO_5", "BCPQC");
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
}
