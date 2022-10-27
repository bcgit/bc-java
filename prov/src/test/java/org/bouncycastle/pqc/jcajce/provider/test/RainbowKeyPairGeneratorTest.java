package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for Falcon with BCPQC provider.
 */
public class RainbowKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Rainbow", "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        RainbowParameterSpec[] specs =
            new RainbowParameterSpec[]
                {
                    RainbowParameterSpec.rainbowIIIclassic,
                    RainbowParameterSpec.rainbowIIIcircumzenithal,
                    RainbowParameterSpec.rainbowIIIcompressed,
                    RainbowParameterSpec.rainbowVclassic,
                    RainbowParameterSpec.rainbowVcircumzenithal,
                    RainbowParameterSpec.rainbowVcompressed,
                };
        kf = KeyFactory.getInstance("Rainbow", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
