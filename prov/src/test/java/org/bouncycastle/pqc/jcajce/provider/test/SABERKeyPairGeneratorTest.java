package org.bouncycastle.pqc.jcajce.provider.test;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * KeyFactory/KeyPairGenerator tests for SABER with BCPQC provider.
 */
public class SABERKeyPairGeneratorTest
        extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFacory()
            throws Exception
    {
        kf = KeyFactory.getInstance("SABER", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_saber.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
            throws Exception
    {
        SABERParameterSpec[] specs =
                new SABERParameterSpec[]
                        {
                                SABERParameterSpec.lightsaberkemr3,
                                SABERParameterSpec.saberkemr3,
                                SABERParameterSpec.firesaberkemr3,
                        };
        kf = KeyFactory.getInstance("SABER", "BCPQC");

        kpg = KeyPairGenerator.getInstance("SABER", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
