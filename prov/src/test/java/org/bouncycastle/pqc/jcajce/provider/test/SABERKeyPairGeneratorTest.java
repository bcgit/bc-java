package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;

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

    public void testKeyFactory()
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
                                SABERParameterSpec.lightsaberkem128r3,
                                SABERParameterSpec.saberkem128r3,
                                SABERParameterSpec.firesaberkem128r3,
                                SABERParameterSpec.lightsaberkem192r3,
                                SABERParameterSpec.saberkem192r3,
                                SABERParameterSpec.firesaberkem192r3,
                                SABERParameterSpec.lightsaberkem256r3,
                                SABERParameterSpec.saberkem256r3,
                                SABERParameterSpec.firesaberkem256r3,
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
