package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
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

}
