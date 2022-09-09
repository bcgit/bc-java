package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for BIKE with BCPQC provider.
 */
public class BIKEKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("BIKE", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_bike.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        BIKEParameterSpec[] specs =
            new BIKEParameterSpec[]
                {
                        BIKEParameterSpec.bike128,
                        BIKEParameterSpec.bike192,
                        BIKEParameterSpec.bike256
                };
        kf = KeyFactory.getInstance("BIKE", "BCPQC");

        kpg = KeyPairGenerator.getInstance("BIKE", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
