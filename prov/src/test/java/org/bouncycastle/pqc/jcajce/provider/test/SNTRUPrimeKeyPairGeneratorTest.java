package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for SNTRUPrime with BCPQC provider.
 */
public class SNTRUPrimeKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("SNTRUPrime", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_frodo.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        SNTRUPrimeParameterSpec[] specs =
            new SNTRUPrimeParameterSpec[]
                {
                        SNTRUPrimeParameterSpec.sntrup653,
                        SNTRUPrimeParameterSpec.sntrup761,
                        SNTRUPrimeParameterSpec.sntrup857,
                        SNTRUPrimeParameterSpec.sntrup953,
                        SNTRUPrimeParameterSpec.sntrup1013,
                        SNTRUPrimeParameterSpec.sntrup1277
                };
        kf = KeyFactory.getInstance("SNTRUPrime", "BCPQC");

        kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
