package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for NTRULPRime with BCPQC provider.
 */
public class NTRULPRimeKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("NTRULPRime", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_frodo.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        NTRULPRimeParameterSpec[] specs =
            new NTRULPRimeParameterSpec[]
                {
                        NTRULPRimeParameterSpec.ntrulpr653,
                        NTRULPRimeParameterSpec.ntrulpr761,
                        NTRULPRimeParameterSpec.ntrulpr857,
                        NTRULPRimeParameterSpec.ntrulpr953,
                        NTRULPRimeParameterSpec.ntrulpr1013,
                        NTRULPRimeParameterSpec.ntrulpr1277
                };
        kf = KeyFactory.getInstance("NTRULPRime", "BCPQC");

        kpg = KeyPairGenerator.getInstance("NTRULPRime", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
