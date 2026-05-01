package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;

public class NTRUPlusKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("NTRUPLUS", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_hqc.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        NTRUPlusParameterSpec[] specs =
            new NTRUPlusParameterSpec[]
                {
                    NTRUPlusParameterSpec.ntruplus_768,
                    NTRUPlusParameterSpec.ntruplus_864,
                    NTRUPlusParameterSpec.ntruplus_1152
                };
        kf = KeyFactory.getInstance("NTRUPLUS", "BCPQC");

        kpg = KeyPairGenerator.getInstance("NTRUPLUS", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
