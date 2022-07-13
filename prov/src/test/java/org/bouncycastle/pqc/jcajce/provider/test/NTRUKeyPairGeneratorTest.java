package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for NTRU with BCPQC provider.
 */
public class NTRUKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("NTRU", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_ntru.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        NTRUParameterSpec[] specs =
            new NTRUParameterSpec[]
                {
                    NTRUParameterSpec.ntruhps2048509,
                    NTRUParameterSpec.ntruhps2048677,
                    NTRUParameterSpec.ntruhps4096821,
                    NTRUParameterSpec.ntruhrss701
                };
        kf = KeyFactory.getInstance("NTRU", "BCPQC");

        kpg = KeyPairGenerator.getInstance("NTRU", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
