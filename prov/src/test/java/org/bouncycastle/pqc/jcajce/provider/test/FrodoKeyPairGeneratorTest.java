package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for Frodo with BCPQC provider.
 */
public class FrodoKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("Frodo", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_frodo.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        FrodoParameterSpec[] specs =
            new FrodoParameterSpec[]
                {
                        FrodoParameterSpec.frodokem640aes,
                        FrodoParameterSpec.frodokem640shake,
                        FrodoParameterSpec.frodokem976aes,
                        FrodoParameterSpec.frodokem976shake,
                        FrodoParameterSpec.frodokem1344aes,
                        FrodoParameterSpec.frodokem1344shake
                };
        kf = KeyFactory.getInstance("Frodo", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Frodo", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
