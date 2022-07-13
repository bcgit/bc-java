package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.SIKEParameterSpec;

/**
 * KeyFactory/KeyPairGenerator tests for SIKE with BCPQC provider.
 */
public class SIKEKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("SIKE", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_sike.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        SIKEParameterSpec[] specs =
            new SIKEParameterSpec[]
                {
                    SIKEParameterSpec.sikep434,
                    SIKEParameterSpec.sikep503,
                    SIKEParameterSpec.sikep610,
                    SIKEParameterSpec.sikep751,
                    SIKEParameterSpec.sikep434_compressed,
                    SIKEParameterSpec.sikep503_compressed,
                    SIKEParameterSpec.sikep610_compressed,
                    SIKEParameterSpec.sikep751_compressed
                };
        kf = KeyFactory.getInstance("SIKE", "BCPQC");

        kpg = KeyPairGenerator.getInstance("SIKE", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }

}
