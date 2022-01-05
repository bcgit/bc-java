package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;


/**
 * KeyFactory/KeyPairGenerator tests for SPHINCSPlus with the BCPQC provider.
 */
public class SphincsPlusKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.sphincsPlus.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        kf = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");

        kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha256_128f, new SecureRandom());
        performKeyPairEncodingTest(kpg.generateKeyPair());
    }

}
