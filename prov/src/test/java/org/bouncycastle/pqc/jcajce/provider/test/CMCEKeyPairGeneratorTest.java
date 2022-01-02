package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;


/**
 * KeyFactory/KeyPairGenerator tests for CMCE with the BCPQC provider.
 */
public class CMCEKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("CMCE", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.classicMcEliece.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        kf = KeyFactory.getInstance("CMCE", "BCPQC");

        kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
        kpg.initialize(CMCEParameterSpec.mceliece348864, new SecureRandom());
        performKeyPairEncodingTest(kpg.generateKeyPair());
    }
}
