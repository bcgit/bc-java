package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;


/**
 * KeyFactory/KeyPairGenerator tests for NewHope (NH) with the BCPQC provider.
 */
public class NewHopeKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("NH", "BCPQC");
        kf = KeyFactory.getInstance(PQCObjectIdentifiers.newHope.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        kf = KeyFactory.getInstance("NH", "BCPQC");

        kpg = KeyPairGenerator.getInstance("NH", "BCPQC");
        kpg.initialize(1024, new SecureRandom());

        performKeyPairEncodingTest(kpg.generateKeyPair());
    }

}
