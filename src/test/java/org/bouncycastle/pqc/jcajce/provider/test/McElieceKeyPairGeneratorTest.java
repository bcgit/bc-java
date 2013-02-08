package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.pqc.jcajce.spec.ECCKeyGenParameterSpec;


public class McElieceKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
        try
        {
            kf = KeyFactory.getInstance("McEliece");
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
    }

    public void testKeyPairEncoding_9_33()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("McEliecePKCS");
        ECCKeyGenParameterSpec params = new ECCKeyGenParameterSpec(9, 33);
        kpg.initialize(params);
        performKeyPairEncodingTest();
    }

}
