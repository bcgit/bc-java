package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.pqc.jcajce.spec.ECCKeyGenParameterSpec;


public class McElieceCCA2KeyPairGeneratorTest
    extends KeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
        try
        {
            kf = KeyFactory.getInstance("McElieceCCA2");
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
    }


    public void testKeyPairEncoding_9_33()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("McElieceKobaraImai");
        ECCKeyGenParameterSpec params = new ECCKeyGenParameterSpec(9, 33);
        kpg.initialize(params);
        performKeyPairEncodingTest();
    }

}
