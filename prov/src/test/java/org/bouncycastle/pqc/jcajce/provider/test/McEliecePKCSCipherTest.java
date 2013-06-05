package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.bouncycastle.pqc.jcajce.spec.ECCKeyGenParameterSpec;

public class McEliecePKCSCipherTest
    extends AsymmetricBlockCipherTest
{

    protected void setUp()
    {
        super.setUp();

        try
        {
            kpg = KeyPairGenerator.getInstance("McEliecePKCS");
            cipher = Cipher.getInstance("McEliecePKCSwithSHA256");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }


    }

    public void testEnDecryption_9_33()
        throws Exception
    {
        ECCKeyGenParameterSpec params = new ECCKeyGenParameterSpec(9, 33);
        kpg.initialize(params);
        performEnDecryptionTest(2, 10, params);
    }

    public void testEnDecryption_11_50()
        throws Exception
    {
        ECCKeyGenParameterSpec params = new ECCKeyGenParameterSpec(11, 50);
        kpg.initialize(params);
        performEnDecryptionTest(2, 10, params);
    }


}
