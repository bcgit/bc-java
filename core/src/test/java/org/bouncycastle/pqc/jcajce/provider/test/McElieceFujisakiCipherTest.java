package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.bouncycastle.pqc.jcajce.spec.ECCKeyGenParameterSpec;


public class McElieceFujisakiCipherTest
    extends AsymmetricHybridCipherTest
{

    protected void setUp()
    {
        super.setUp();
        try
        {
            kpg = KeyPairGenerator.getInstance("McElieceFujisaki");
            cipher = Cipher.getInstance("McElieceFujisakiWithSHA256");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

    }

    /**
     * Test encryption and decryption performance for SHA256 message digest and parameters
     * m=11, t=50.
     */
    public void testEnDecryption_SHA256_11_50()
        throws Exception
    {
        // initialize key pair generator
        ECCKeyGenParameterSpec kpgParams = new ECCKeyGenParameterSpec(11, 50);
        kpg.initialize(kpgParams);

        // perform test
        performEnDecryptionTest(1, 10, 32, null);
    }

}
