package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;


public class McElieceFujisakiCipherTest
    extends AsymmetricHybridCipherTest
{

    protected void setUp()
    {
        super.setUp();
        try
        {
            kpg = KeyPairGenerator.getInstance("McElieceFujisaki");
            cipher = Cipher.getInstance("McElieceFujisaki");
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
        McElieceCCA2KeyGenParameterSpec kpgParams = new McElieceCCA2KeyGenParameterSpec(11, 50);
        kpg.initialize(kpgParams);

        // perform test
        performEnDecryptionTest(1, 10, 32, null);
    }

}
