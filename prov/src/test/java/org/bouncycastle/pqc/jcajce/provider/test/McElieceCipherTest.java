package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;

public class McElieceCipherTest
    extends AsymmetricBlockCipherTest
{

    protected void setUp()
    {
        super.setUp();

        try
        {
            kpg = KeyPairGenerator.getInstance("McEliece");
            cipher = Cipher.getInstance("McEliece");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }


    }

    public void testEnDecryption_9_33()
        throws Exception
    {
        McElieceKeyGenParameterSpec params = new McElieceKeyGenParameterSpec(9, 33);
        kpg.initialize(params);
        performEnDecryptionTest(2, 10, params);
    }

    public void testEnDecryption_11_50()
        throws Exception
    {
        McElieceKeyGenParameterSpec params = new McElieceKeyGenParameterSpec(11, 50);
        kpg.initialize(params);
        performEnDecryptionTest(2, 10, params);
    }


}
