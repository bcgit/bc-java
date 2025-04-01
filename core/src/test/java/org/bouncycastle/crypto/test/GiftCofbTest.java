package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.GiftCofbEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.test.SimpleTest;

public class GiftCofbTest
    extends SimpleTest
{
    public String getName()
    {
        return "GiftCofb";
    }

    public void performTest()
        throws Exception
    {
        CipherTest.checkAEADCipherOutputSize(this, 16, 16, 16, 16, new GiftCofbEngine());
        CipherTest.implTestVectorsEngine(new GiftCofbEngine(), "crypto/giftcofb", "giftcofb_LWC_AEAD_KAT_128_128.txt", this);
        CipherTest.implTestBufferingEngine(16, 16, 128, this, new CipherTest.Instance()
        {
            @Override
            public AEADCipher createInstance()
            {
                return new GiftCofbEngine();
            }
        });
        CipherTest.implTestExceptionsEngine(16, 16, this, new CipherTest.Instance()
        {
            @Override
            public AEADCipher createInstance()
            {
                return new GiftCofbEngine();
            }
        });
        implTestParametersEngine(new GiftCofbEngine(), 16, 16, 16);
        CipherTest.checkAEADParemeter(this, 16, 16, 16, 16, new GiftCofbEngine());
        CipherTest.testOverlapping(this, 16, 16, 16, 16, new GiftCofbEngine());
        CipherTest.checkAEADCipherMultipleBlocks(this, 1025, 33, 16, 128, 16, new GiftCofbEngine());

        CipherTest.checkCipher(16, 16, 40, 128, new CipherTest.Instance()
        {
            public AEADCipher createInstance()
            {
                return new GiftCofbEngine();
            }
        });
    }

    private void implTestParametersEngine(GiftCofbEngine cipher, int keySize, int ivSize,
                                          int macSize)
    {
        if (cipher.getKeyBytesSize() != keySize)
        {
            fail("key bytes of " + cipher.getAlgorithmName() + " is not correct");
        }
        if (cipher.getIVBytesSize() != ivSize)
        {
            fail("iv bytes of " + cipher.getAlgorithmName() + " is not correct");
        }

        CipherParameters parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

        cipher.init(true, parameters);
        if (cipher.getOutputSize(0) != macSize)
        {
            fail("getOutputSize of " + cipher.getAlgorithmName() + " is incorrect for encryption");
        }

        cipher.init(false, parameters);
        if (cipher.getOutputSize(macSize) != 0)
        {
            fail("getOutputSize of " + cipher.getAlgorithmName() + " is incorrect for decryption");
        }
    }

    public static void main(String[] args)
    {
        runTest(new GiftCofbTest());
    }
}
