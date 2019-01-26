package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;


public abstract class AsymmetricBlockCipherTest
    extends FlexiTest
{

    protected Cipher cipher;

    protected KeyPair keyPair;

    protected PublicKey pubKey;

    protected PrivateKey privKey;

    protected KeyPairGenerator kpg;

    private byte[] mBytes;

    private byte[] cBytes;

    private byte[] dBytes;

    protected final void performEnDecryptionTest(int numPassesKPG,
                                                 int numPassesEncDec, AlgorithmParameterSpec params)
    {

        try
        {
            for (int j = 0; j < numPassesKPG; j++)
            {
                keyPair = kpg.genKeyPair();
                pubKey = keyPair.getPublic();
                privKey = keyPair.getPrivate();

                for (int k = 1; k <= numPassesEncDec; k++)
                {
                    // initialize for encryption
                    cipher.init(Cipher.ENCRYPT_MODE, pubKey, params, sr);

                    // generate random message
                    final int plainTextSize = cipher.getBlockSize();
                    int mLength = rand.nextInt(plainTextSize) + 1;
                    mBytes = new byte[mLength];
                    rand.nextBytes(mBytes);

                    int cLen = cipher.getOutputSize(mBytes.length);
                    // encrypt
                    cBytes = cipher.doFinal(mBytes);
                    assertTrue(cBytes.length <= cLen);
                    // initialize for decryption
                    cipher.init(Cipher.DECRYPT_MODE, privKey, params);
                    int dLen = cipher.getOutputSize(cBytes.length);
                    // decrypt
                    dBytes = cipher.doFinal(cBytes);
                    assertTrue(dBytes.length <= dLen);
  
                    // compare
                    assertEquals("Encryption and Decryption test failed:\n"
                        + " actual decrypted text: "
                        + ByteUtils.toHexString(dBytes)
                        + "\n expected plain text: "
                        + ByteUtils.toHexString(mBytes), mBytes, dBytes);
                }
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail(e);
        }
    }

}
