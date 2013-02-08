package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;

import org.bouncycastle.pqc.jcajce.provider.util.AsymmetricHybridCipher;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

/**
 * Base class for unit tests of {@link AsymmetricHybridCipher}s.
 */
public abstract class AsymmetricHybridCipherTest
    extends FlexiTest
{

    /**
     * the {@link KeyPairGenerator} to use for the test
     */
    protected KeyPairGenerator kpg;

    /**
     * the {@link AsymmetricHybridCipher} to use for the test
     */
    protected Cipher cipher;

    private KeyPair keyPair;

    private PublicKey pubKey;

    private PrivateKey privKey;

    private byte[] mBytes, cBytes, dBytes;

    protected final void performEnDecryptionTest(int numPassesKPG,
                                                 int numPassesEncDec, int plainTextSize,
                                                 AlgorithmParameterSpec params)
    {

        try
        {
            for (int j = 0; j < numPassesKPG; j++)
            {
                // generate key pair
                //kpg.initialize(params);
                keyPair = kpg.genKeyPair();
                pubKey = keyPair.getPublic();
                privKey = keyPair.getPrivate();

                for (int k = 1; k <= numPassesEncDec; k++)
                {
                    // initialize for encryption
                    cipher.init(Cipher.ENCRYPT_MODE, pubKey, params, sr);

                    // generate random message
                    int mLength = rand.nextInt(plainTextSize) + 1;
                    mBytes = new byte[mLength];
                    rand.nextBytes(mBytes);

                    // encrypt
                    cBytes = cipher.doFinal(mBytes);


                    // initialize for decryption
                    cipher.init(Cipher.DECRYPT_MODE, privKey, params);
                    // decrypt
                    dBytes = cipher.doFinal(cBytes);
                    // compare
                    assertEquals(
                        "Encryption/decryption test failed for message \""
                            + ByteUtils.toHexString(mBytes)
                            + "\":\n actual decrypted text: "
                            + ByteUtils.toHexString(dBytes)
                            + "\n expected plain text: "
                            + ByteUtils.toHexString(mBytes), mBytes,
                        dBytes);
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
