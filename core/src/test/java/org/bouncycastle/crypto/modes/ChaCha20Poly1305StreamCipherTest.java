package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ChaCha20Poly1305StreamCipherTest {

    private static final byte[] PLAINTEXT = Hex.decode(
        "4c616469657320616e642047656e746c"
            + "656d656e206f662074686520636c6173"
            + "73206f66202739393a20496620492063"
            + "6f756c64206f6666657220796f75206f"
            + "6e6c79206f6e652074697020666f7220"
            + "746865206675747572652c2073756e73"
            + "637265656e20776f756c642062652069"
            + "742e"
    );

    private static final byte[] CIPHERTEXT = Hex.decode(
        "d31a8d34648e60db7b86afbc53ef7ec2" +
            "a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b" +
            "1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58" +
            "fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b" +
            "6116"
    );

    private static final byte[] AAD = Hex.decode(
        "50515253c0c1c2c3c4c5c6c7");

    private static final byte[] KEY = Hex.decode(
        "808182838485868788898a8b8c8d8e8f"
            + "909192939495969798999a9b9c9d9e9f"
    );

    private static final byte[] IV = Hex.decode(
        "070000004041424344454647"
    );

    private static final byte[] TAG = Hex.decode(
        "1ae10b594f09e26a7e902ecbd0600691"
    );

    @Test(expected = IllegalArgumentException.class)
    public void testRequiredKeySizeIv() {
        ChaCha20Poly1305StreamCipher cipher = new ChaCha20Poly1305StreamCipher();

        cipher.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), IV));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequiredKeySizeAead() {
        ChaCha20Poly1305StreamCipher cipher = new ChaCha20Poly1305StreamCipher();

        cipher.init(true, new AEADParameters(new KeyParameter(new byte[16]), 16, IV));
    }

    @Test
    public void testResetAfterDoFinal() throws InvalidCipherTextException {
        // Ensure the cipher is effectively reset after doFinal(), meaning you can do:
        //  processAADBytes(...)
        //  processBytes(...)
        //  doFinal(...)
        //  processAADBytes(...)
        //  processBytes(...)
        //  doFinal(...)
        // without a manual reset in between.

        ChaCha20Poly1305StreamCipher cipher = new ChaCha20Poly1305StreamCipher();
        cipher.init(true, ivParameters());

        cipher.processAADBytes(AAD, 0, AAD.length);
        int outputSize = cipher.getOutputSize(PLAINTEXT.length);
        byte[] encrypted1 = new byte[outputSize];
        cipher.processBytes(PLAINTEXT, 0, PLAINTEXT.length, encrypted1, 0);
        cipher.doFinal(encrypted1, 0);

        System.out.println("mac1=" + Hex.toHexString(cipher.getMac()));
        System.out.println("encrypted1=" + Hex.toHexString(encrypted1));

        // TODO this test should pass without re-initializing here, but it doesn't
        cipher.init(true, ivParameters());

        cipher.processAADBytes(AAD, 0, AAD.length);
        outputSize = cipher.getOutputSize(PLAINTEXT.length);
        byte[] encrypted2 = new byte[outputSize];
        cipher.processBytes(PLAINTEXT, 0, PLAINTEXT.length, encrypted2, 0);
        cipher.doFinal(encrypted2, 0);

        System.out.println("mac2=" + Hex.toHexString(cipher.getMac()));
        System.out.println("encrypted2=" + Hex.toHexString(encrypted2));

        assertTrue(Arrays.constantTimeAreEqual(encrypted1, encrypted2));
    }

    @Test
    public void testEncryptDecrypt() throws InvalidCipherTextException {
        testEncryptDecryptWithParameters(ivParameters());
        testEncryptDecryptWithParameters(aeadParameters());
        testEncryptDecryptWithParameters(aeadParametersWithAssociatedText());
    }

    private static void testEncryptDecryptWithParameters(CipherParameters parameters) throws InvalidCipherTextException {
        ChaCha20Poly1305StreamCipher cipher = new ChaCha20Poly1305StreamCipher();

        cipher.init(true, parameters);
        cipher.processAADBytes(AAD, 0, AAD.length);

        int outputSize = cipher.getOutputSize(PLAINTEXT.length);
        assertEquals(PLAINTEXT.length + 16, outputSize);

        byte[] encrypted = new byte[outputSize];
        cipher.processBytes(PLAINTEXT, 0, PLAINTEXT.length, encrypted, 0);
        cipher.doFinal(encrypted, 0);

        byte[] cipherText = Arrays.copyOfRange(encrypted, 0, encrypted.length - 16);
        assertTrue(Arrays.constantTimeAreEqual(CIPHERTEXT, cipherText));

        byte[] lastMac1 = cipher.getMac();
        assertNotNull(lastMac1);
        assertEquals(16, lastMac1.length);

        if (parameters instanceof AEADParameters) {
            byte[] initialAssociatedText = ((AEADParameters) parameters).getAssociatedText();

            if (initialAssociatedText == null || initialAssociatedText.length == 0) {
                assertTrue(Arrays.constantTimeAreEqual(TAG, lastMac1));
            }
        }

        cipher.init(false, parameters);
        cipher.processAADBytes(AAD, 0, AAD.length);

        outputSize = cipher.getOutputSize(encrypted.length);
        assertEquals(PLAINTEXT.length, outputSize);

        byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
        cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
        cipher.doFinal(decrypted, 0);

        assertTrue(Arrays.constantTimeAreEqual(PLAINTEXT, decrypted));

        byte[] lastMac2 = cipher.getMac();
        assertNotNull(lastMac2);
        assertEquals(16, lastMac2.length);
        assertTrue(Arrays.constantTimeAreEqual(lastMac1, lastMac2));
    }

    private ParametersWithIV ivParameters() {
        return new ParametersWithIV(keyParameter(), IV);
    }

    private AEADParameters aeadParameters() {
        return new AEADParameters(keyParameter(), 16, IV);
    }

    private AEADParameters aeadParametersWithAssociatedText() {
        return new AEADParameters(keyParameter(), 16, IV, Arrays.reverse(AAD));
    }

    private KeyParameter keyParameter() {
        return new KeyParameter(KEY);
    }

}
