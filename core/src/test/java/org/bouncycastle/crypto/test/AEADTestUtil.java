package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestFailedException;

public class AEADTestUtil
{

    public static void testTampering(Test test, AEADBlockCipher cipher, CipherParameters params)
        throws InvalidCipherTextException
    {
        byte[] plaintext = new byte[1000];
        for (int i = 0; i < plaintext.length; i++)
        {
            plaintext[i] = (byte)i;
        }
        cipher.init(true, params);

        byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)];
        int len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        cipher.doFinal(ciphertext, len);

        int macLength = cipher.getMac().length;

        // Test tampering with a single byte
        cipher.init(false, params);
        byte[] tampered = new byte[ciphertext.length];
        byte[] output = new byte[plaintext.length];
        System.arraycopy(ciphertext, 0, tampered, 0, tampered.length);
        tampered[0] += 1;

        cipher.processBytes(tampered, 0, tampered.length, output, 0);
        try
        {
            cipher.doFinal(output, 0);
            throw new TestFailedException(
                new SimpleTestResult(false, test + " : tampering of ciphertext not detected."));
        }
        catch (InvalidCipherTextException e)
        {
            // Expected
        }

        // Test truncation of ciphertext to < tag length
        cipher.init(false, params);
        byte[] truncated = new byte[macLength - 1];
        System.arraycopy(ciphertext, 0, truncated, 0, truncated.length);

        cipher.processBytes(truncated, 0, truncated.length, output, 0);
        try
        {
            cipher.doFinal(output, 0);
            fail(test, "tampering of ciphertext not detected.");
        }
        catch (InvalidCipherTextException e)
        {
            // Expected
        }
    }

    private static void fail(Test test, String message)
    {
        throw new TestFailedException(SimpleTestResult.failed(test, message));
    }

    private static void fail(Test test, String message, String expected, String result)
    {
        throw new TestFailedException(SimpleTestResult.failed(test, message, expected, result));
    }

    public static void testReset(Test test, AEADBlockCipher cipher1, AEADBlockCipher cipher2, CipherParameters params)
        throws InvalidCipherTextException
    {
        cipher1.init(true, params);

        byte[] plaintext = new byte[1000];
        byte[] ciphertext = new byte[cipher1.getOutputSize(plaintext.length)];

        // Establish baseline answer
        crypt(cipher1, plaintext, ciphertext);

        // Test encryption resets
        checkReset(test, cipher1, params, true, plaintext, ciphertext);

        // Test decryption resets with fresh instance
        cipher2.init(false, params);
        checkReset(test, cipher2, params, false, ciphertext, plaintext);
    }

    private static void checkReset(Test test,
                                   AEADBlockCipher cipher,
                                   CipherParameters params,
                                   boolean encrypt,
                                   byte[] pretext,
                                   byte[] posttext)
        throws InvalidCipherTextException
    {
        // Do initial run
        byte[] output = new byte[posttext.length];
        crypt(cipher, pretext, output);

        // Check encrypt resets cipher
        crypt(cipher, pretext, output);
        if (!Arrays.areEqual(output, posttext))
        {
            fail(test, (encrypt ? "Encrypt" : "Decrypt") + " did not reset cipher.");
        }

        // Check init resets data
        cipher.processBytes(pretext, 0, 100, output, 0);
        cipher.init(encrypt, params);

        try
        {
            crypt(cipher, pretext, output);
        }
        catch (DataLengthException e)
        {
            fail(test, "Init did not reset data.");
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(test, "Init did not reset data.", new String(Hex.encode(posttext)), new String(Hex.encode(output)));
        }

        // Check init resets AD
        cipher.processAADBytes(pretext, 0, 100);
        cipher.init(encrypt, params);

        try
        {
            crypt(cipher, pretext, output);
        }
        catch (DataLengthException e)
        {
            fail(test, "Init did not reset additional data.");
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(test, "Init did not reset additional data.");
        }

        // Check reset resets data
        cipher.processBytes(pretext, 0, 100, output, 0);
        cipher.reset();

        try
        {
            crypt(cipher, pretext, output);
        }
        catch (DataLengthException e)
        {
            fail(test, "Init did not reset data.");
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(test, "Reset did not reset data.");
        }

        // Check reset resets AD
        cipher.processAADBytes(pretext, 0, 100);
        cipher.reset();

        try
        {
            crypt(cipher, pretext, output);
        }
        catch (DataLengthException e)
        {
            fail(test, "Init did not reset data.");
        }
        if (!Arrays.areEqual(output, posttext))
        {
            fail(test, "Reset did not reset additional data.");
        }
    }

    private static void crypt(AEADBlockCipher cipher, byte[] plaintext, byte[] output)
        throws InvalidCipherTextException
    {
        int len = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
        cipher.doFinal(output, len);
    }

}
