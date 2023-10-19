package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test Cases for LEA Cipher.
 * Test Vectors taken from https://en.wikipedia.org/wiki/LEA_(cipher).html
 */
public class LEATest
    extends SimpleTest
{
    public String getName()
    {
        return "LEA";
    }

    public void performTest()
        throws Exception
    {
        testFromVectorFile();
        new LEA128Test().testTheCipher(this);
        new LEA192Test().testTheCipher(this);
        new LEA256Test().testTheCipher(this);
    }

    /**
     * Test the Cipher against the results.
     *
     * @param pCipher   the cipher to test.
     * @param pKey      the key to test
     * @param pData     the data to test
     * @param pExpected the expected results
     */
    void testCipher(final BlockCipher pCipher,
                    final String pKey,
                    final String pData,
                    final String pExpected)
    {
        /* Create the output buffer */
        final byte[] myOutput = new byte[pCipher.getBlockSize()];
        final byte[] myFinal = new byte[pCipher.getBlockSize()];

        /* Access the key and the data */
        final KeyParameter myKey = new KeyParameter(Hex.decode(pKey));
        final byte[] myData = Hex.decode(pData);

        /* Initialise the cipher */
        pCipher.init(true, myKey);
        pCipher.processBlock(myData, 0, myOutput, 0);

        /* Check the encryption */
        final byte[] myExpected = Hex.decode(pExpected);
        isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));

        /* Initialise the cipher */
        pCipher.init(false, myKey);
        pCipher.processBlock(myOutput, 0, myFinal, 0);
        isTrue("Decryption mismatch", Arrays.areEqual(myData, myFinal));
    }

    /**
     * LEA128.
     */
    static class LEA128Test
    {
        /**
         * Test details.
         */
        private static final String KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        private static final String TESTDATA = "101112131415161718191a1b1c1d1e1f";
        private static final String EXPECTED = "9fc84e3528c6c6185532c7a704648bfd";

        /**
         * Test cipher.
         */
        void testTheCipher(final LEATest pTest)
        {
            pTest.testCipher(new LEAEngine(), KEY, TESTDATA, EXPECTED);
        }
    }

    /**
     * LEA192.
     */
    static class LEA192Test
    {
        /**
         * Test details.
         */
        private static final String KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687";
        private static final String TESTDATA = "202122232425262728292a2b2c2d2e2f";
        private static final String EXPECTED = "6fb95e325aad1b878cdcf5357674c6f2";

        /**
         * Test cipher.
         */
        void testTheCipher(final LEATest pTest)
        {
            pTest.testCipher(new LEAEngine(), KEY, TESTDATA, EXPECTED);
        }
    }

    /**
     * LEA256.
     */
    static class LEA256Test
    {
        /**
         * Test details.
         */
        private static final String KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f";
        private static final String TESTDATA = "303132333435363738393a3b3c3d3e3f";
        private static final String EXPECTED = "d651aff647b189c13a8900ca27f9e197";

        /**
         * Test cipher.
         */
        void testTheCipher(final LEATest pTest)
        {
            pTest.testCipher(new LEAEngine(), KEY, TESTDATA, EXPECTED);
        }
    }

    /**
     * Execute test vector file.
     *
     * @throws Exception
     */
    public void testFromVectorFile()
        throws Exception
    {

        BufferedReader bin = new BufferedReader(new InputStreamReader(TestResourceFinder.findTestResource("crypto", "lea.txt")));
        String line;

        String comment = null;
        byte[] key = null;
        byte[] plainText = null;
        byte[] cipherText = null;
        byte[] iv = null;


        while ((line = bin.readLine()) != null)
        {
            line = line.trim();
            if (line.length() == 0 || line.startsWith("#"))
            {
                continue;
            }

            if (line.startsWith("Comment:"))
            {
                comment = line.substring(line.indexOf(":") + 1).trim();
            }
            else if (line.startsWith("Key:"))
            {
                line = remove(remove(line, "0x"), ", ").trim();
                key = Hex.decode(line.substring(line.indexOf(":") + 1).trim());
            }
            else if (line.startsWith("Plaintext:"))
            {
                line = remove(remove(line, "0x"), ", ").trim();
                plainText = Hex.decode(line.substring(line.indexOf(":") + 1).trim());
            }
            else if (line.startsWith("Ciphertext:"))
            {
                line = remove(remove(line, "0x"), ", ").trim();
                cipherText = Hex.decode(line.substring(line.indexOf(":") + 1).trim());
            }
            else if (line.startsWith("IV:"))
            {
                line = remove(remove(line, "0x"), ", ").trim();
                iv = Hex.decode(line.substring(line.indexOf(":") + 1).trim());
            }
            else if (line.startsWith("Test:"))
            {
                if (comment.indexOf("ECB") >= 0)
                {
                    LEAEngine engine = new LEAEngine();
                    if (line.endsWith("Encrypt"))
                    {
                        engine.init(true, new KeyParameter(key));
                        byte[] result = new byte[cipherText.length];
                        int l = 0;
                        while (l < result.length)
                        {
                            l += engine.processBlock(plainText, l, result, l);
                        }

                        isTrue(comment + " cipher text must match vector", Arrays.areEqual(result, cipherText));
                    }
                    else if (line.endsWith("Decrypt"))
                    {
                        engine.init(false, new KeyParameter(key));
                        byte[] result = new byte[plainText.length];
                        int l = 0;

                        while (l < result.length)
                        {
                            l += engine.processBlock(cipherText, l, result, l);
                        }

                        isTrue(comment + " plain text must match", Arrays.areEqual(result, plainText));
                    }

                }
                else if (comment.indexOf("CTR") >= 0 || comment.indexOf("CBC") >= 0)
                {
                    BlockCipher engine;

                    if (comment.indexOf("CBC") >= 0)
                    {
                        engine = CBCBlockCipher.newInstance(new LEAEngine());
                    }
                    else
                    {
                        // CTR
                        engine = SICBlockCipher.newInstance(new LEAEngine());
                    }
                    if (line.endsWith("Encrypt"))
                    {
                        engine.init(true, new ParametersWithIV(new KeyParameter(key), iv));
                        byte[] result = new byte[cipherText.length];
                        int l = 0;
                        while (l < result.length)
                        {
                            l += engine.processBlock(plainText, l, result, l);
                        }

                        isTrue(comment + " cipher text must match vector", Arrays.areEqual(result, cipherText));
                    }
                    else if (line.endsWith("Decrypt"))
                    {
                        engine.init(false, new ParametersWithIV(new KeyParameter(key), iv));
                        byte[] result = new byte[plainText.length];
                        int l = 0;

                        while (l < result.length)
                        {
                            l += engine.processBlock(cipherText, l, result, l);
                        }

                        isTrue(comment + " plain text must match", Arrays.areEqual(result, plainText));
                    }
                }
                else
                {
                    throw new IllegalStateException("unknown mode");
                }


            }

        }

    }

    private static String remove(String orig, String txt)
    {
        int idx = -1;
        while ((idx = orig.indexOf(txt)) >= 0)
        {
            orig = orig.substring(0, idx) + orig.substring(idx + txt.length());
        }

        return orig;
    }

    /**
     * Main entry point.
     *
     * @param args the argyments
     */
    public static void main(String[] args)
    {
        runTest(new LEATest());
    }
}
