package net.sourceforge.joceanus.jgordianknot.crypto.test;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.modes.ChaChaPoly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test Cases for ChaCha20Poly1305.
 * Test Vectors taken from RFC7539 https://tools.ietf.org/html/rfc7539
 */
public class ChaCha20PolyTest
        extends SimpleTest {
    public String getName() {
        return "ChaCha20Poly1305";
    }

    public void performTest()
            throws Exception {
        new ChaChaPoly1305Test().testTheCipher();
    }

    /**
     * The TestCase.
     */
    private static class TestCase {
        /**
         * The testCase.
         */
        private final String theKey;
        private final String theIV;
        private final String theAAD;
        private final String thePlainText;
        private final String theExpected;

        /**
         * Constructor.
         * @param pKey the key
         * @param pIV the IV
         * @param pExpected the expected results.
         */
        TestCase(final String pKey,
                 final String pIV,
                 final String pExpected) {
            this(pKey, pIV, null, null, pExpected);
        }

        /**
         * Constructor.
         * @param pKey the key
         * @param pIV the IV
         * @param pPlain the plainText
         * @param pExpected the expected results.
         */
        TestCase(final String pKey,
                 final String pIV,
                 final String pPlain,
                 final String pExpected) {
            this(pKey, pIV, null, pPlain, pExpected);
        }

        /**
         * Constructor.
         * @param pKey the key
         * @param pIV the IV
         * @param pAAD the AAD
         * @param pPlain the plainText
         * @param pExpected the expected results.
         */
        TestCase(final String pKey,
                 final String pIV,
                 final String pAAD,
                 final String pPlain,
                 final String pExpected) {
            theKey = pKey;
            theIV = pIV;
            theAAD = pAAD;
            thePlainText = pPlain;
            theExpected = pExpected;
        }
    }

    /**
     * ChaCha20Poly1305.
     */
    class ChaChaPoly1305Test {
        /**
         * TestCases.
         */
        private static final String KEY = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
        private static final String IV = "070000004041424344454647";
        private static final String AAD = "50515253c0c1c2c3c4c5c6c7";
        private static final String PLAIN = "4c616469657320616e642047656e746c" +
                "656d656e206f662074686520636c6173" +
                "73206f66202739393a20496620492063" +
                "6f756c64206f6666657220796f75206f" +
                "6e6c79206f6e652074697020666f7220" +
                "746865206675747572652c2073756e73" +
                "637265656e20776f756c642062652069" +
                "742e";
        private static final String EXPECTED =
                "d31a8d34648e60db7b86afbc53ef7ec2" +
                        "a4aded51296e08fea9e2b5a736ee62d6" +
                        "3dbea45e8ca9671282fafb69da92728b" +
                        "1a71de0a9e060b2905d6a5b67ecd3b36" +
                        "92ddbd7f2d778b8c9803aee328091b58" +
                        "fab324e4fad675945585808b4831d7bc" +
                        "3ff4def08e4b7a9de576d26586cec64b" +
                        "6116" +
                        "1ae10b594f09e26a7e902ecbd0600691";
        private final TestCase TEST = new TestCase(KEY, IV, AAD,
                PLAIN, EXPECTED
        );

        /**
         * Test Cipher.
         */
        void testTheCipher() {
            final ChaChaPoly1305 myEngine = new ChaChaPoly1305(new ChaCha7539Engine());
            testAADCipher(myEngine, TEST);
        }
    }

    /**
     * Test the Cipher against the results.
     * @param pCipher the cipher to test.
     * @param pTestCase the testCase
     */
    void testAADCipher(final ChaChaPoly1305 pCipher,
                       final TestCase pTestCase) {
        try {
            /* Access the expected bytes */
            final byte[] myExpected = Hex.decode(pTestCase.theExpected);

            /* Access plainText */
            final byte[] myData = Hex.decode(pTestCase.thePlainText);

            /* Access AAD */
            final byte[] myAAD = Hex.decode(pTestCase.theAAD);

            /* Access the key and the iv */
            final KeyParameter myKey = new KeyParameter(Hex.decode(pTestCase.theKey));
            final byte[] myIV = Hex.decode(pTestCase.theIV);
            final ParametersWithIV myIVParms = new ParametersWithIV(myKey, myIV);
            final AEADParameters myAEADParms = new AEADParameters(myKey, 0, myIV, myAAD);

            /* Initialise the cipher and encrypt the data */
            pCipher.init(true, myAEADParms);
            final byte[] myOutput = new byte[pCipher.getOutputSize(myData.length)];
            int iProcessed = pCipher.processBytes(myData, 0, myData.length, myOutput, 0);
            pCipher.doFinal(myOutput, iProcessed);

            /* Check the encryption */
            isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));

            /* Check that auto-reset worked */
            iProcessed = pCipher.processBytes(myData, 0, myData.length, myOutput, 0);
            pCipher.doFinal(myOutput, iProcessed);

            /* Check the encryption */
            isTrue("Encryption mismatch after reset", Arrays.areEqual(myExpected, myOutput));

            /* Initialise the cipher and decrypt the data */
            pCipher.init(false, myAEADParms);
            final byte[] myResult = new byte[pCipher.getOutputSize(myExpected.length)];
            iProcessed = pCipher.processBytes(myExpected, 0, myExpected.length, myResult, 0);
            pCipher.doFinal(myResult, iProcessed);

            /* Check the decryption */
            isTrue("Decryption mismatch", Arrays.areEqual(myData, myResult));

            /* Loop to process differing block sizes */
            for (int blockSize = 1; blockSize <= 64; blockSize <<= 1) {
                /* Process the decryption one block at a time */
                iProcessed = 0;
                int iRemaining = myExpected.length;
                final byte[] myResult2 = new byte[pCipher.getOutputSize(myExpected.length)];
                for (int i = 0; iRemaining > 0; i += blockSize, iRemaining -= blockSize) {
                    int myLen = Math.min(blockSize, iRemaining);
                    iProcessed += pCipher.processBytes(myExpected, i, myLen, myResult2, iProcessed);
                }
                pCipher.doFinal(myResult2, iProcessed);

                /* Check the decryption */
                isTrue("Block Decryption mismatch for size " + blockSize, Arrays.areEqual(myData, myResult));
            }

            /* Initialise the cipher and encrypt the data pass AAD explicitly */
            pCipher.init(true, myIVParms);
            pCipher.processAADBytes(myAAD, 0, myAAD.length);
            final byte[] myOutput2 = new byte[pCipher.getOutputSize(myData.length)];
            iProcessed = pCipher.processBytes(myData, 0, myData.length, myOutput2, 0);
            pCipher.doFinal(myOutput2, iProcessed);

            /* Check the encryption */
            isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput2));

            /* Catch exceptions */
        } catch (InvalidCipherTextException e) {
            fail("Failed to resolve mac", e);
        }
    }
}
