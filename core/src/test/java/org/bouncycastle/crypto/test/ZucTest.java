package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Zuc128CoreEngine;
import org.bouncycastle.crypto.engines.Zuc128Engine;
import org.bouncycastle.crypto.engines.Zuc256CoreEngine;
import org.bouncycastle.crypto.engines.Zuc256Engine;
import org.bouncycastle.crypto.macs.Zuc128Mac;
import org.bouncycastle.crypto.macs.Zuc256Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test Cases for Zuc128 and Zuc256.
 * Test Vectors taken from https://www.gsma.com/aboutus/wp-content/uploads/2014/12/eea3eia3zucv16.pdf for Zuc128
 * and https://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180126529970733243.pdf for Zuc256.
 */
public class ZucTest
    extends SimpleTest
{
    private static final int INT_SIZE = 32;
    private static final int BYTE_SIZE = 8;
    
    /**
     * Test Keys and IV.
     */
    private static final String KEY128_1 =
        "00000000000000000000000000000000";
    private static final String KEY128_2 =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    private static final String KEY256_1 =
        "00000000000000000000000000000000" +
            "00000000000000000000000000000000";
    private static final String KEY256_2 =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    private static final String IV128_1 = "00000000000000000000000000000000";
    private static final String IV128_2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    private static final String IV200_1 = "00000000000000000000000000000000000000000000000000";
    private static final String IV200_2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF3F3F3F3F3F3F3F3F";

    /**
     * Define the bit limits for engines.
     */
    private static final int ZUC256LIMIT = 20000;
    private static final int ZUC128LIMIT = 65504;

    public String getName()
    {
        return "Zuc";
    }

    public void performTest()
        throws Exception
    {
        new Zuc128Test().testTheCipher();
        new Zuc256Test().testTheCipher();
        new Zuc128MacTest().testTheMac();
        new Zuc256Mac32Test().testTheMac();
        new Zuc256Mac64Test().testTheMac();
        new Zuc256Mac128Test().testTheMac();
    }

    /**
     * The TestCase.
     */
    private static class TestCase
    {
        /**
         * The testCase.
         */
        private final String theKey;
        private final String theIV;
        private final String thePlainText;
        private final String theExpected;

        /**
         * Constructor.
         *
         * @param pKey      the key
         * @param pIV       the IV
         * @param pExpected the expected results.
         */
        TestCase(final String pKey,
                 final String pIV,
                 final String pExpected)
        {
            this(pKey, pIV, null, pExpected);
        }

        /**
         * Constructor.
         *
         * @param pKey      the key
         * @param pIV       the IV
         * @param pPlain    the plainText
         * @param pExpected the expected results.
         */
        TestCase(final String pKey,
                 final String pIV,
                 final String pPlain,
                 final String pExpected)
        {
            theKey = pKey;
            theIV = pIV;
            thePlainText = pPlain;
            theExpected = pExpected;
        }
    }

    /**
     * Zuc128.
     */
    class Zuc128Test
    {
        /**
         * TestCases.
         */
        private final TestCase TEST4 = new TestCase(KEY128_1, IV128_1,
            "27bede74018082da87d4e5b69f18bf6632070e0f39b7b692b4673edc3184a48e27636f4414510d62cc15cfe194ec4f6d4b8c8fcc630648badf41b6f9d16a36ca"
        );
        private final TestCase TEST5 = new TestCase(KEY128_2, IV128_2,
            "0657cfa07096398b734b6cb4883eedf4257a76eb97595208d884adcdb1cbffb8e0f9d15846a0eed015328503351138f740d079af17296c232c4f022d6e4acac6"
        );

        /**
         * Test cipher.
         */
        void testTheCipher()
        {
            final Zuc128CoreEngine myEngine = new Zuc128Engine();
            testCipher(myEngine, TEST4);
            testCipher(myEngine, TEST5);
            testStreamLimit(myEngine, TEST5, ZUC128LIMIT);
        }
    }

    /**
     * Zuc256.
     */
    class Zuc256Test
    {
        /**
         * TestCases.
         */
        private final TestCase TEST4 = new TestCase(KEY256_1, IV200_1,
            "58d03ad62e032ce2dafc683a39bdcb0352a2bc67f1b7de74163ce3a101ef55589639d75b95fa681b7f090df756391ccc903b7612744d544c17bc3fad8b163b08"
        );
        private final TestCase TEST5 = new TestCase(KEY256_2, IV200_2,
            "3356cbaed1a1c18b6baa4ffe343f777c9e15128f251ab65b949f7b26ef7157f296dd2fa9df95e3ee7a5be02ec32ba585505af316c2f9ded27cdbd935e441ce11"
        );

        /**
         * Test cipher.
         */
        void testTheCipher()
        {
            final Zuc256CoreEngine myEngine = new Zuc256Engine();
            testCipher(myEngine, TEST4);
            testCipher(myEngine, TEST5);
            testStreamLimit(myEngine, TEST5, ZUC256LIMIT);
        }
    }

    /**
     * Zuc128Mac.
     */
    class Zuc128MacTest
    {

        /**
         * TestCases.
         */
        private final TestCase TEST1 = new TestCase(KEY128_1, IV128_1,
            "508dd5ff"
        );
        private final TestCase TEST2 = new TestCase(KEY128_1, IV128_1,
            "fbed4c12"
        );
        private final TestCase TEST3 = new TestCase(KEY128_2, IV128_2,
            "55e01504"
        );
        private final TestCase TEST4 = new TestCase(KEY128_2, IV128_2,
            "9ce9a0c4"
        );

        /**
         * Test Mac.
         */
        void testTheMac()
        {
            final Zuc128Mac myMac = new Zuc128Mac();
            testMac(myMac, false, TEST1);
            testMac(myMac, true, TEST2);
            testMac(myMac, false, TEST3);
            testMac(myMac, true, TEST4);
            testMacLimit(myMac, TEST4, ZUC128LIMIT - (2 * INT_SIZE));

            // reset without init().
            Zuc128Mac xMac = new Zuc128Mac();

            xMac.reset();
        }
    }

    /**
     * Zuc256Mac32.
     */
    class Zuc256Mac32Test
    {
        /**
         * TestCases.
         */
        private final TestCase TEST1 = new TestCase(KEY256_1, IV200_1,
            "9b972a74"
        );
        private final TestCase TEST2 = new TestCase(KEY256_1, IV200_1,
            "8754f5cf"
        );
        private final TestCase TEST3 = new TestCase(KEY256_2, IV200_2,
            "1f3079b4"
        );
        private final TestCase TEST4 = new TestCase(KEY256_2, IV200_2,
            "5c7c8b88"
        );

        /**
         * Test Mac.
         */
        void testTheMac()
        {
            final Zuc256Mac myMac = new Zuc256Mac(32);
            testMac(myMac, false, TEST1);
            testMac(myMac, true, TEST2);
            testMac(myMac, false, TEST3);
            testMac(myMac, true, TEST4);
            testMacLimit(myMac, TEST4, ZUC256LIMIT - (2 * myMac.getMacSize() * BYTE_SIZE));

            // reset without init().
            Zuc256Mac xMac = new Zuc256Mac(32);

            xMac.reset();
        }
    }

    /**
     * Zuc256Mac64.
     */
    class Zuc256Mac64Test
    {
        /**
         * TestCases.
         */
        private final TestCase TEST1 = new TestCase(KEY256_1, IV200_1,
            "673e54990034d38c"
        );
        private final TestCase TEST2 = new TestCase(KEY256_1, IV200_1,
            "130dc225e72240cc"
        );
        private final TestCase TEST3 = new TestCase(KEY256_2, IV200_2,
            "8c71394d39957725"
        );
        private final TestCase TEST4 = new TestCase(KEY256_2, IV200_2,
            "ea1dee544bb6223b"
        );

        /**
         * Test Mac.
         */
        void testTheMac()
        {
            final Zuc256Mac myMac = new Zuc256Mac(64);
            testMac(myMac, false, TEST1);
            testMac(myMac, true, TEST2);
            testMac(myMac, false, TEST3);
            testMac(myMac, true, TEST4);
            testMacLimit(myMac, TEST4, ZUC256LIMIT - (2 * myMac.getMacSize() * BYTE_SIZE));
        }
    }

    /**
     * Zuc256Mac128.
     */
    class Zuc256Mac128Test
    {
        /**
         * TestCases.
         */
        private final TestCase TEST1 = new TestCase(KEY256_1, IV200_1,
            "d85e54bbcb9600967084c952a1654b26"
        );
        private final TestCase TEST2 = new TestCase(KEY256_1, IV200_1,
            "df1e8307b31cc62beca1ac6f8190c22f"
        );
        private final TestCase TEST3 = new TestCase(KEY256_2, IV200_2,
            "a35bb274b567c48b28319f111af34fbd"
        );
        private final TestCase TEST4 = new TestCase(KEY256_2, IV200_2,
            "3a83b554be408ca5494124ed9d473205"
        );

        /**
         * Test Mac.
         */
        void testTheMac()
        {
            final Zuc256Mac myMac = new Zuc256Mac(128);
            testMac(myMac, false, TEST1);
            testMac(myMac, true, TEST2);
            testMac(myMac, false, TEST3);
            testMac(myMac, true, TEST4);
            testMacLimit(myMac, TEST4, ZUC256LIMIT - (2 * myMac.getMacSize() * BYTE_SIZE));
        }
    }

    /**
     * Test the Cipher against the results.
     *
     * @param pCipher   the cipher to test.
     * @param pTestCase the testCase
     */
    void testCipher(final StreamCipher pCipher,
                    final TestCase pTestCase)
    {
        /* Access the expected bytes */
        final byte[] myExpected = Hex.decode(pTestCase.theExpected);

        /* Create the output buffer */
        final byte[] myOutput = new byte[myExpected.length];

        /* Access plainText or nulls */
        final byte[] myData = pTestCase.thePlainText != null
            ? Hex.decode(pTestCase.thePlainText)
            : new byte[myExpected.length];

        /* Access the key and the iv */
        final KeyParameter myKey = new KeyParameter(Hex.decode(pTestCase.theKey));
        final byte[] myIV = Hex.decode(pTestCase.theIV);
        final ParametersWithIV myParms = new ParametersWithIV(myKey, myIV);

        /* Initialise the cipher and create the keyStream */
        pCipher.init(true, myParms);
        pCipher.processBytes(myData, 0, myData.length, myOutput, 0);

        /* Check the encryption */
        isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));
    }

    /**
     * Test the Mac against the results.
     *
     * @param pMac      the mac to test.
     * @param pOnes     use all ones as data?
     * @param pTestCase the testCase
     */
    void testMac(final Mac pMac,
                 final boolean pOnes,
                 final TestCase pTestCase)
    {
        /* Access the expected bytes */
        final byte[] myExpected = Hex.decode(pTestCase.theExpected);

        /* Create the output buffer and the data */
        final byte[] myOutput = new byte[pMac.getMacSize()];
        final byte[] myData = new byte[(pOnes ? 4000 : 400) / 8];
        Arrays.fill(myData, (byte)(pOnes ? 0x11 : 0));

        /* Access the key and the iv */
        final KeyParameter myKey = new KeyParameter(Hex.decode(pTestCase.theKey));
        final byte[] myIV = Hex.decode(pTestCase.theIV);
        final ParametersWithIV myParms = new ParametersWithIV(myKey, myIV);

        /* Initialise the cipher and create the keyStream */
        pMac.init(myParms);
        pMac.update(myData, 0, myData.length);
        pMac.doFinal(myOutput, 0);

        /* Check the mac */
        isTrue("Mac mismatch", Arrays.areEqual(myExpected, myOutput));

        /* Check doFinal reset */
        pMac.update(myData, 0, myData.length);
        pMac.doFinal(myOutput, 0);

        isTrue("DoFinal Mac mismatch", Arrays.areEqual(myExpected, myOutput));

        /* Check reset() */
        pMac.update(myData, 0, myData.length);

        pMac.reset();

        pMac.update(myData, 0, myData.length);
        pMac.doFinal(myOutput, 0);

        isTrue("Reset Mac mismatch", Arrays.areEqual(myExpected, myOutput));
    }

    /**
     * Test the Stream Cipher against the limit.
     *
     * @param pCipher   the cipher to test.
     * @param pTestCase the testCase
     * @param pLimit    the limit in bits.
     */
    void testStreamLimit(final StreamCipher pCipher,
                         final TestCase pTestCase,
                         final int pLimit)
    {
        /* Check the limit is a whole number of integers */
        isTrue("Invalid limit", (pLimit % INT_SIZE == 0));
        final int myNumBytes = pLimit / BYTE_SIZE;

        /* Create the maximum # of bytes */
        final byte[] myData = new byte[myNumBytes];
        final byte[] myOutput = new byte[myNumBytes];

        /* Access the key and the iv */
        final KeyParameter myKey = new KeyParameter(Hex.decode(pTestCase.theKey));
        final byte[] myIV = Hex.decode(pTestCase.theIV);
        final ParametersWithIV myParms = new ParametersWithIV(myKey, myIV);

        /* Initialise the cipher and create the keyStream */
        pCipher.init(true, myParms);
        pCipher.processBytes(myData, 0, myData.length, myOutput, 0);

        /* Check that next encryption throws exception */
        try
        {
            pCipher.processBytes(myData, 0, 1, myOutput, 0);
            fail("Limit Failure");
        }
        catch (IllegalStateException e)
        {
            /* OK */
        }
    }

    /**
     * Test the Mac against the limit.
     *
     * @param pMac      the mac to test.
     * @param pTestCase the testCase
     * @param pLimit    the limit in bits.
     */
    void testMacLimit(final Mac pMac,
                      final TestCase pTestCase,
                      final int pLimit)
    {
        /* Check the limit is a whole numbet of integers */
        isTrue("Invalid limit", (pLimit % INT_SIZE == 0));
        final int myNumBytes = pLimit / BYTE_SIZE;

        /* Create the maximum # of bytes */
        final byte[] myData = new byte[myNumBytes];
        final byte[] myOutput = new byte[myNumBytes];

        /* Access the key and the iv */
        final KeyParameter myKey = new KeyParameter(Hex.decode(pTestCase.theKey));
        final byte[] myIV = Hex.decode(pTestCase.theIV);
        final ParametersWithIV myParms = new ParametersWithIV(myKey, myIV);

        /* Initialise the mac and create the result */
        pMac.init(myParms);
        pMac.update(myData, 0, myData.length);
        pMac.doFinal(myOutput, 0);

        /* Initialise the mac and process as much data as possible */
        pMac.init(myParms);
        pMac.update(myData, 0, myData.length);

        /* We expect a failure on processing a further byte */
        try
        {
            pMac.update(myData, 0, 1);
            pMac.doFinal(myOutput, 0);
            fail("Limit Failure");
        }
        catch (IllegalStateException e)
        {
            /* OK */
        }
    }

    /**
     * Main entry point.
     *
     * @param args the argyments
     */
    public static void main(String[] args)
    {
        runTest(new ZucTest());
    }
}
