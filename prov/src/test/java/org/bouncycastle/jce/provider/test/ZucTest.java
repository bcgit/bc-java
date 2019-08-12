package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class ZucTest
    extends SimpleTest
{
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

    private final TestCase ZUC128_TEST1 = new TestCase(KEY128_1, IV128_1,
        "27bede74018082da87d4e5b69f18bf6632070e0f39b7b692b4673edc3184a48e27636f4414510d62cc15cfe194ec4f6d4b8c8fcc630648badf41b6f9d16a36ca"
    );
    private final TestCase ZUC128_TEST2 = new TestCase(KEY128_2, IV128_2,
        "0657cfa07096398b734b6cb4883eedf4257a76eb97595208d884adcdb1cbffb8e0f9d15846a0eed015328503351138f740d079af17296c232c4f022d6e4acac6"
    );
    private final TestCase ZUC256_TEST1 = new TestCase(KEY256_1, IV200_1,
        "58d03ad62e032ce2dafc683a39bdcb0352a2bc67f1b7de74163ce3a101ef55589639d75b95fa681b7f090df756391ccc903b7612744d544c17bc3fad8b163b08"
    );
    private final TestCase ZUC256_TEST2 = new TestCase(KEY256_2, IV200_2,
        "3356cbaed1a1c18b6baa4ffe343f777c9e15128f251ab65b949f7b26ef7157f296dd2fa9df95e3ee7a5be02ec32ba585505af316c2f9ded27cdbd935e441ce11"
    );

    private final TestCase MAC128_TEST1 = new TestCase(KEY128_1, IV128_1, "508dd5ff");
    private final TestCase MAC128_TEST2 = new TestCase(KEY128_1, IV128_1, "fbed4c12");
    private final TestCase MAC256_TEST1 = new TestCase(KEY256_1, IV200_1, "d85e54bbcb9600967084c952a1654b26");
    private final TestCase MAC256_TEST2 = new TestCase(KEY256_1, IV200_1, "df1e8307b31cc62beca1ac6f8190c22f");
    private final TestCase MAC256_64_TEST1 = new TestCase(KEY256_1, IV200_1, "673e54990034d38c");
    private final TestCase MAC256_64_TEST2 = new TestCase(KEY256_1, IV200_1, "130dc225e72240cc");
    private final TestCase MAC256_32_TEST1 = new TestCase(KEY256_1, IV200_1, "9b972a74");
    private final TestCase MAC256_32_TEST2 = new TestCase(KEY256_1, IV200_1, "8754f5cf");
    
    public String getName()
    {
        return "Zuc";
    }

    /**
     * Test the Cipher against the results.
     *
     * @param pCipher   the cipher to test.
     * @param pTestCase the testCase
     */
    void testCipher(final Cipher pCipher,
                    final TestCase pTestCase)
    throws Exception
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
        final SecretKey myKey = new SecretKeySpec(Hex.decode(pTestCase.theKey), pCipher.getAlgorithm());
        final byte[] myIV = Hex.decode(pTestCase.theIV);

        /* Initialise the cipher and create the keyStream */
        pCipher.init(Cipher.ENCRYPT_MODE, myKey, new IvParameterSpec(myIV));

        pCipher.doFinal(myData, 0, myData.length, myOutput, 0);

        /* Check the encryption */
        isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));

        AlgorithmParameters algParams = AlgorithmParameters.getInstance(pCipher.getAlgorithm(), "BC");

        algParams.init(new IvParameterSpec(myIV));

        pCipher.init(Cipher.DECRYPT_MODE, myKey, algParams);

        pCipher.doFinal(myData, 0, myData.length, myOutput, 0);
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
        throws Exception
    {
        /* Access the expected bytes */
        final byte[] myExpected = Hex.decode(pTestCase.theExpected);

        /* Create the output buffer and the data */
        final byte[] myOutput = new byte[pMac.getMacLength()];

        isTrue("Mac length mismatch", myExpected.length == myOutput.length);

        final byte[] myData = new byte[(pOnes ? 4000 : 400) / 8];
        Arrays.fill(myData, (byte)(pOnes ? 0x11 : 0));

        /* Access the key and the iv */
        final SecretKey myKey = new SecretKeySpec(Hex.decode(pTestCase.theKey), pMac.getAlgorithm());
        final byte[] myIV = Hex.decode(pTestCase.theIV);

        /* Initialise the cipher and create the keyStream */
        pMac.init(myKey, new IvParameterSpec(myIV));
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

    private void simpleTest(Cipher zuc)
        throws Exception
    {
        KeyGenerator kGen = KeyGenerator.getInstance(zuc.getAlgorithm(), "BC");
        byte[] msg = Strings.toByteArray("Hello, world!");
        SecretKey k = kGen.generateKey();

        zuc.init(Cipher.ENCRYPT_MODE, k);

        byte[] enc = zuc.doFinal(msg);

        byte[] iv = zuc.getIV();
        AlgorithmParameters algParam = zuc.getParameters();

        zuc.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));

        byte[] dec = zuc.doFinal(enc);

        areEqual(msg, dec);

        zuc.init(Cipher.DECRYPT_MODE, k, algParam);

        dec = zuc.doFinal(enc);

        areEqual(msg, dec);
    }

    public void performTest()
        throws Exception
    {
        final Cipher zuc128 = Cipher.getInstance("Zuc-128", "BC");
        testCipher(zuc128, ZUC128_TEST1);
        testCipher(zuc128, ZUC128_TEST2);

        simpleTest(zuc128);

        final Cipher zuc256 = Cipher.getInstance("Zuc-256", "BC");
        testCipher(zuc256, ZUC256_TEST1);
        testCipher(zuc256, ZUC256_TEST2);

        simpleTest(zuc256);

        final Mac mac128 = Mac.getInstance("Zuc-128", "BC");

        // check reset
        mac128.reset();

        testMac(mac128, false, MAC128_TEST1);
        testMac(mac128, true, MAC128_TEST2);

        final Mac mac256 = Mac.getInstance("Zuc-256", "BC");

        // check reset
        mac256.reset();
        
        testMac(mac256, false, MAC256_TEST1);
        testMac(mac256, true, MAC256_TEST2);

        final Mac mac256_128 = Mac.getInstance("Zuc-256-128", "BC");

        testMac(mac256_128, false, MAC256_TEST1);
        testMac(mac256_128, true, MAC256_TEST2);

        final Mac mac256_64 = Mac.getInstance("Zuc-256-64", "BC");

        testMac(mac256_64, false, MAC256_64_TEST1);
        testMac(mac256_64, true, MAC256_64_TEST2);

        final Mac mac256_32 = Mac.getInstance("Zuc-256-32", "BC");

        testMac(mac256_32, false, MAC256_32_TEST1);
        testMac(mac256_32, true, MAC256_32_TEST2);
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

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test test = new ZucTest();
        TestResult result = test.perform();

        System.out.println(result.toString());
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}
