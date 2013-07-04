package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors from the "work in progress" Internet-Draft <a
 * href="http://tools.ietf.org/html/draft-irtf-cfrg-ocb-03">The OCB Authenticated-Encryption
 * Algorithm</a>
 */
public class OCBTest
    extends SimpleTest
{

    private static final String K = "000102030405060708090A0B0C0D0E0F";
    private static final String N = "000102030405060708090A0B";

    // Each test vector contains the strings A, P, C in order
    private static final String[][] TEST_VECTORS = new String[][]{
        {"", "", "197B9C3C441D3C83EAFB2BEF633B9182"},
        {"0001020304050607", "0001020304050607",
            "92B657130A74B85A16DC76A46D47E1EAD537209E8A96D14E"},
        {"0001020304050607", "", "98B91552C8C009185044E30A6EB2FE21"},
        {"", "0001020304050607", "92B657130A74B85A971EFFCAE19AD4716F88E87B871FBEED"},
        {"000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F",
            "BEA5E8798DBE7110031C144DA0B26122776C9924D6723A1F" + "C4524532AC3E5BEB"},
        {"000102030405060708090A0B0C0D0E0F", "", "7DDB8E6CEA6814866212509619B19CC6"},
        {"", "000102030405060708090A0B0C0D0E0F",
            "BEA5E8798DBE7110031C144DA0B2612213CC8B747807121A" + "4CBB3E4BD6B456AF"},
        {"000102030405060708090A0B0C0D0E0F1011121314151617",
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "BEA5E8798DBE7110031C144DA0B26122FCFCEE7A2A8D4D48" + "5FA94FC3F38820F1DC3F3D1FD4E55E1C"},
        {"000102030405060708090A0B0C0D0E0F1011121314151617", "",
            "282026DA3068BC9FA118681D559F10F6"},
        {"", "000102030405060708090A0B0C0D0E0F1011121314151617",
            "BEA5E8798DBE7110031C144DA0B26122FCFCEE7A2A8D4D48" + "6EF2F52587FDA0ED97DC7EEDE241DF68"},
        {
            "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F",
            "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6"
                + "57149D53773463CBB2A040DD3BD5164372D76D7BB6824240"},
        {"000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F", "",
            "E1E072633BADE51A60E85951D9C42A1B"},
        {
            "",
            "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F",
            "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6"
                + "57149D53773463CB4A3BAE824465CFDAF8C41FC50C7DF9D9"},
        {
            "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627",
            "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627",
            "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6"
                + "57149D53773463CB68C65778B058A635659C623211DEEA0D" + "E30D2C381879F4C8"},
        {"000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627",
            "", "7AEB7A69A1687DD082CA27B0D9A37096"},
        {
            "",
            "000102030405060708090A0B0C0D0E0F1011121314151617" + "18191A1B1C1D1E1F2021222324252627",
            "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A6"
                + "57149D53773463CB68C65778B058A635060C8467F4ABAB5E" + "8B3C2067A2E115DC"},

    };

    public String getName()
    {
        return "OCB";
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i < TEST_VECTORS.length; ++i)
        {
            runTestCase("Test Case " + i, TEST_VECTORS[i]);
        }

        runLongerTestCase(128, 128, Hex.decode("B2B41CBF9B05037DA7F16C24A35C1C94"));
        runLongerTestCase(192, 128, Hex.decode("1529F894659D2B51B776740211E7D083"));
        runLongerTestCase(256, 128, Hex.decode("42B83106E473C0EEE086C8D631FD4C7B"));
        runLongerTestCase(128, 96, Hex.decode("1A4F0654277709A5BDA0D380"));
        runLongerTestCase(192, 96, Hex.decode("AD819483E01DD648978F4522"));
        runLongerTestCase(256, 96, Hex.decode("CD2E41379C7E7C4458CCFB4A"));
        runLongerTestCase(128, 64, Hex.decode("B7ECE9D381FE437F"));
        runLongerTestCase(192, 64, Hex.decode("DE0574C87FF06DF9"));
        runLongerTestCase(256, 64, Hex.decode("833E45FF7D332F7E"));

        testExceptions();
    }

    private void testExceptions() throws InvalidCipherTextException
    {
        OCBBlockCipher ocb = new OCBBlockCipher(new AESFastEngine(), new AESFastEngine());

        try
        {
            ocb = new OCBBlockCipher(new DESEngine(), new DESEngine());
            
            fail("incorrect block size not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            ocb.init(false, new KeyParameter(new byte[16]));

            fail("illegal argument not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        AEADTestUtil.testReset(this, new OCBBlockCipher(new AESEngine(), new AESEngine()), new OCBBlockCipher(new AESEngine(), new AESEngine()), new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[15]));
        AEADTestUtil.testTampering(this, ocb, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[15]));
    }
    
    private void runTestCase(String testName, String[] testVector)
        throws InvalidCipherTextException
    {

        runTestCase(testName, testVector, 128);
    }

    private void runTestCase(String testName, String[] testVector, int macLengthBits)
        throws InvalidCipherTextException
    {

        byte[] key = Hex.decode(K);
        byte[] nonce = Hex.decode(N);

        int pos = 0;
        byte[] A = Hex.decode(testVector[pos++]);
        byte[] P = Hex.decode(testVector[pos++]);
        byte[] C = Hex.decode(testVector[pos++]);

        int macLengthBytes = macLengthBits / 8;

        // TODO Variations processing AAD and cipher bytes incrementally

        KeyParameter keyParameter = new KeyParameter(key);
        AEADParameters aeadParameters = new AEADParameters(keyParameter, macLengthBits, nonce, A);

        OCBBlockCipher encCipher = initCipher(true, aeadParameters);
        OCBBlockCipher decCipher = initCipher(false, aeadParameters);

        checkTestCase(encCipher, decCipher, testName, macLengthBytes, P, C);
        checkTestCase(encCipher, decCipher, testName + " (reused)", macLengthBytes, P, C);

        // TODO Key reuse
    }

    private OCBBlockCipher initCipher(boolean forEncryption, AEADParameters parameters)
    {
        OCBBlockCipher c = new OCBBlockCipher(new AESFastEngine(), new AESFastEngine());
        c.init(forEncryption, parameters);
        return c;
    }

    private void checkTestCase(OCBBlockCipher encCipher, OCBBlockCipher decCipher, String testName,
                               int macLengthBytes, byte[] P, byte[] C)
        throws InvalidCipherTextException
    {

        byte[] tag = Arrays.copyOfRange(C, C.length - macLengthBytes, C.length);

        {
            byte[] enc = new byte[encCipher.getOutputSize(P.length)];
            int len = encCipher.processBytes(P, 0, P.length, enc, 0);
            len += encCipher.doFinal(enc, len);

            if (enc.length != len)
            {
                fail("encryption reported incorrect length: " + testName);
            }

            if (!areEqual(C, enc))
            {
                fail("incorrect encrypt in: " + testName);
            }

            if (!areEqual(tag, encCipher.getMac()))
            {
                fail("getMac() not the same as the appended tag: " + testName);
            }
        }

        {
            byte[] dec = new byte[decCipher.getOutputSize(C.length)];
            int len = decCipher.processBytes(C, 0, C.length, dec, 0);
            len += decCipher.doFinal(dec, len);

            if (dec.length != len)
            {
                fail("decryption reported incorrect length: " + testName);
            }

            if (!areEqual(P, dec))
            {
                fail("incorrect decrypt in: " + testName);
            }

            if (!areEqual(tag, decCipher.getMac()))
            {
                fail("getMac() not the same as the appended tag: " + testName);
            }
        }
    }

    private void runLongerTestCase(int aesKeySize, int tagLen, byte[] expectedOutput)
        throws InvalidCipherTextException
    {
        KeyParameter key = new KeyParameter(new byte[aesKeySize / 8]);
        byte[] N = new byte[12];

        AEADBlockCipher c1 = new OCBBlockCipher(new AESFastEngine(), new AESFastEngine());
        c1.init(true, new AEADParameters(key, tagLen, N));

        AEADBlockCipher c2 = new OCBBlockCipher(new AESFastEngine(), new AESFastEngine());

        long total = 0;

        byte[] S = new byte[128];

        for (int i = 0; i < 128; ++i)
        {
            N[11] = (byte)i;

            c2.init(true, new AEADParameters(key, tagLen, N));

            total += updateCiphers(c1, c2, S, i, true, true);
            total += updateCiphers(c1, c2, S, i, false, true);
            total += updateCiphers(c1, c2, S, i, true, false);
        }

        long expectedTotal = 16256 + (48 * tagLen);

        if (total != expectedTotal)
        {
            fail("test generated the wrong amount of input: " + total);
        }

        byte[] output = new byte[c1.getOutputSize(0)];
        c1.doFinal(output, 0);

        if (!areEqual(expectedOutput, output))
        {
            fail("incorrect encrypt in long-form test");
        }
    }

    private int updateCiphers(AEADBlockCipher c1, AEADBlockCipher c2, byte[] S, int i,
                              boolean includeAAD, boolean includePlaintext)
        throws InvalidCipherTextException
    {

        int inputLen = includePlaintext ? i : 0;
        int outputLen = c2.getOutputSize(inputLen);

        byte[] output = new byte[outputLen];

        int len = 0;

        if (includeAAD)
        {
            c2.processAADBytes(S, 0, i);
        }

        if (includePlaintext)
        {
            len += c2.processBytes(S, 0, i, output, len);
        }

        len += c2.doFinal(output, len);

        c1.processAADBytes(output, 0, len);

        return len;
    }

    public static void main(String[] args)
    {
        runTest(new OCBTest());
    }
}
