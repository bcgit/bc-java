package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Times;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors from <a href="https://tools.ietf.org/html/rfc7253">RFC 7253 on The OCB
 * Authenticated-Encryption Algorithm</a>
 */
public class OCBTest
    extends SimpleTest
{
    private static final String KEY_128 = "000102030405060708090A0B0C0D0E0F";
    private static final String KEY_96 = "0F0E0D0C0B0A09080706050403020100";

    /*
     * Test vectors from Appendix A of the specification, containing the strings N, A, P, C in order
     */

    private static final String[][] TEST_VECTORS_128 = new String[][]{
        { "BBAA99887766554433221100",
          "",
          "",
          "785407BFFFC8AD9EDCC5520AC9111EE6" },
        { "BBAA99887766554433221101",
          "0001020304050607",
          "0001020304050607",
          "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009" },
        { "BBAA99887766554433221102",
          "0001020304050607",
          "",
          "81017F8203F081277152FADE694A0A00" },
        { "BBAA99887766554433221103",
          "",
          "0001020304050607",
          "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9" },
        { "BBAA99887766554433221104",
          "000102030405060708090A0B0C0D0E0F",
          "000102030405060708090A0B0C0D0E0F",
          "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358" },
        { "BBAA99887766554433221105",
          "000102030405060708090A0B0C0D0E0F",
          "",
          "8CF761B6902EF764462AD86498CA6B97" },
        { "BBAA99887766554433221106",
          "",
          "000102030405060708090A0B0C0D0E0F",
          "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D" },
        { "BBAA99887766554433221107",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F" },
        { "BBAA99887766554433221108",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "",
          "6DC225A071FC1B9F7C69F93B0F1E10DE" },
        { "BBAA99887766554433221109",
          "",
          "000102030405060708090A0B0C0D0E0F1011121314151617",
          "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF" },
        { "BBAA9988776655443322110A",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240" },
        { "BBAA9988776655443322110B",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "",
          "FE80690BEE8A485D11F32965BC9D2A32" },
        { "BBAA9988776655443322110C",
          "",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF" },
        { "BBAA9988776655443322110D",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
          "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60" },
        { "BBAA9988776655443322110E",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
          "",
          "C5CD9D1850C141E358649994EE701B68" },
        { "BBAA9988776655443322110F",
          "",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
          "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479" },
    };

    private static final String[][] TEST_VECTORS_96 = new String[][]{
        { "BBAA9988776655443322110D",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
          "1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FDAC4F02AA" },
    };

    public String getName()
    {
        return "OCB";
    }

    public void performTest()
        throws Exception
    {
        byte[] K128 = Hex.decode(KEY_128);
        for (int i = 0; i < TEST_VECTORS_128.length; ++i)
        {
            runTestCase("Test Case " + i, TEST_VECTORS_128[i], 128, K128);
        }

        byte[] K96 = Hex.decode(KEY_96);
        for (int i = 0; i < TEST_VECTORS_96.length; ++i)
        {
            runTestCase("Test Case " + i, TEST_VECTORS_96[i], 96, K96);
        }

        runLongerTestCase(128, 128, "67E944D23256C5E0B6C61FA22FDF1EA2");
        runLongerTestCase(192, 128, "F673F2C3E7174AAE7BAE986CA9F29E17");
        runLongerTestCase(256, 128, "D90EB8E9C977C88B79DD793D7FFA161C");
        runLongerTestCase(128, 96, "77A3D8E73589158D25D01209");
        runLongerTestCase(192, 96, "05D56EAD2752C86BE6932C5E");
        runLongerTestCase(256, 96, "5458359AC23B0CBA9E6330DD");
        runLongerTestCase(128, 64, "192C9B7BD90BA06A");
        runLongerTestCase(192, 64, "0066BC6E0EF34E24");
        runLongerTestCase(256, 64, "7D4EA5D445501CBE");

        randomTests();
        outputSizeTests();
        testExceptions();
    }

    private void testExceptions() throws InvalidCipherTextException
    {
        AEADBlockCipher ocb = createOCBCipher();

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

        AEADTestUtil.testReset(this, createOCBCipher(), createOCBCipher(), new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[15]));
        AEADTestUtil.testTampering(this, ocb, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[15]));
        AEADTestUtil.testOutputSizes(this, createOCBCipher(), new AEADParameters(new KeyParameter(new byte[16]), 128,
                new byte[15]));
        AEADTestUtil.testBufferSizeChecks(this, createOCBCipher(), new AEADParameters(new KeyParameter(new byte[16]),
                128, new byte[15]));
    }

    private void runTestCase(String testName, String[] testVector, int macLengthBits, byte[] K)
        throws InvalidCipherTextException
    {
        int pos = 0;
        byte[] N = Hex.decode(testVector[pos++]);
        byte[] A = Hex.decode(testVector[pos++]);
        byte[] P = Hex.decode(testVector[pos++]);
        byte[] C = Hex.decode(testVector[pos++]);

        int macLengthBytes = macLengthBits / 8;

        KeyParameter keyParameter = new KeyParameter(K);
        AEADParameters parameters = new AEADParameters(keyParameter, macLengthBits, N, A);

        AEADBlockCipher encCipher = initOCBCipher(true, parameters);
        AEADBlockCipher decCipher = initOCBCipher(false, parameters);

        checkTestCase(encCipher, decCipher, testName, macLengthBytes, P, C);
        checkTestCase(encCipher, decCipher, testName + " (reused)", macLengthBytes, P, C);

        // Key reuse
        AEADParameters keyReuseParams = AEADTestUtil.reuseKey(parameters);
        encCipher.init(true, keyReuseParams);
        decCipher.init(false, keyReuseParams);
        checkTestCase(encCipher, decCipher, testName + " (key reuse)", macLengthBytes, P, C);
    }

    private BlockCipher createUnderlyingCipher()
    {
        return new AESEngine();
    }

    private AEADBlockCipher createOCBCipher()
    {
        return new OCBBlockCipher(createUnderlyingCipher(), createUnderlyingCipher());
    }

    private AEADBlockCipher initOCBCipher(boolean forEncryption, AEADParameters parameters)
    {
        AEADBlockCipher c = createOCBCipher();
        c.init(forEncryption, parameters);
        return c;
    }

    private void checkTestCase(AEADBlockCipher encCipher, AEADBlockCipher decCipher, String testName,
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

    private void runLongerTestCase(int keyLen, int tagLen, String expectedOutputHex)
        throws InvalidCipherTextException
    {
        byte[] expectedOutput = Hex.decode(expectedOutputHex);
        byte[] keyBytes = new byte[keyLen / 8];
        keyBytes[keyBytes.length - 1] = (byte)tagLen;
        KeyParameter key = new KeyParameter(keyBytes);

        AEADBlockCipher c1 = initOCBCipher(true, new AEADParameters(key, tagLen, createNonce(385)));
        AEADBlockCipher c2 = createOCBCipher();

        long total = 0;

        byte[] S = new byte[128];

        int n = 0;
        for (int i = 0; i < 128; ++i)
        {
            c2.init(true, new AEADParameters(key, tagLen, createNonce(++n)));
            total += updateCiphers(c1, c2, S, i, true, true);
            c2.init(true, new AEADParameters(key, tagLen, createNonce(++n)));
            total += updateCiphers(c1, c2, S, i, false, true);
            c2.init(true, new AEADParameters(key, tagLen, createNonce(++n)));
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

    private byte[] createNonce(int n)
    {
        return new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)(n >>> 8), (byte)n };
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

    private void randomTests()
        throws InvalidCipherTextException
    {
        SecureRandom srng = new SecureRandom();
        srng.setSeed(Times.nanoTime());
        for (int i = 0; i < 10; ++i)
        {
            randomTest(srng);
        }
    }

    private void randomTest(SecureRandom srng)
        throws InvalidCipherTextException
    {
        int kLength = 16 + 8 * (Math.abs(srng.nextInt()) % 3);
        byte[] K = new byte[kLength];
        srng.nextBytes(K);

        int pLength = srng.nextInt() >>> 16;
        byte[] P = new byte[pLength];
        srng.nextBytes(P);

        int aLength = srng.nextInt() >>> 24;
        byte[] A = new byte[aLength];
        srng.nextBytes(A);

        int saLength = srng.nextInt() >>> 24;
        byte[] SA = new byte[saLength];
        srng.nextBytes(SA);

        int ivLength = 1 + nextInt(srng, 15);
        byte[] IV = new byte[ivLength];
        srng.nextBytes(IV);

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, IV, A);
        AEADBlockCipher cipher = initOCBCipher(true, parameters);
        byte[] C = new byte[cipher.getOutputSize(P.length)];
        int predicted = cipher.getUpdateOutputSize(P.length);

        int split = nextInt(srng, SA.length + 1);
        cipher.processAADBytes(SA, 0, split);
        int len = cipher.processBytes(P, 0, P.length, C, 0);
        cipher.processAADBytes(SA, split, SA.length - split);

        if (predicted != len)
        {
            fail("encryption reported incorrect update length in randomised test");
        }

        len += cipher.doFinal(C, len);

        if (C.length != len)
        {
            fail("encryption reported incorrect length in randomised test");
        }

        byte[] encT = cipher.getMac();
        byte[] tail = new byte[C.length - P.length];
        System.arraycopy(C, P.length, tail, 0, tail.length);

        if (!areEqual(encT, tail))
        {
            fail("stream contained wrong mac in randomised test");
        }

        cipher.init(false, parameters);
        byte[] decP = new byte[cipher.getOutputSize(C.length)];
        predicted = cipher.getUpdateOutputSize(C.length);

        split = nextInt(srng, SA.length + 1);
        cipher.processAADBytes(SA, 0, split);
        len = cipher.processBytes(C, 0, C.length, decP, 0);
        cipher.processAADBytes(SA, split, SA.length - split);

        if (predicted != len)
        {
            fail("decryption reported incorrect update length in randomised test");
        }

        len += cipher.doFinal(decP, len);

        if (!areEqual(P, decP))
        {
            fail("incorrect decrypt in randomised test");
        }

        byte[] decT = cipher.getMac();
        if (!areEqual(encT, decT))
        {
            fail("decryption produced different mac from encryption");
        }

        //
        // key reuse test
        //
        cipher.init(false, AEADTestUtil.reuseKey(parameters));
        decP = new byte[cipher.getOutputSize(C.length)];

        split = nextInt(srng, SA.length + 1);
        cipher.processAADBytes(SA, 0, split);
        len = cipher.processBytes(C, 0, C.length, decP, 0);
        cipher.processAADBytes(SA, split, SA.length - split);

        len += cipher.doFinal(decP, len);

        if (!areEqual(P, decP))
        {
            fail("incorrect decrypt in randomised test");
        }

        decT = cipher.getMac();
        if (!areEqual(encT, decT))
        {
            fail("decryption produced different mac from encryption");
        }
    }

    private void outputSizeTests()
    {
        byte[] K = new byte[16];
        byte[] A = null;
        byte[] IV = new byte[15];

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, IV, A);
        AEADBlockCipher cipher = initOCBCipher(true, parameters);

        if (cipher.getUpdateOutputSize(0) != 0)
        {
            fail("incorrect getUpdateOutputSize for initial 0 bytes encryption");
        }

        if (cipher.getOutputSize(0) != 16)
        {
            fail("incorrect getOutputSize for initial 0 bytes encryption");
        }

        cipher.init(false, parameters);

        if (cipher.getUpdateOutputSize(0) != 0)
        {
            fail("incorrect getUpdateOutputSize for initial 0 bytes decryption");
        }

        // NOTE: 0 bytes would be truncated data, but we want it to fail in the doFinal, not here
        if (cipher.getOutputSize(0) != 0)
        {
            fail("fragile getOutputSize for initial 0 bytes decryption");
        }

        if (cipher.getOutputSize(16) != 0)
        {
            fail("incorrect getOutputSize for initial MAC-size bytes decryption");
        }
    }

    private static int nextInt(SecureRandom rand, int n)
    {
        if ((n & -n) == n)  // i.e., n is a power of 2
        {
            return (int)((n * (long)(rand.nextInt() >>> 1)) >> 31);
        }

        int bits, value;
        do
        {
            bits = rand.nextInt() >>> 1;
            value = bits % n;
        }
        while (bits - value + (n - 1) < 0);

        return value;
    }

    public static void main(String[] args)
    {
        runTest(new OCBTest());
    }
}
