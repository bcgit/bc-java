package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.macs.SipHash;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.Times;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ChaCha20Poly1305Test
    extends SimpleTest
{
    private static final String[][] TEST_VECTORS = new String[][] {
    {
        "Test Case 1",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "4c616469657320616e642047656e746c"
        + "656d656e206f662074686520636c6173"
        + "73206f66202739393a20496620492063"
        + "6f756c64206f6666657220796f75206f"
        + "6e6c79206f6e652074697020666f7220"
        + "746865206675747572652c2073756e73"
        + "637265656e20776f756c642062652069"
        + "742e",
        "50515253c0c1c2c3c4c5c6c7",
        "070000004041424344454647",
        "d31a8d34648e60db7b86afbc53ef7ec2"
        + "a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b"
        + "1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58"
        + "fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b"
        + "6116",
        "1ae10b594f09e26a7e902ecbd0600691",
    },
    };

    public String getName()
    {
        return "ChaCha20Poly1305";
    }

    public void performTest() throws Exception
    {
        for (int i = 0; i < TEST_VECTORS.length; ++i)
        {
            runTestCase(TEST_VECTORS[i]);
        }

        outputSizeTests();
        randomTests();
        testExceptions();
    }

    private void checkTestCase(
        ChaCha20Poly1305    encCipher,
        ChaCha20Poly1305    decCipher,
        String              testName,
        byte[]              SA,
        byte[]              P,
        byte[]              C,
        byte[]              T)
        throws InvalidCipherTextException
    {
        byte[] enc = new byte[encCipher.getOutputSize(P.length)];
        if (SA != null)
        {
            encCipher.processAADBytes(SA, 0, SA.length);
        }
        int len = encCipher.processBytes(P, 0, P.length, enc, 0);
        len += encCipher.doFinal(enc, len);

        if (enc.length != len)
        {
            fail("encryption reported incorrect length: " + testName);
        }

        byte[] mac = encCipher.getMac();

        byte[] data = new byte[P.length];
        System.arraycopy(enc, 0, data, 0, data.length);
        byte[] tail = new byte[enc.length - P.length];
        System.arraycopy(enc, P.length, tail, 0, tail.length);

        if (!areEqual(C, data))
        {
            fail("incorrect encrypt in: " + testName);
        }

        if (!areEqual(T, mac))
        {
            fail("getMac() returned wrong mac in: " + testName);
        }

        if (!areEqual(T, tail))
        {
            fail("stream contained wrong mac in: " + testName);
        }

        byte[] dec = new byte[decCipher.getOutputSize(enc.length)];
        if (SA != null)
        {
            decCipher.processAADBytes(SA, 0, SA.length);
        }
        len = decCipher.processBytes(enc, 0, enc.length, dec, 0);
        len += decCipher.doFinal(dec, len);
        mac = decCipher.getMac();

        data = new byte[C.length];
        System.arraycopy(dec, 0, data, 0, data.length);

        if (!areEqual(P, data))
        {
            fail("incorrect decrypt in: " + testName);
        }
    }

    private ChaCha20Poly1305 initCipher(boolean forEncryption, AEADParameters parameters)
    {
        ChaCha20Poly1305 c = new ChaCha20Poly1305();
        c.init(forEncryption, parameters);
        return c;
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

    private void outputSizeTests()
    {
        byte[] K = new byte[32];
        byte[] A = null;
        byte[] N = new byte[12];

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, N, A);
        ChaCha20Poly1305 cipher = initCipher(true, parameters);

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

    private void randomTests() throws InvalidCipherTextException
    {
        SecureRandom random = new SecureRandom();
        random.setSeed(Times.nanoTime());

        for (int i = 0; i < 100; ++i)
        {
            randomTest(random);
        }
    }

    private void randomTest(SecureRandom random) throws InvalidCipherTextException
    {
        int kLength = 32;
        byte[] K = new byte[kLength];
        random.nextBytes(K);

        int pHead = random.nextInt() >>> 24;
        int pLength = random.nextInt() >>> 16;
        int pTail = random.nextInt() >>> 24;
        byte[] P = new byte[pHead + pLength + pTail];
        random.nextBytes(P);

        int aLength = random.nextInt() >>> 24;
        byte[] A = new byte[aLength];
        random.nextBytes(A);

        int saLength = random.nextInt() >>> 24;
        byte[] SA = new byte[saLength];
        random.nextBytes(SA);

        int nonceLength = 12;
        byte[] nonce = new byte[nonceLength];
        random.nextBytes(nonce);

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, nonce, A);
        ChaCha20Poly1305 cipher = initCipher(true, parameters);

        int ctLength = cipher.getOutputSize(pLength);
        byte[] C = new byte[saLength + ctLength];
        System.arraycopy(SA, 0, C, 0, saLength);

        int split = nextInt(random, saLength + 1);
        cipher.processAADBytes(C, 0, split);
        cipher.processAADBytes(C, split, saLength - split);

        int predicted = cipher.getUpdateOutputSize(pLength);
        int len = cipher.processBytes(P, pHead, pLength, C, saLength);
        if (predicted != len)
        {
            fail("encryption reported incorrect update length in randomised test");
        }

        len += cipher.doFinal(C, saLength + len);
        if (ctLength != len)
        {
            fail("encryption reported incorrect length in randomised test");
        }

        byte[] encT = cipher.getMac();
        byte[] tail = new byte[ctLength - pLength];
        System.arraycopy(C, saLength + pLength, tail, 0, tail.length);

        if (!areEqual(encT, tail))
        {
            fail("stream contained wrong mac in randomised test");
        }

        cipher.init(false, parameters);

        int decPHead = random.nextInt() >>> 24;
        int decPLength = cipher.getOutputSize(ctLength);
        int decPTail = random.nextInt() >>> 24;
        byte[] decP = new byte[decPHead + decPLength + decPTail];

        split = nextInt(random, saLength + 1);
        cipher.processAADBytes(C, 0, split);
        cipher.processAADBytes(C, split, saLength - split);

        predicted = cipher.getUpdateOutputSize(ctLength);
        len = cipher.processBytes(C, saLength, ctLength, decP, decPHead);
        if (predicted != len)
        {
            fail("decryption reported incorrect update length in randomised test");
        }

        len += cipher.doFinal(decP, decPHead + len);

        if (!areEqual(P, pHead, pHead + pLength, decP, decPHead, decPHead + decPLength))
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

        decPHead = random.nextInt() >>> 24;
        decPLength = cipher.getOutputSize(ctLength);
        decPTail = random.nextInt() >>> 24;
        decP = new byte[decPHead + decPLength + decPTail];

        split = nextInt(random, saLength + 1);
        cipher.processAADBytes(C, 0, split);
        cipher.processAADBytes(C, split, saLength - split);

        len = cipher.processBytes(C, saLength, ctLength, decP, decPHead);
        len += cipher.doFinal(decP, decPHead + len);

        if (!areEqual(P, pHead, pHead + pLength, decP, decPHead, decPHead + decPLength))
        {
            fail("incorrect decrypt in randomised test");
        }

        decT = cipher.getMac();
        if (!areEqual(encT, decT))
        {
            fail("decryption produced different mac from encryption");
        }
    }

    private void runTestCase(String[] testVector)
        throws InvalidCipherTextException
    {
        int pos = 0;
        String testName = testVector[pos++];
        byte[] K = Hex.decode(testVector[pos++]);
        byte[] P = Hex.decode(testVector[pos++]);
        byte[] A = Hex.decode(testVector[pos++]);
        byte[] N = Hex.decode(testVector[pos++]);
        byte[] C = Hex.decode(testVector[pos++]);
        byte[] T = Hex.decode(testVector[pos++]);

        runTestCase(testName, K, N, A, P, C, T);
    }

    private void runTestCase(
        String  testName,
        byte[]  K,
        byte[]  N,
        byte[]  A,
        byte[]  P,
        byte[]  C,
        byte[]  T)
        throws InvalidCipherTextException
    {
        byte[] fa = new byte[A.length / 2];
        byte[] la = new byte[A.length - (A.length / 2)];
        System.arraycopy(A, 0, fa, 0, fa.length);
        System.arraycopy(A, fa.length, la, 0, la.length);

        runTestCase(testName + " all initial associated data", K, N, A, null, P, C, T);
        runTestCase(testName + " all subsequent associated data", K, N, null, A, P, C, T);
        runTestCase(testName + " split associated data", K, N, fa, la, P, C, T);
    }

    private void runTestCase(
        String  testName,
        byte[]  K,
        byte[]  N,
        byte[]  A,
        byte[]  SA,
        byte[]  P,
        byte[]  C,
        byte[]  T)
        throws InvalidCipherTextException
    {
        AEADParameters parameters = new AEADParameters(new KeyParameter(K), T.length * 8, N, A);
        ChaCha20Poly1305 encCipher = initCipher(true, parameters);
        ChaCha20Poly1305 decCipher = initCipher(false, parameters);
        checkTestCase(encCipher, decCipher, testName, SA, P, C, T);
        encCipher = initCipher(true, parameters);
        checkTestCase(encCipher, decCipher, testName + " (reused)", SA, P, C, T);

        // Key reuse
        AEADParameters keyReuseParams = AEADTestUtil.reuseKey(parameters);

        try
        {
            encCipher.init(true, keyReuseParams);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message", "cannot reuse nonce for ChaCha20Poly1305 encryption".equals(e.getMessage()));
        }
    }

    private void testExceptions() throws InvalidCipherTextException
    {
        ChaCha20Poly1305 c = new ChaCha20Poly1305();

        try
        {
            c = new ChaCha20Poly1305(new SipHash());

            fail("incorrect mac size not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            c.init(false, new KeyParameter(new byte[32]));

            fail("illegal argument not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        AEADTestUtil.testTampering(this, c, new AEADParameters(new KeyParameter(new byte[32]), 128, new byte[12]));

        byte[] P = Strings.toByteArray("Hello world!");
        byte[] buf = new byte[100];

        c = new ChaCha20Poly1305();
        AEADParameters aeadParameters = new AEADParameters(new KeyParameter(new byte[32]), 128, new byte[12]);
        c.init(true, aeadParameters);

        c.processBytes(P, 0, P.length, buf, 0);

        c.doFinal(buf, 0);

        try
        {
            c.doFinal(buf, 0);
            fail("no exception on reuse");
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message", e.getMessage().equals("ChaCha20Poly1305 cannot be reused for encryption"));
        }

        try
        {
            c.init(true, aeadParameters);
            fail("no exception on reuse");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message", e.getMessage().equals("cannot reuse nonce for ChaCha20Poly1305 encryption"));
        }
    }

    public static void main(String[] args)
    {
        runTest(new ChaCha20Poly1305Test());
    }
}
