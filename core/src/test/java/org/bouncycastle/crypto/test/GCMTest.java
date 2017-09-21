package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.gcm.BasicGCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables64kGCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.Times;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors from "The Galois/Counter Mode of Operation (GCM)", McGrew/Viega, Appendix B
 */
public class GCMTest
    extends SimpleTest
{
    private static final String[][] TEST_VECTORS = new String[][] {
        {
            "Test Case 1",
            "00000000000000000000000000000000",
            "",
            "",
            "000000000000000000000000",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        },
        {
            "Test Case 2",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        },
        {
            "Test Case 3",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b391aafd255",
            "",
            "cafebabefacedbaddecaf888",
            "42831ec2217774244b7221b784d0d49c"
            + "e3aa212f2c02a4e035c17e2329aca12e"
            + "21d514b25466931c7d8f6a5aac84aa05"
            + "1ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        },
        {
            "Test Case 4",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "cafebabefacedbaddecaf888",
            "42831ec2217774244b7221b784d0d49c"
            + "e3aa212f2c02a4e035c17e2329aca12e"
            + "21d514b25466931c7d8f6a5aac84aa05"
            + "1ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        },
        {
            "Test Case 5",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "cafebabefacedbad",
            "61353b4c2806934a777ff51fa22a4755"
            + "699b2a714fcdc6f83766e5f97b6c7423"
            + "73806900e49f24b22b097544d4896b42"
            + "4989b5e1ebac0f07c23f4598",
            "3612d2e79e3b0785561be14aaca2fccb",
        },
        {
            "Test Case 6",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "9313225df88406e555909c5aff5269aa"
            + "6a7a9538534f7da1e4c303d2a318a728"
            + "c3c0c95156809539fcf0e2429a6b5254"
            + "16aedbf5a0de6a57a637b39b",
            "8ce24998625615b603a033aca13fb894"
            + "be9112a5c3a211a8ba262a3cca7e2ca7"
            + "01e4a9a4fba43c90ccdcb281d48c7c6f"
            + "d62875d2aca417034c34aee5",
            "619cc5aefffe0bfa462af43c1699d050",
        },
        {
            "Test Case 7",
            "00000000000000000000000000000000"
            + "0000000000000000",
            "",
            "",
            "000000000000000000000000",
            "",
            "cd33b28ac773f74ba00ed1f312572435",
        },
        {
            "Test Case 8",
            "00000000000000000000000000000000"
            + "0000000000000000",
            "00000000000000000000000000000000",
            "",
            "000000000000000000000000",
            "98e7247c07f0fe411c267e4384b0f600",
            "2ff58d80033927ab8ef4d4587514f0fb",
        },
        {
            "Test Case 9",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b391aafd255",
            "",
            "cafebabefacedbaddecaf888",
            "3980ca0b3c00e841eb06fac4872a2757"
            + "859e1ceaa6efd984628593b40ca1e19c"
            + "7d773d00c144c525ac619d18c84a3f47"
            + "18e2448b2fe324d9ccda2710acade256",
            "9924a7c8587336bfb118024db8674a14",
        },
        {
            "Test Case 10",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "cafebabefacedbaddecaf888",
            "3980ca0b3c00e841eb06fac4872a2757"
            + "859e1ceaa6efd984628593b40ca1e19c"
            + "7d773d00c144c525ac619d18c84a3f47"
            + "18e2448b2fe324d9ccda2710",
            "2519498e80f1478f37ba55bd6d27618c",
        },
        {
            "Test Case 11",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "cafebabefacedbad",
            "0f10f599ae14a154ed24b36e25324db8"
            + "c566632ef2bbb34f8347280fc4507057"
            + "fddc29df9a471f75c66541d4d4dad1c9"
            + "e93a19a58e8b473fa0f062f7",
            "65dcc57fcf623a24094fcca40d3533f8",
        },
        {
            "Test Case 12",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "9313225df88406e555909c5aff5269aa"
            + "6a7a9538534f7da1e4c303d2a318a728"
            + "c3c0c95156809539fcf0e2429a6b5254"
            + "16aedbf5a0de6a57a637b39b",
            "d27e88681ce3243c4830165a8fdcf9ff"
            + "1de9a1d8e6b447ef6ef7b79828666e45"
            + "81e79012af34ddd9e2f037589b292db3"
            + "e67c036745fa22e7e9b7373b",
            "dcf566ff291c25bbb8568fc3d376a6d9",
        },
        {
            "Test Case 13",
            "00000000000000000000000000000000"
            + "00000000000000000000000000000000",
            "",
            "",
            "000000000000000000000000",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        },
        {
            "Test Case 14",
            "00000000000000000000000000000000"
            + "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "000000000000000000000000",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        },
        {
            "Test Case 15",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b391aafd255",
            "",
            "cafebabefacedbaddecaf888",
            "522dc1f099567d07f47f37a32a84427d"
            + "643a8cdcbfe5c0c97598a2bd2555d1aa"
            + "8cb08e48590dbb3da7b08b1056828838"
            + "c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        },
        {
            "Test Case 16",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "cafebabefacedbaddecaf888",
            "522dc1f099567d07f47f37a32a84427d"
            + "643a8cdcbfe5c0c97598a2bd2555d1aa"
            + "8cb08e48590dbb3da7b08b1056828838"
            + "c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        },
        {
            "Test Case 17",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "cafebabefacedbad",
            "c3762df1ca787d32ae47c13bf19844cb"
            + "af1ae14d0b976afac52ff7d79bba9de0"
            + "feb582d33934a4f0954cc2363bc73f78"
            + "62ac430e64abe499f47c9b1f",
            "3a337dbf46a792c45e454913fe2ea8f2",
        },
        {
            "Test Case 18",
            "feffe9928665731c6d6a8f9467308308"
            + "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a"
            + "86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525"
            + "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeef"
            + "abaddad2",
            "9313225df88406e555909c5aff5269aa"
            + "6a7a9538534f7da1e4c303d2a318a728"
            + "c3c0c95156809539fcf0e2429a6b5254"
            + "16aedbf5a0de6a57a637b39b",
            "5a8def2f0c9e53f1f75d7853659e2a20"
            + "eeb2b22aafde6419a058ab4f6f746bf4"
            + "0fc0c3b780f244452da3ebf1c5d82cde"
            + "a2418997200ef82e44ae7e3f",
            "a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
        },
    };

    public String getName()
    {
        return "GCM";
    }

    public void performTest() throws Exception
    {
        for (int i = 0; i < TEST_VECTORS.length; ++i)
        {
            runTestCase(TEST_VECTORS[i]);
        }

        randomTests();
        outputSizeTests();
        testExceptions();
    }

    protected BlockCipher createAESEngine()
    {
        return new AESEngine();
    }

    private void testExceptions() throws InvalidCipherTextException
    {
        GCMBlockCipher gcm = new GCMBlockCipher(createAESEngine());

        try
        {
            gcm = new GCMBlockCipher(new DESEngine());

            fail("incorrect block size not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            gcm.init(false, new KeyParameter(new byte[16]));

            fail("illegal argument not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        AEADTestUtil.testTampering(this, gcm, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]));

        byte[] P = Strings.toByteArray("Hello world!");
        byte[] buf = new byte[100];

        GCMBlockCipher c = new GCMBlockCipher(createAESEngine());
        AEADParameters aeadParameters = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]);
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
            isTrue("wrong message", e.getMessage().equals("GCM cipher cannot be reused for encryption"));
        }

        try
        {
            c.init(true, aeadParameters);
            fail("no exception on reuse");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message", e.getMessage().equals("cannot reuse nonce for GCM encryption"));
        }
    }

    private void runTestCase(String[] testVector)
        throws InvalidCipherTextException
    {
        for (int macLength = 12; macLength <= 16; ++macLength)
        {
            runTestCase(testVector, macLength);
        }
    }

    private void runTestCase(String[] testVector, int macLength)
        throws InvalidCipherTextException
    {
        int pos = 0;
        String testName = testVector[pos++];
        byte[] K = Hex.decode(testVector[pos++]);
        byte[] P = Hex.decode(testVector[pos++]);
        byte[] A = Hex.decode(testVector[pos++]);
        byte[] IV = Hex.decode(testVector[pos++]);
        byte[] C = Hex.decode(testVector[pos++]);

        // For short MAC, take leading bytes
        byte[] t = Hex.decode(testVector[pos++]);
        byte[] T = new byte[macLength];
        System.arraycopy(t, 0, T, 0, T.length);

        // Default multiplier
        runTestCase(null, null, testName, K, IV, A, P, C, T);

        runTestCase(new BasicGCMMultiplier(), new BasicGCMMultiplier(), testName, K, IV, A, P, C, T);
        runTestCase(new Tables4kGCMMultiplier(), new Tables4kGCMMultiplier(), testName, K, IV, A, P, C, T);
        runTestCase(new Tables8kGCMMultiplier(), new Tables8kGCMMultiplier(), testName, K, IV, A, P, C, T);
        runTestCase(new Tables64kGCMMultiplier(), new Tables64kGCMMultiplier(), testName, K, IV, A, P, C, T);
    }

    private void runTestCase(
        GCMMultiplier   encM,
        GCMMultiplier   decM,
        String          testName,
        byte[]          K,
        byte[]          IV,
        byte[]          A,
        byte[]          P,
        byte[]          C,
        byte[]          T)
        throws InvalidCipherTextException
    {
        byte[] fa = new byte[A.length / 2];
        byte[] la = new byte[A.length - (A.length / 2)];
        System.arraycopy(A, 0, fa, 0, fa.length);
        System.arraycopy(A, fa.length, la, 0, la.length);

        runTestCase(encM, decM, testName + " all initial associated data", K, IV, A, null, P, C, T);
        runTestCase(encM, decM, testName + " all subsequent associated data", K, IV, null, A, P, C, T);
        runTestCase(encM, decM, testName + " split associated data", K, IV, fa, la, P, C, T);
    }

    private void runTestCase(
        GCMMultiplier   encM,
        GCMMultiplier   decM,
        String          testName,
        byte[]          K,
        byte[]          IV,
        byte[]          A,
        byte[]          SA,
        byte[]          P,
        byte[]          C,
        byte[]          T)
        throws InvalidCipherTextException
    {
        AEADParameters parameters = new AEADParameters(new KeyParameter(K), T.length * 8, IV, A);
        GCMBlockCipher encCipher = initCipher(encM, true, parameters);
        GCMBlockCipher decCipher = initCipher(decM, false, parameters);
        checkTestCase(encCipher, decCipher, testName, SA, P, C, T);
        encCipher = initCipher(encM, true, parameters);
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
            isTrue("wrong message", "cannot reuse nonce for GCM encryption".equals(e.getMessage()));
        }
    }

    private GCMBlockCipher initCipher(GCMMultiplier m, boolean forEncryption, AEADParameters parameters)
    {
        GCMBlockCipher c = new GCMBlockCipher(createAESEngine(), m);
        c.init(forEncryption, parameters);
        return c;
    }

    private void checkTestCase(
        GCMBlockCipher  encCipher,
        GCMBlockCipher  decCipher,
        String          testName,
        byte[]          SA,
        byte[]          P,
        byte[]          C,
        byte[]          T)
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
//            System.out.println("" + enc.length + "/" + len);
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

    private void randomTests()
        throws InvalidCipherTextException
    {
        SecureRandom srng = new SecureRandom();
        srng.setSeed(Times.nanoTime());
        randomTests(srng, null);
        randomTests(srng, new BasicGCMMultiplier());
        randomTests(srng, new Tables4kGCMMultiplier());
        randomTests(srng, new Tables8kGCMMultiplier());
        randomTests(srng, new Tables64kGCMMultiplier());
    }

    private void randomTests(SecureRandom srng, GCMMultiplier m)
        throws InvalidCipherTextException
    {
        for (int i = 0; i < 10; ++i)
        {
            randomTest(srng, m);
        }
    }

    private void randomTest(SecureRandom srng, GCMMultiplier m)
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

        int ivLength = 1 + (srng.nextInt() >>> 24);
        byte[] IV = new byte[ivLength];
        srng.nextBytes(IV);

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, IV, A);
        GCMBlockCipher cipher = initCipher(m, true, parameters);
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
        byte[] IV = new byte[16];

        AEADParameters parameters = new AEADParameters(new KeyParameter(K), 16 * 8, IV, A);
        GCMBlockCipher cipher = initCipher(null, true, parameters);

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
        runTest(new GCMTest());
    }
}
