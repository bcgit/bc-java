package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.modes.gcm.BasicGCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables64kGCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
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
    private static final String[][] TEST_VECTORS = new String[][]{
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
        testResetBehavior();
        testRefusedInit();
        testStreamingAndOverlap();
        testPartialBlockReuse();
        testCounterBlockCleanup();
    }

    private void testStreamingAndOverlap() throws InvalidCipherTextException
    {
        int[] chunkSizes = new int[]{ 1, 15, 16, 17 };
        for (int i = 0; i < TEST_VECTORS.length; ++i)
        {
            String[] vector = TEST_VECTORS[i];
            byte[] key = Hex.decode(vector[1]);
            byte[] plaintext = Hex.decode(vector[2]);
            byte[] aad = Hex.decode(vector[3]);
            byte[] nonce = Hex.decode(vector[4]);
            byte[] ciphertext = Hex.decode(vector[5]);
            byte[] tag = Hex.decode(vector[6]);

            for (int macSize = 4; macSize <= 16; macSize += 4)
            {
                AEADParameters params = new AEADParameters(new KeyParameter(key), macSize * 8, nonce);
                byte[] expected = Arrays.concatenate(ciphertext, Arrays.copyOf(tag, macSize));
                for (int j = 0; j < chunkSizes.length; ++j)
                {
                    GCMModeCipher cipher = createGCM(createAESEngine());
                    cipher.init(true, params);
                    isTrue("fragmented encryption: " + vector[0],
                        areEqual(expected, processFragments(cipher, plaintext, aad, chunkSizes[j])));
                    cipher.init(false, params);
                    isTrue("fragmented decryption: " + vector[0],
                        areEqual(plaintext, processFragments(cipher, expected, aad, chunkSizes[j])));
                }

                params = new AEADParameters(new KeyParameter(key), macSize * 8, nonce, aad);
                for (int offset = 0; offset <= 14; offset += 7)
                {
                    GCMModeCipher cipher = createGCM(createAESEngine());
                    cipher.init(true, params);
                    checkOverlap(cipher, plaintext, expected, offset);
                    cipher.init(false, params);
                    checkOverlap(cipher, expected, plaintext, offset);
                }
            }
        }
    }

    private byte[] processFragments(GCMModeCipher cipher, byte[] input, byte[] aad, int chunkSize)
        throws InvalidCipherTextException
    {
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int aadSplit = aad.length / 2;
        cipher.processAADBytes(aad, 0, aadSplit);
        int length = 0;
        int position = 0;
        while (position < input.length)
        {
            length += cipher.processByte(input[position++], output, length);
            int count = Math.min(chunkSize, input.length - position);
            length += cipher.processBytes(input, position, count, output, length);
            position += count;
        }
        cipher.processAADBytes(aad, aadSplit, aad.length - aadSplit);
        length += cipher.doFinal(output, length);
        isEquals("fragmented output length", output.length, length);
        return output;
    }

    private void checkOverlap(GCMModeCipher cipher, byte[] input, byte[] expected, int outOff)
        throws InvalidCipherTextException
    {
        byte[] buffer = new byte[Math.max(input.length + 7, expected.length + outOff)];
        System.arraycopy(input, 0, buffer, 7, input.length);
        int length = cipher.processBytes(buffer, 7, input.length, buffer, outOff);
        length += cipher.doFinal(buffer, outOff + length);
        isEquals("overlapping output length", expected.length, length);
        isTrue("overlapping output", areEqual(expected, Arrays.copyOfRange(buffer, outOff, outOff + length)));
    }

    private void testPartialBlockReuse() throws InvalidCipherTextException
    {
        int[] lengths = new int[]{ 0, 1, 15, 16, 17, 31, 32, 33, 257 };
        byte[] key = new byte[32];
        byte[] aad = Hex.decode("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        GCMModeCipher cipher = createGCM(createAESEngine());

        for (int i = 0; i < lengths.length; ++i)
        {
            byte[] nonce = new byte[12];
            nonce[0] = (byte)(i + 1);
            AEADParameters params = new AEADParameters(new KeyParameter(key), 128, nonce, aad);
            byte[] plaintext = new byte[lengths[i]];
            for (int j = 0; j < plaintext.length; ++j)
            {
                plaintext[j] = (byte)(j * 31 + i);
            }

            GCMModeCipher fresh = createGCM(createAESEngine());
            fresh.init(true, params);
            byte[] expected = processAll(fresh, plaintext);
            cipher.init(true, params);
            isTrue("encryption after reinitialisation", areEqual(expected, processAll(cipher, plaintext)));

            cipher.init(false, params);
            isTrue("decryption after reinitialisation", areEqual(plaintext, processAll(cipher, expected)));
            isTrue("decryption after implicit reset", areEqual(plaintext, processAll(cipher, expected)));

            cipher.processBytes(expected, 0, Math.min(17, expected.length), new byte[plaintext.length], 0);
            cipher.reset();
            isTrue("decryption after partial input and reset", areEqual(plaintext, processAll(cipher, expected)));

            byte[] tampered = Arrays.clone(expected);
            tampered[tampered.length - 1] ^= 1;
            try
            {
                processAll(cipher, tampered);
                fail("tampered tag accepted");
            }
            catch (InvalidCipherTextException e)
            {
                // expected
            }
            cipher.init(false, params);
            isTrue("decryption after failed authentication", areEqual(plaintext, processAll(cipher, expected)));

            try
            {
                cipher.processBytes(expected, 0, expected.length, new byte[0], 0);
                cipher.doFinal(new byte[0], 0);
                isEquals("empty plaintext expected", 0, plaintext.length);
            }
            catch (OutputLengthException e)
            {
                isTrue("unexpected output length exception", plaintext.length > 0);
            }
            cipher.init(false, params);
            isTrue("decryption after short output", areEqual(plaintext, processAll(cipher, expected)));
        }
    }

    private byte[] processAll(GCMModeCipher cipher, byte[] input) throws InvalidCipherTextException
    {
        return processAll(cipher, input, false);
    }

    private byte[] processAll(GCMModeCipher cipher, byte[] input, boolean bytewise)
        throws InvalidCipherTextException
    {
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int length = 0;
        if (bytewise)
        {
            for (int i = 0; i < input.length; ++i)
            {
                length += cipher.processByte(input[i], output, length);
            }
        }
        else
        {
            length = cipher.processBytes(input, 0, input.length, output, 0);
        }
        length += cipher.doFinal(output, length);
        isEquals("output length", output.length, length);
        return output;
    }

    private void testCounterBlockCleanup() throws InvalidCipherTextException
    {
        for (int direction = 0; direction < 2; ++direction)
        {
            for (int length = 1; length <= 31; length += 15)
            {
                boolean encrypt = direction == 0;
                boolean bytewise = length == 31;
                AEADParameters params = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
                byte[] plaintext = new byte[length];
                GCMModeCipher fresh = createGCM(createAESEngine());
                fresh.init(true, params);
                byte[] ciphertext = processAll(fresh, plaintext);
                byte[] input = encrypt ? plaintext : ciphertext;

                RecordingAESEngine engine = new RecordingAESEngine();
                GCMModeCipher cipher = GCMBlockCipher.newInstance(engine);
                cipher.init(encrypt, params);
                engine.recording = true;
                engine.fail = true;
                try
                {
                    processAll(cipher, input, bytewise);
                    fail("block cipher failure not propagated");
                }
                catch (IllegalStateException e)
                {
                    isEquals("injected failure", e.getMessage());
                }
                isTrue("counter block not cleared on failure", areEqual(new byte[16], engine.output));

                engine.recording = false;
                engine.fail = false;
                engine.output = null;
                // Use a fresh nonce after the interrupted encryption.
                byte[] nonce = new byte[12];
                nonce[0] = 1;
                AEADParameters next = encrypt
                    ? new AEADParameters(new KeyParameter(new byte[16]), 128, nonce) : params;
                fresh.init(encrypt, next);
                byte[] expected = processAll(fresh, input);
                cipher.init(encrypt, next);
                engine.recording = true;
                isTrue("reinitialisation after block cipher failure", areEqual(expected, processAll(cipher, input, bytewise)));
                isTrue("counter block not cleared on success", areEqual(new byte[16], engine.output));
            }
        }
    }

    private static class RecordingAESEngine extends AESEngine
    {
        private boolean recording;
        private boolean fail;
        private byte[] output;

        public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        {
            int length = super.processBlock(in, inOff, out, outOff);
            if (recording)
            {
                if (output == null)
                {
                    output = out;
                }
                if (fail)
                {
                    throw new IllegalStateException("injected failure");
                }
            }
            return length;
        }
    }


    private void testResetBehavior() throws Exception
    {
        GCMModeCipher gcm = createGCM(createAESEngine());
        SecureRandom rnd = new SecureRandom();

        int[] ivLens = new int[]{10,12,16};
        for (int i = 0; i != ivLens.length; i++)
        {
            int ivLen = ivLens[i];
            int[] kss = new int[]{16, 24, 32};
            for (int j = 0; j != kss.length; j++)
            {
                int ks = kss[j];
                byte[] key = new byte[ks];
                byte[] iv = new byte[ivLen];

                rnd.nextBytes(key);
                rnd.nextBytes(iv);
                gcm.init(true, new ParametersWithIV(new KeyParameter(key), iv));

                byte[] msg = new byte[1024];
                rnd.nextBytes(msg);

                byte[] ct = new byte[gcm.getOutputSize(msg.length)];

                int l = gcm.processBytes(msg, 0, msg.length, ct, 0);
                gcm.doFinal(ct, l);

                //
                // Set up decrypt and do it before and after a reset.
                //
                gcm.init(false, new ParametersWithIV(new KeyParameter(key), iv));

                byte[] outPreReset = new byte[msg.length];
                l = gcm.processBytes(ct, 0, ct.length, outPreReset, 0);
                gcm.doFinal(outPreReset, l);

                gcm.reset();
                byte[] outPostReset = new byte[msg.length];
                l = gcm.processBytes(ct, 0, ct.length, outPostReset, 0);
                gcm.doFinal(outPostReset, l);

                isTrue("before / after reset decryptions not the same", Arrays.areEqual(outPreReset, outPostReset));
                isTrue("decryption not same as message", Arrays.areEqual(msg, outPostReset));

            }

        }

    }


    protected BlockCipher createAESEngine()
    {
        return AESEngine.newInstance();
    }

    protected GCMModeCipher createGCM(BlockCipher cipher)
    {
        return GCMBlockCipher.newInstance(cipher);
    }

    private void testExceptions() throws InvalidCipherTextException
    {
        GCMModeCipher gcm = createGCM(createAESEngine());

        try
        {
            gcm = createGCM(new DESEngine());

            fail("incorrect block size not picked up");
        } catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            gcm.init(false, new KeyParameter(new byte[16]));

            fail("illegal argument not picked up");
        } catch (IllegalArgumentException e)
        {
            // expected
        }

        AEADTestUtil.testTampering(this, gcm, new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]));

        byte[] P = Strings.toByteArray("Hello world!");
        byte[] buf = new byte[100];

        GCMModeCipher c = GCMBlockCipher.newInstance(AESEngine.newInstance());
        AEADParameters aeadParameters = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]);
        c.init(true, aeadParameters);

        c.processBytes(P, 0, P.length, buf, 0);

        c.doFinal(buf, 0);

        try
        {
            c.doFinal(buf, 0);
            fail("no exception on reuse");
        } catch (IllegalStateException e)
        {
            isTrue("wrong message", e.getMessage().equals("GCM cipher cannot be reused for encryption"));
        }

        try
        {
            c.init(true, aeadParameters);
            fail("no exception on reuse");
        } catch (IllegalArgumentException e)
        {
            isTrue("wrong message", e.getMessage().equals("cannot reuse nonce for GCM encryption"));
        }
    }

    /*
     * An init that is refused, or fails part way, must leave the cipher unusable rather than still armed with the
     * key and nonce of the previous encryption, and must not displace the key and nonce the reuse check remembers.
     */
    private void testRefusedInit() throws InvalidCipherTextException
    {
        byte[] P = Strings.toByteArray("Hello world!");
        byte[] buf = new byte[100];
        byte[] N = new byte[12];
        AEADParameters params = new AEADParameters(new KeyParameter(new byte[16]), 128, N, Strings.toByteArray("aad"));

        GCMModeCipher c = GCMBlockCipher.newInstance(AESEngine.newInstance());
        c.init(true, params);
        c.doFinal(buf, c.processBytes(P, 0, P.length, buf, 0));

        checkEncryptionRefused(c, P, buf, "after doFinal");

        try
        {
            c.init(true, params);
            fail("no exception on reuse");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message", e.getMessage().equals("cannot reuse nonce for GCM encryption"));
        }

        checkEncryptionRefused(c, P, buf, "after refused init");

        // an init that fails on the key must not replace the remembered key, or the original pair is accepted again
        try
        {
            c.init(true, new AEADParameters(new KeyParameter(new byte[15]), 128, N));
            fail("bad key length not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            c.init(true, params);
            fail("no exception on reuse after failed init");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message", e.getMessage().equals("cannot reuse nonce for GCM encryption"));
        }

        // a good init afterwards, with a fresh nonce or for decryption, still works
        byte[] N2 = new byte[12];
        N2[0] = 1;
        AEADParameters params2 = new AEADParameters(new KeyParameter(new byte[16]), 128, N2, Strings.toByteArray("aad"));
        c.init(true, params2);
        int len = c.processBytes(P, 0, P.length, buf, 0);
        len += c.doFinal(buf, len);

        try
        {
            c.init(true, new AEADParameters(new KeyParameter(new byte[16]), 136, N2));
            fail("bad mac size not picked up");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        c.init(false, params2);
        byte[] dec = new byte[P.length];
        int dLen = c.processBytes(buf, 0, len, dec, 0);
        dLen += c.doFinal(dec, dLen);
        isTrue("decryption after refused init failed", dLen == P.length && areEqual(P, dec));
    }

    private void checkEncryptionRefused(GCMModeCipher c, byte[] P, byte[] buf, String when)
    {
        String expected = "GCM cipher cannot be reused for encryption";

        try
        {
            c.processAADByte(P[0]);
            fail("processAADByte allowed " + when);
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message", expected.equals(e.getMessage()));
        }

        try
        {
            c.processAADBytes(P, 0, P.length);
            fail("processAADBytes allowed " + when);
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message", expected.equals(e.getMessage()));
        }

        try
        {
            c.processByte(P[0], buf, 0);
            fail("processByte allowed " + when);
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message", expected.equals(e.getMessage()));
        }

        try
        {
            c.processBytes(P, 0, P.length, buf, 0);
            fail("processBytes allowed " + when);
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message", expected.equals(e.getMessage()));
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
            GCMMultiplier encM,
            GCMMultiplier decM,
            String testName,
            byte[] K,
            byte[] IV,
            byte[] A,
            byte[] P,
            byte[] C,
            byte[] T)
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
            GCMMultiplier encM,
            GCMMultiplier decM,
            String testName,
            byte[] K,
            byte[] IV,
            byte[] A,
            byte[] SA,
            byte[] P,
            byte[] C,
            byte[] T)
            throws InvalidCipherTextException
    {
        AEADParameters parameters = new AEADParameters(new KeyParameter(K), T.length * 8, IV, A);
        GCMModeCipher encCipher = initCipher(encM, true, parameters);
        GCMModeCipher decCipher = initCipher(decM, false, parameters);
        checkTestCase(encCipher, decCipher, testName, SA, P, C, T);
        encCipher = initCipher(encM, true, parameters);
        checkTestCase(encCipher, decCipher, testName + " (reused)", SA, P, C, T);

        // Key reuse
        AEADParameters keyReuseParams = AEADTestUtil.reuseKey(parameters);

        try
        {
            encCipher.init(true, keyReuseParams);
            fail("no exception");
        } catch (IllegalArgumentException e)
        {
            isTrue("wrong message", "cannot reuse nonce for GCM encryption".equals(e.getMessage()));
        }
    }

    private GCMModeCipher initCipher(GCMMultiplier m, boolean forEncryption, AEADParameters parameters)
    {
        GCMModeCipher c = GCMBlockCipher.newInstance(AESEngine.newInstance(), m);
        c.init(forEncryption, parameters);
        return c;
    }

    private void checkTestCase(
            GCMModeCipher encCipher,
            GCMModeCipher decCipher,
            String testName,
            byte[] SA,
            byte[] P,
            byte[] C,
            byte[] T)
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
        GCMModeCipher cipher = initCipher(m, true, parameters);
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
        GCMModeCipher cipher = initCipher(null, true, parameters);

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
            return (int) ((n * (long) (rand.nextInt() >>> 1)) >> 31);
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
