package org.bouncycastle.crypto.test.speedy;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import org.bouncycastle.util.encoders.Hex;

public class ThroughputTest
{

    private static final int DATA_SIZE = 100 * 1024 * 1024;
    private static final int RUNS = 1;
    private static final long CLOCK_SPEED = 2400000000L;

    private static SecureRandom rand = new SecureRandom();

    public static void main(String[] args)
        throws InterruptedException, IOException
    {
//        testTF_1024_1();
//        testTF_1024_2();
        testTF_512_1();
        testTF_512_2();
//        testTF_256_1();
//        testTF_256_2();
        System.out.println("Initialising test data.");
        byte[] input = new byte[DATA_SIZE];
        rand.nextBytes(input);

        System.out.println("Init complete.");
//        speedTestCipher(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256), input);
        speedTestCipher(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512), input);
//        speedTestCipher(new Skein3FishEngine(), input);
//        speedTestCipher(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024), input);
//        speedTestCipher(new ThreefishReferenceEngine(), input);
        speedTestCipher(new AESFastEngine(), input);
//        speedTestCipher(new TwofishEngine(), input);
//        speedTestCipher(new BlowfishEngine(), input);
    }

    private static void testTF_512_1()
        throws IOException
    {
        byte[] key = new byte[64];
        byte[] tweak = new byte[16];
        byte[] plaintext = new byte[64];
        byte[] expected = Hex.decode("b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe");

        runTestVector("Threefish-512-1: Fast", key, tweak, plaintext, expected, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512));
        runTestVector("Threefish-512-1: Reference", key, tweak, plaintext, expected, new ThreefishReferenceEngine());
    }

    private static void testTF_256_1()
        throws IOException
    {
        byte[] key = new byte[32];
        byte[] tweak = new byte[16];
        byte[] plaintext = new byte[32];
        byte[] expected = Hex.decode("84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8");

        runTestVector("Threefish-256-1: ", key, tweak, plaintext, expected, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256));
    }

    private static void testTF_1024_1()
        throws IOException
    {
        byte[] key = new byte[128];
        byte[] tweak = new byte[16];
        byte[] plaintext = new byte[128];
        byte[] expected = Hex.decode("f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90df0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a20b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e");

        runTestVector("Threefish-1024-1: ", key, tweak, plaintext, expected, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024));
    }

    private static void runTestVector(String name, byte[] key, byte[] tweak, byte[] plaintext, byte[] expected, BlockCipher cipher)
    {
        System.out.println("====");
        System.out.println(name + ": ");
        cipher.init(true, new TweakableBlockCipherParameters(new KeyParameter(key), tweak));

        byte[] ciphertext = new byte[key.length];
        cipher.processBlock(plaintext, 0, ciphertext, 0);

        System.out.println("Plaintext  : " + new String(Hex.encode(plaintext)));
        System.out.println("Expected   : " + new String(Hex.encode(expected)));
        System.out.println("Ciphertext : " + new String(Hex.encode(ciphertext)));
        System.out.println("  Encrypt  : " + org.bouncycastle.util.Arrays.areEqual(expected, ciphertext));

        cipher.init(false, new TweakableBlockCipherParameters(new KeyParameter(key), tweak));
        byte[] replain = new byte[plaintext.length];
        cipher.processBlock(ciphertext, 0, replain, 0);

        System.out.println("Replain    : " + new String(Hex.encode(replain)));
        System.out.println("  Decrypt  : " + org.bouncycastle.util.Arrays.areEqual(plaintext, replain));
    }

    private static void testTF_512_2()
        throws IOException
    {
        byte[] key = Hex.decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        byte[] tweak = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] plaintext = Hex.decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0");
        byte[] expected = Hex.decode("e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d");

        runTestVector("Threefish-512-2: Fast", key, tweak, plaintext, expected, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512));
        runTestVector("Threefish-512-2: Reference", key, tweak, plaintext, expected, new ThreefishReferenceEngine());
    }

    private static void testTF_256_2()
        throws IOException
    {
        byte[] key = Hex.decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
        byte[] tweak = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] plaintext = Hex.decode("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0");
        byte[] expected = Hex.decode("e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df");

        runTestVector("Threefish-256-2: ", key, tweak, plaintext, expected, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256));
    }

    private static void testTF_1024_2()
        throws IOException
    {
        byte[] key = Hex.decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        byte[] tweak = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] plaintext = Hex.decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180");
        byte[] expected = Hex.decode("a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c83313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde");

        runTestVector("Threefish-1024-2: ", key, tweak, plaintext, expected, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024));
    }

    private static void speedTestCipher(BlockCipher cipher, byte[] input)
        throws InterruptedException
    {
        byte[] key = new byte[cipher.getBlockSize()];
        rand.nextBytes(key);

        cipher.init(true, new KeyParameter(key));
        speedTestCipherForMode("encrypt", cipher, input);
        cipher.init(false, new KeyParameter(key));
        speedTestCipherForMode("decrypt", cipher, input);
    }

    private static void speedTestCipherForMode(String mode, BlockCipher cipher, byte[] input)
        throws InterruptedException
    {
        System.out.println("======");
        System.out.println("Testing " + cipher.getAlgorithmName() + " " + cipher.getBlockSize() * 8 + " " + mode);
        System.out.println("Beginning warmup run.");

        long warmup = testCipher(cipher, input);
        System.out.println("Warmup run 1 in " + (warmup / 1000000) + "ms");
        Thread.sleep(100);
        warmup = testCipher(cipher, input);
        System.out.println("Warmup run 2 in " + (warmup / 1000000) + "ms");

        System.gc();
        Thread.sleep(500);
        System.gc();
        Thread.sleep(500);

        System.out.println("Beginning " + RUNS + " hot runs.");

        long[] runtimes = new long[RUNS];
        long total = 0;
        for (int i = 0; i < RUNS; i++)
        {
            runtimes[i] = testCipher(cipher, input);
            total += runtimes[i];
            System.out.println("Run " + (i + 1) + ": " + runtimes[i] / 100000 + "ms");
        }
        long averageRuntime = total / RUNS;
        System.out.println(cipher.getAlgorithmName() + " Average run time: " + averageRuntime / 1000000 + "ms");
        final long mbPerSecond = (long)((double)DATA_SIZE / averageRuntime * 1000000000 / (1024 * 1024));
        System.out.println(cipher.getAlgorithmName() + " Average speed:    " + mbPerSecond + " MB/s");
        System.out.println(cipher.getAlgorithmName() + " Average speed:    " + CLOCK_SPEED / (double)(mbPerSecond * (1024 * 1024)) + " c/b");
    }

    private static long testCipher(BlockCipher cipher, byte[] input)
    {
        long start = System.nanoTime();
        int blockSize = cipher.getBlockSize();
        byte[] out = new byte[blockSize];

        for (int i = 0; i < (input.length - blockSize); i += blockSize)
        {
            cipher.processBlock(input, i, out, 0);
//            byte[] test = new byte[blockSize];
//            System.arraycopy(input, i, test, 0, test.length);
//            if (!Arrays.equals(out, test)) {
//                System.err.println(":(");
//            }
        }

        long end = System.nanoTime();
        long delta = end - start;
        return delta;
    }
}
