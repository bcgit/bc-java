package org.bouncycastle.crypto.test.speedy;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.NullEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.macs.SipHash;
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Microbenchmark of MACs on short, medium, long messages, with optional object creation cost.
 */
public class MacThroughputTest
{

    private static final long CLOCK_SPEED = 2400000000L;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static Poly1305KeyGenerator kg = new Poly1305KeyGenerator();;

    private static final byte[] SHORT_MESSAGE = new byte[16];
    private static final byte[] MEDIUM_MESSAGE = new byte[256];
    private static final byte[] LONG_MESSAGE = new byte[8192];
    static
    {
        RANDOM.nextBytes(SHORT_MESSAGE);
        RANDOM.nextBytes(MEDIUM_MESSAGE);
        RANDOM.nextBytes(LONG_MESSAGE);
    }

    private static final int SHORT_MESSAGE_COUNT = 20000000;
    private static final int MEDIUM_MESSAGE_COUNT = 2200000;
    private static final int LONG_MESSAGE_COUNT = 80000;

    static
    {
        kg.init(new KeyGenerationParameters(RANDOM, 256));
    }

    private static KeyParameter generatePoly1305Key()
    {
        return new KeyParameter(kg.generateKey());
    }

    public static void main(String[] args)
    {
        testMac(new HMac(new SHA1Digest()), new KeyParameter(generateNonce(20)), 3);
        testMac(new SkeinMac(SkeinMac.SKEIN_512, 128), new KeyParameter(generateNonce(64)), 2);
        testMac(new SipHash(), new KeyParameter(generateNonce(16)), 1);
        testMac(new CMac(new AESFastEngine()), new KeyParameter(generateNonce(16)), 3);
        testMac(new GMac(new GCMBlockCipher(new AESFastEngine())), new ParametersWithIV(new KeyParameter(
                generateNonce(16)), generateNonce(16)), 5);
        testMac(new Poly1305(new NullEngine(16)), new ParametersWithIV(generatePoly1305Key(), generateNonce(16)), 1);
        testMac(new Poly1305(new AESFastEngine()), new ParametersWithIV(generatePoly1305Key(), generateNonce(16)), 1);
        testMac(new Poly1305Reference(new NullEngine(16)), new ParametersWithIV(generatePoly1305Key(),
                generateNonce(16)), 1);
    }

    private static byte[] generateNonce(int sizeBytes)
    {
        byte[] nonce = new byte[16];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    private static void testMac(Mac mac, CipherParameters params, int rateFactor)
    {
        System.out.println("=========================");

        long total = testRun(mac, params, false, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT, rateFactor));
        System.out.printf("%s Warmup 1 run time: %,d ms\n", mac.getAlgorithmName(), total / 1000000);
        total = testRun(mac, params, false, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT, rateFactor));
        System.out.printf("%s Warmup 2 run time: %,d ms\n", mac.getAlgorithmName(), total / 1000000);
        System.gc();
        try
        {
            Thread.sleep(1000);
        } catch (InterruptedException e)
        {
        }

        test("Short", mac, params, false, SHORT_MESSAGE, adjust(SHORT_MESSAGE_COUNT, rateFactor));
        // test("Short", mac, params, true, SHORT_MESSAGE, adjust(SHORT_MESSAGE_COUNT, rateFactor));
        test("Medium", mac, params, false, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT, rateFactor));
        // test("Medium", mac, params, true, MEDIUM_MESSAGE, adjust(MEDIUM_MESSAGE_COUNT,
        // rateFactor));
        test("Long", mac, params, false, LONG_MESSAGE, adjust(LONG_MESSAGE_COUNT, rateFactor));
        // test("Long", mac, params, true, LONG_MESSAGE, adjust(LONG_MESSAGE_COUNT, rateFactor));
    }

    private static int adjust(int iterationCount, int rateFactor)
    {
        return (int)(iterationCount * (1.0f / rateFactor));
    }

    private static void test(String name,
                             Mac mac,
                             CipherParameters params,
                             boolean initPerMessage,
                             byte[] message,
                             int adjustedCount)
    {
        System.out.println("=========================");
        long total = testRun(mac, params, initPerMessage, message, adjustedCount);

        long averageRuntime = total / adjustedCount;
        System.out.printf("%s %-7s%s Total run time:   %,d ms\n", mac.getAlgorithmName(), name, initPerMessage ? "*"
                : " ", total / 1000000);
        System.out.printf("%s %-7s%s Average run time: %,d ns\n", mac.getAlgorithmName(), name, initPerMessage ? "*"
                : " ", averageRuntime);
        final long mbPerSecond = (long)((double)message.length / averageRuntime * 1000000000 / (1024 * 1024));
        System.out.printf("%s %-7s%s Average speed:    %,d MB/s\n", mac.getAlgorithmName(), name, initPerMessage ? "*"
                : " ", mbPerSecond);
        System.out.printf("%s %-7s%s Average speed:    %,f c/b\n", mac.getAlgorithmName(), name, initPerMessage ? "*"
                : " ", CLOCK_SPEED / (double)(mbPerSecond * (1024 * 1024)));
    }

    private static long testRun(Mac mac,
                                CipherParameters params,
                                boolean initPerMessage,
                                byte[] message,
                                int adjustedCount)
    {
        byte[] out = new byte[mac.getMacSize()];

        if (!initPerMessage)
        {
            mac.init(params);
        }
        long start = System.nanoTime();

        for (int i = 0; i < adjustedCount; i++)
        {
            if (initPerMessage)
            {
                mac.init(params);
            }
            mac.update(message, 0, message.length);
            mac.doFinal(out, 0);
        }
        long total = System.nanoTime() - start;
        return total;
    }
}
