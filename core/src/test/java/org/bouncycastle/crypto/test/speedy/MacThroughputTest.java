package org.bouncycastle.crypto.test.speedy;

import java.security.SecureRandom;

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
    private interface MacProvider
    {
        public Mac getMac();

        int getRateFactor();

        public String getAlgorithmName();

        public int getMacSize();
    }

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

    private static final MacProvider POLY_1305 = new MacProvider() {

        public Mac getMac()
        {
            final Poly1305 mac = new Poly1305(new NullEngine(16));
            new ParametersWithIV(generatePoly1305Key(), generateNonce(16));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "Poly1305";
        }

        public int getMacSize()
        {
            return 16;
        }

        public int getRateFactor()
        {
            return 1;
        }
    };

    private static final MacProvider POLY_1305_AES = new MacProvider() {

        public Mac getMac()
        {
            final Poly1305 mac = new Poly1305(new NullEngine(16));
            new ParametersWithIV(generatePoly1305Key(), generateNonce(16));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "Poly1305-AES";
        }

        public int getMacSize()
        {
            return 16;
        }

        public int getRateFactor()
        {
            return 1;
        }
    };

    private static final MacProvider POLY_1305_REF = new MacProvider() {

        public Mac getMac()
        {
            final Mac mac = new Poly1305Reference(new NullEngine(16));
            new ParametersWithIV(generatePoly1305Key(), generateNonce(16));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "Poly1305-Ref";
        }

        public int getMacSize()
        {
            return 16;
        }

        public int getRateFactor()
        {
            return 10;
        }
    };

    private static final MacProvider CMAC_AES = new MacProvider() {

        public Mac getMac()
        {
            final Mac mac = new CMac(new AESFastEngine());
            mac.init(new KeyParameter(generateNonce(16)));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "CMAC-AES";
        }

        public int getMacSize()
        {
            return 16;
        }

        public int getRateFactor()
        {
            return 3;
        }
    };

    private static final MacProvider GMAC_AES = new MacProvider() {

        public Mac getMac()
        {
            final Mac mac = new GMac(new GCMBlockCipher(new AESFastEngine()));
            mac.init(new ParametersWithIV(new KeyParameter(generateNonce(16)), generateNonce(16)));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "GMAC-AES";
        }

        public int getMacSize()
        {
            return 16;
        }

        public int getRateFactor()
        {
            return 5;
        }
    };

    private static final MacProvider SIPHASH = new MacProvider() {

        public Mac getMac()
        {
            final Mac mac = new SipHash();
            mac.init(new KeyParameter(generateNonce(16)));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "SipHash";
        }

        public int getMacSize()
        {
            return 8;
        }

        public int getRateFactor()
        {
            return 1;
        }
    };

    private static final MacProvider SKEIN = new MacProvider() {

        public Mac getMac()
        {
            final Mac mac = new SkeinMac(SkeinMac.SKEIN_512, 128);
            mac.init(new KeyParameter(generateNonce(64)));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "SkeinMac";
        }

        public int getMacSize()
        {
            return 16;
        }

        public int getRateFactor()
        {
            return 2;
        }
    };

    private static final MacProvider HMAC_SHA1 = new MacProvider() {

        public Mac getMac()
        {
            final Mac mac = new HMac(new SHA1Digest());
            mac.init(new KeyParameter(generateNonce(20)));
            return mac;
        }

        public String getAlgorithmName()
        {
            return "HMAC-SHA1";
        }

        public int getMacSize()
        {
            return 20;
        }

        public int getRateFactor()
        {
            return 3;
        }
    };

    public static void main(String[] args)
    {
        // testMac(HMAC_SHA1);
        // testMac(SKEIN);
        testMac(SIPHASH);
        testMac(CMAC_AES);
        // testMac(GMAC_AES);
        // testMac(POLY_1305);
        // testMac(POLY_1305_AES);
        // testMac(POLY_1305_REF);
    }

    private static byte[] generateNonce(int sizeBytes)
    {
        byte[] nonce = new byte[16];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    private static void testMac(MacProvider macProvider)
    {
        System.out.println("=========================");

        long total = testRun(macProvider, false, MEDIUM_MESSAGE, MEDIUM_MESSAGE_COUNT);
        System.out.printf("%s Warmup 1 run time: %,d ms\n", macProvider.getAlgorithmName(), total / 1000000);
        total = testRun(macProvider, false, MEDIUM_MESSAGE, MEDIUM_MESSAGE_COUNT);
        System.out.printf("%s Warmup 2 run time: %,d ms\n", macProvider.getAlgorithmName(), total / 1000000);
        System.gc();
        try
        {
            Thread.sleep(1000);
        } catch (InterruptedException e)
        {
        }

        test("Short", macProvider, false, SHORT_MESSAGE, SHORT_MESSAGE_COUNT);
        // test("Short", macProvider, true, SHORT_MESSAGE, SHORT_MESSAGE_COUNT / 100);
        test("Medium", macProvider, false, MEDIUM_MESSAGE, MEDIUM_MESSAGE_COUNT);
        // test("Medium", macProvider, true, MEDIUM_MESSAGE, MEDIUM_MESSAGE_COUNT / 10);
        test("Long", macProvider, false, LONG_MESSAGE, LONG_MESSAGE_COUNT);
        // test("Long", macProvider, true, LONG_MESSAGE, LONG_MESSAGE_COUNT / 3);
    }

    private static void test(String name,
                             MacProvider macProvider,
                             boolean macPerMessage,
                             byte[] message,
                             int iterationCount)
    {
        System.out.println("=========================");
        long total = testRun(macProvider, macPerMessage, message, iterationCount);

        int adjustedCount = (int)(iterationCount * (1.0f / macProvider.getRateFactor()));
        long averageRuntime = total / adjustedCount;
        System.out.printf("%s %-7s%s Total run time:   %,d ms\n", macProvider.getAlgorithmName(), name,
                macPerMessage ? "*" : " ", total / 1000000);
        System.out.printf("%s %-7s%s Average run time: %,d ns\n", macProvider.getAlgorithmName(), name,
                macPerMessage ? "*" : " ", averageRuntime);
        final long mbPerSecond = (long)((double)message.length / averageRuntime * 1000000000 / (1024 * 1024));
        System.out.printf("%s %-7s%s Average speed:    %,d MB/s\n", macProvider.getAlgorithmName(), name,
                macPerMessage ? "*" : " ", mbPerSecond);
        System.out.printf("%s %-7s%s Average speed:    %,f c/b\n", macProvider.getAlgorithmName(), name,
                macPerMessage ? "*" : " ", CLOCK_SPEED / (double)(mbPerSecond * (1024 * 1024)));
    }

    private static long testRun(MacProvider macProvider, boolean macPerMessage, byte[] message, int iterationCount)
    {
        byte[] out = new byte[macProvider.getMacSize()];

        Mac mac = null;
        if (!macPerMessage)
        {
            mac = macProvider.getMac();
        }
        long start = System.nanoTime();

        int adjustedCount = (int)(iterationCount * (1.0f / macProvider.getRateFactor()));
        // System.err.println(macProvider.getAlgorithmName() + " " + adjustedCount);
        for (int i = 0; i < adjustedCount; i++)
        {
            if (macPerMessage)
            {
                mac = macProvider.getMac();
            }
            mac.update(message, 0, message.length);
            mac.doFinal(out, 0);
        }
        long total = System.nanoTime() - start;
        return total;
    }
}
