package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/*
 */
public class Poly1305Test
    extends SimpleTest
{
    private static final int MAXLEN = 1000;

    private static class KeyEngine
        implements BlockCipher
    {

        private byte[] key;
        private final int blockSize;

        public KeyEngine(int blockSize)
        {
            this.blockSize = blockSize;
        }

        public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
        {
            if (params instanceof KeyParameter)
            {
                this.key = ((KeyParameter)params).getKey();
            }
        }

        public String getAlgorithmName()
        {
            return "Key";
        }

        public int getBlockSize()
        {
            return blockSize;
        }

        public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException,
            IllegalStateException
        {
            System.arraycopy(key, 0, out, outOff, key.length);
            return key.length;
        }

        public void reset()
        {
        }

    }

    private static class TestCase
    {
        private final byte[] key;
        private final byte[] nonce;
        private final byte[] message;
        private final byte[] expectedMac;

        public TestCase(String key, String nonce, String message, String expectedMac)
        {
            this.key = Hex.decode(key);
            // nacl test case keys are not pre-clamped
            Poly1305KeyGenerator.clamp(this.key);
            this.nonce = (nonce == null) ? null : Hex.decode(nonce);
            this.message = Hex.decode(message);
            this.expectedMac = Hex.decode(expectedMac);
        }
    }

    private static TestCase[] CASES = {
            // Raw Poly1305
            // onetimeauth.c from nacl-20110221
            new TestCase("2539121d8e234e652d651fa4c8cff880eea6a7251c1e72916d11c2cb214d3c25", null,
                    "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
                        + "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
                        + "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
                        + "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
                    "f3ffc7703f9400e52a7dfb4b3d3305d9"),

            // Poly1305-AES
            // Loop 1 of test-poly1305aes from poly1305aes-20050218
            new TestCase("0000000000000000000000000000000000000000000000000000000000000000",
                    "00000000000000000000000000000000", "", "66e94bd4ef8a2c3b884cfa59ca342b2e"),
            new TestCase("f795bd4a52e29ed713d313fa20e98dbcf795bd0a50e29e0710d3130a20e98d0c",
                    "917cf69ebd68b2ec9b9fe9a3eadda692", "66f7", "5ca585c75e8f8f025e710cabc9a1508b"),
            new TestCase("e69dae0aab9f91c03a325dcc9436fa903ef49901c8e11c000430d90ad45e7603",
                    "166450152e2394835606a9d1dd2cdc8b", "66f75c0e0c7a406586", "2924f51b9c2eff5df09db61dd03a9ca1"),
            new TestCase("85a4ea91a7de0b0d96eed0d4bf6ecf1cda4afc035087d90e503f8f0ea08c3e0d",
                    "0b6ef7a0b8f8c738b0f8d5995415271f",
                    "66f75c0e0c7a40658629e3392f7f8e3349a02191ffd49f39879a8d9d1d0e23ea",
                    "3c5a13adb18d31c64cc29972030c917d"),
            new TestCase(
                    "25eb69bac5cdf7d6bfcee4d9d5507b82ca3c6a0da0a864024ca3090628c28e0d",
                    "046772a4f0a8de92e4f0d628cdb04484",
                    "66f75c0e0c7a40658629e3392f7f8e3349a02191ffd49f39879a8d9d1d0e23ea3caa4d240bd2ab8a8c4a6bb8d3288d9de4b793f05e97646dd4d98055de",
                    "fc5fb58dc65daf19b14d1d05da1064e8"),

            // Specific test cases generated from test-poly1305aes from poly1305aes-20050218 that
            // expose Java unsigned integer problems
            new TestCase(
                    "95cc0e44d0b79a8856afcae1bec4fe3c" + "01bcb20bfc8b6e03609ddd09f44b060f",
                    null,
                    "66f75c0e0c7a40658629e3392f7f8e3349a02191ffd49f39879a8d9d1d0e23ea3caa4d240bd2ab8a8c4a6bb8d3288d9de4b793f05e97646dd4d98055de"
                        + "fc3e0677d956b4c62664bac15962ab15d93ccbbc03aafdbde779162ed93b55361f0f8acaa41d50ef5175927fe79ea316186516eef15001cd04d3524a55"
                        + "e4fa3c5ca479d3aaa8a897c21807f721b6270ffc68b6889d81a116799f6aaa35d8e04c7a7dd5e6da2519e8759f54e906696f5772fee093283bcef7b930"
                        + "aed50323bcbc8c820c67422c1e16bdc022a9c0277c9d95fef0ea4ee11e2b27276da811523c5acb80154989f8a67ee9e3fa30b73b0c1c34bf46e3464d97"
                        + "7cd7fcd0ac3b82721080bb0d9b982ee2c77feee983d7ba35da88ce86955002940652ab63bc56fb16f994da2b01d74356509d7d1b6d7956b0e5a557757b"
                        + "d1ced2eef8650bc5b6d426108c1518abcbd0befb6a0d5fd57a3e2dbf31458eab63df66613653d4beae73f5c40eb438fbcfdcf4a4ba46320184b9ca0da4"
                        + "dfae77de7ccc910356caea3243f33a3c81b064b3b7cedc7435c223f664227215715980e6e0bb570d459ba80d7512dbe458c8f0f3f52d659b6e8eef19ee"
                        + "71aea2ced85c7a42ffca6522a62db49a2a46eff72bd7f7e0883acd087183f0627f3537a4d558754ed63358e8182bee196735b361dc9bd64d5e34e1074a"
                        + "855655d2974cc6fa1653754cf40f561d8c7dc526aab2908ec2d2b977cde1a1fb1071e32f40e049ea20f30368ba1592b4fe57fb51595d23acbdace324cd"
                        + "d78060a17187c662368854e915402d9b52fb21e984663e41c26a109437e162cfaf071b53f77e50000a5388ff183b82ce7a1af476c416d7d204157b3633"
                        + "b2f4ec077b699b032816997e37bceded8d4a04976fd7d0c0b029f290794c3be504c5242287ea2f831f11ed5690d92775cd6e863d7731fd4da687ebfb13"
                        + "df4c41dc0fb8", "ae345d555eb04d6947bb95c0965237e2"),
            new TestCase(
                    "76fb3635a2dc92a1f768163ab12f2187" + "cd07fd0ef8c0be0afcbdb30af4af0009",
                    null,
                    "f05204a74f0f88a7fa1a95b84ec3d8ffb36fcdc7723ea65dfe7cd464e86e0abf6b9d51db3220cfd8496ad6e6d36ebee8d990f9ce0d3bb7f72b7ab5b3ab0a73240d11efe772c857021ae859db4933cdde4387b471d2ce700fef4b81087f8f47c307881fd83017afcd15b8d21edf9b704677f46df97b07e5b83f87c8abd90af9b1d0f9e2710e8ebd0d4d1c6a055abea861f42368bed94d9373e909c1d3715b221c16bc524c55c31ec3eab204850bb2474a84f9917038eff9d921130951391b5c54f09b5e1de833ea2cd7d3b306740abb7096d1e173da83427da2adddd3631eda30b54dbf487f2b082e8646f07d6e0a87e97522ca38d4ace4954bf3db6dd3a93b06fa18eb56856627ed6cffcd7ae26374554ca18ab8905f26331d323fe10e6e70624c7bc07a70f06ecd804b48f8f7e75e910165e1beb554f1f0ec7949c9c8d429a206b4d5c0653102249b6098e6b45fac2a07ff0220b0b8ae8f4c6bcc0c813a7cd141fa8b398b42575fc395747c5a0257ac41d6c1f434cfbf5dfe8349f5347ef6b60e611f5d6c3cbc20ca2555274d1934325824cef4809da293ea13f181929e2af025bbd1c9abdc3af93afd4c50a2854ade3887f4d2c8c225168052c16e74d76d2dd3e9467a2c5b8e15c06ffbffa42b8536384139f07e195a8c9f70f514f31dca4eb2cf262c0dcbde53654b6250a29efe21d54e83c80e005a1cad36d5934ff01c32e4bc5fe06d03064ff4a268517df4a94c759289f323734318cfa5d859d4ce9c16e63d02dff0896976f521607638535d2ee8dd3312e1ddc80a55d34fe829ab954c1ebd54d929954770f1be9d32b4c05003c5c9e97943b6431e2afe820b1e967b19843e5985a131b1100517cdc363799104af91e2cf3f53cb8fd003653a6dd8a31a3f9d566a7124b0ffe9695bcb87c482eb60106f88198f766a40bc0f4873c23653c5f9e7a8e446f770beb8034cf01d21028ba15ccee21a8db918c4829d61c88bfa927bc5def831501796c5b401a60a6b1b433c9fb905c8cd40412fffee81ab",
                    "045be28cc52009f506bdbfabedacf0b4"),

    };

    public String getName()
    {
        return "Poly1305";
    }

    public void performTest()
        throws Exception
    {
        testKeyGenerator();
        testInit();
        for (int i = 0; i < CASES.length; i++)
        {
            testCase(i);
        }
        testSequential();
        testReset();
    }

    private void testCase(int i)
    {
        byte[] out = new byte[16];
        TestCase tc = CASES[i];

        final Mac mac;
        if (tc.nonce == null)
        {
            // Raw Poly1305 test - don't do any transform on AES key part
            mac = new Poly1305(new KeyEngine(16));
            mac.init(new ParametersWithIV(new KeyParameter(tc.key), new byte[16]));
        }
        else
        {
            mac = new Poly1305(new AESFastEngine());
            mac.init(new ParametersWithIV(new KeyParameter(tc.key), tc.nonce));
        }
        mac.update(tc.message, 0, tc.message.length);
        mac.doFinal(out, 0);

        if (!Arrays.areEqual(out, tc.expectedMac))
        {
            fail("Mismatched output " + i, new String(Hex.encode(tc.expectedMac)), new String(Hex.encode(out)));
        }
    }

    private void testSequential()
    {
        // Sequential test, adapted from test-poly1305aes
        int len;
        byte[] kr = new byte[32];
        byte[] m = new byte[MAXLEN];
        byte[] n = new byte[16];
        byte[] out = new byte[16];

        int c = 0;
        final Mac mac = new Poly1305(new AESFastEngine());
        for (int loop = 0; loop < 13; loop++)
        {
            len = 0;
            for (;;)
            {
                c++;
                mac.init(new ParametersWithIV(new KeyParameter(kr), n));
                mac.update(m, 0, len);
                mac.doFinal(out, 0);

                // if (c == 678)
                // {
                // TestCase tc = CASES[0];
                //
                // if (!Arrays.areEqual(tc.key, kr))
                // {
                // System.err.println("Key bad");
                // System.err.println(new String(Hex.encode(tc.key)));
                // System.err.println(new String(Hex.encode(kr)));
                // System.exit(1);
                // }
                // if (!Arrays.areEqual(tc.nonce, n))
                // {
                // System.err.println("Nonce bad");
                // System.exit(1);
                // }
                // System.out.printf("[%d] m: %s\n", c, new String(Hex.encode(m, 0, len)));
                // System.out.printf("[%d] K: %s\n", c, new String(Hex.encodje(kr)));
                // System.out.printf("[%d] N: %s\n", c, new String(Hex.encode(n)));
                // System.out.printf("[%d] M: ", c);
                // }
                // System.out.printf("%d/%s\n", c, new String(Hex.encode(out)));

                if (len >= MAXLEN)
                    break;
                n[0] ^= loop;
                for (int i = 0; i < 16; ++i)
                    n[i] ^= out[i];
                if (len % 2 != 0)
                    for (int i = 0; i < 16; ++i)
                        kr[i] ^= out[i];
                if (len % 3 != 0)
                    for (int i = 0; i < 16; ++i)
                        kr[i + 16] ^= out[i];
                Poly1305KeyGenerator.clamp(kr);
                m[len++] ^= out[0];
            }
        }
        // Output after 13 loops as generated by poly1305 ref
        if (c != 13013 || !Arrays.areEqual(out, Hex.decode("c96f60a23701a5b0fd2016f58cbe4f7e")))
        {
            fail("Sequential Poly1305 " + c, "c96f60a23701a5b0fd2016f58cbe4f7e", new String(Hex.encode(out)));
        }
    }

    private void testReset()
    {
        CipherKeyGenerator gen = new Poly1305KeyGenerator();
        gen.init(new KeyGenerationParameters(new SecureRandom(), 256));
        byte[] k = gen.generateKey();

        byte[] m = new byte[10000];
        byte[] check = new byte[16];
        byte[] out = new byte[16];

        // Generate baseline
        Mac poly = new Poly1305(new AESFastEngine());
        poly.init(new ParametersWithIV(new KeyParameter(k), new byte[16]));

        poly.update(m, 0, m.length);
        poly.doFinal(check, 0);

        // Check reset after doFinal
        poly.update(m, 0, m.length);
        poly.doFinal(out, 0);

        if (!Arrays.areEqual(check, out))
        {
            fail("Mac not reset after doFinal");
        }

        // Check reset
        poly.update((byte)1);
        poly.update((byte)2);
        poly.reset();
        poly.update(m, 0, m.length);
        poly.doFinal(out, 0);

        if (!Arrays.areEqual(check, out))
        {
            fail("Mac not reset after doFinal");
        }

        // Check init resets
        poly.update((byte)1);
        poly.update((byte)2);
        poly.init(new ParametersWithIV(new KeyParameter(k), new byte[16]));
        poly.update(m, 0, m.length);
        poly.doFinal(out, 0);

        if (!Arrays.areEqual(check, out))
        {
            fail("Mac not reset after doFinal");
        }
    }

    private void testInit()
    {
        CipherKeyGenerator gen = new Poly1305KeyGenerator();
        gen.init(new KeyGenerationParameters(new SecureRandom(), 256));
        byte[] k = gen.generateKey();

        Mac poly = new Poly1305(new AESFastEngine());
        poly.init(new ParametersWithIV(new KeyParameter(k), new byte[16]));

        try
        {
            poly.init(new ParametersWithIV(new KeyParameter(k), new byte[15]));
            fail("16 byte nonce required");
        } catch (IllegalArgumentException e)
        {
            // Expected
        }

        try
        {
            byte[] k2 = new byte[k.length - 1];
            System.arraycopy(k, 0, k2, 0, k2.length);
            poly.init(new ParametersWithIV(new KeyParameter(k2), new byte[16]));
            fail("32 byte key required");
        } catch (IllegalArgumentException e)
        {
            // Expected
        }

        try
        {
            k[19] = (byte)0xFF;
            poly.init(new ParametersWithIV(new KeyParameter(k), new byte[16]));
            fail("Unclamped key should not be accepted.");
        } catch (IllegalArgumentException e)
        {
            // Expected
        }

    }

    private void testKeyGenerator()
    {
        CipherKeyGenerator gen = new Poly1305KeyGenerator();
        gen.init(new KeyGenerationParameters(new SecureRandom(), 256));
        byte[] k = gen.generateKey();

        if (k.length != 32)
        {
            fail("Poly1305 key should be 256 bits.");
        }

        try
        {
            Poly1305KeyGenerator.checkKey(k);
        } catch (IllegalArgumentException e)
        {
            fail("Poly1305 key should be clamped on generation.");
        }

        byte[] k2 = new byte[k.length];
        System.arraycopy(k, 0, k2, 0, k2.length);
        Poly1305KeyGenerator.clamp(k);
        if (!Arrays.areEqual(k, k2))
        {
            fail("Poly1305 key should be clamped on generation.");
        }

        try
        {
            k2[19] = (byte)0xff;
            Poly1305KeyGenerator.checkKey(k2);
            fail("Unclamped key should fail check.");
        } catch (IllegalArgumentException e)
        {
            // Expected
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new Poly1305Test());
    }
}
