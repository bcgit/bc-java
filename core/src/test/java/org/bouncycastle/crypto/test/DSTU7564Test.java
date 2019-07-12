package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.macs.DSTU7564Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class DSTU7564Test
    extends DigestTest
{

    private static String[] messages =
        {
            "",
            "a",
            "abc",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        };

    private static String[] digests =
        {
            "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6",
            "c51a1d639596fb613d86557314a150c40f8fff3de48bc93a3b03c161f4105ee4",
            "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04",
            "02621dbb53f2c7001be64d7308ecb80d21ba7797c92e98d1efc240d41e4c414b"
        };

    protected Digest cloneDigest(Digest digest)
    {
        return new DSTU7564Digest((DSTU7564Digest)digest);
    }

    public DSTU7564Test()
    {
        super(new DSTU7564Digest(256), messages, digests);
    }

    public static void main(String[] args)
    {
        runTest(new DSTU7564Test());
    }

    public void performTest()
    {
        super.performTest();

        hash256Tests();
        hash384Tests();
        hash512Tests();
        macTests();
        overflowTest();
        keySizeTest();
    }

    private void overflowTest()
    {
        int macBitSize = 256;
        byte[] input = new byte[1024];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }
        byte[] key = Hex.decode("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");

        byte[] expectedMac = Hex.decode("165382df70adcb040b17c1aced117d26d598b239ab631271a05f6d0f875ae9ea");
        byte[] mac = new byte[macBitSize / 8];

        DSTU7564Mac dstu7564mac = new DSTU7564Mac(macBitSize);

        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed overflow test 1 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        macBitSize = 256;
        input = new byte[1023];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }
        key = Hex.decode("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");

        expectedMac = Hex.decode("ed45f163e694d990d2d835dca2f3f869a55a31396c8138161b190d5914d50686");
        mac = new byte[macBitSize / 8];

        dstu7564mac = new DSTU7564Mac(macBitSize);

        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed overflow test 2 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        DSTU7564Digest digest = new DSTU7564Digest(macBitSize);
        byte[] expectedDigest = Hex.decode("6bfc5ec8c1f5963fbed89da115d86e9330634eca341dd42fd94a7007e4af7942");
        byte[] digestBuf = new byte[macBitSize / 8];

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 3 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        expectedDigest = Hex.decode("6f8f0a3f8261af77581ab01cb89d4cb5ed87ca1d9954f11d5586e94b45c82fb8");

        input = new byte[51];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 4 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[52];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("8b6fe2ba77e684b2a1ac82232f4efc49f681cd18c82a0cfff530186a2fc642d2");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 5 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }


        input = new byte[53];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("837f2b0cbe39a4defdfcb44272288d4091cab850161c70695d7831fc5f00e171");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 6 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[54];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("21d423d5b8c7f18a0da42cdd95b36b66344125e2adc6edeab5899926442113bc");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 7 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[55];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("0e7bf74464b81b3ae7d904170776d29f4b02a7227da578dd562d01027af7fd0e");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 8 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[56];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("badea1f49cbcec94acec52b4c695acdddd786cca5a6763929f341a58c5134b3b");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 9 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[57];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("a13b5f6f53ee043292ed65b66c1d49759be4d2fe0c2f6148f2416487965f7bde");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 10 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[63];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("03a44a02c9ffafb43addb290bbcf3b8168f624e8cbd332dc6a9dc7df9d39cbc2");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 11 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[64];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 12 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[65];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("a81c2fb92351f370050b7c36cd51736d5603a50ec1106cbd5fe1c9be2e5c77a6");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 13 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }
    }

    private void macTests()
    {

        //test1
        int macBitSize = 256;
        byte[] input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        byte[] key = Hex.decode("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");

        byte[] expectedMac = Hex.decode("B60594D56FA79BA210314C72C2495087CCD0A99FC04ACFE2A39EF669925D98EE");
        byte[] mac = new byte[macBitSize / 8];

        DSTU7564Mac dstu7564mac = new DSTU7564Mac(macBitSize);

        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed mac test 1 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        //test1a
        input = Hex.decode("0001020304050607");
        key = Hex.decode("08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875");

        expectedMac = Hex.decode("383A0B11989ABF61B2CF3EB489351EB7C9AEF70CF5A9D6DBD90F340FF151BA2D");
        mac = new byte[macBitSize / 8];

        dstu7564mac = new DSTU7564Mac(macBitSize);

        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed mac test 1a - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        //test 2
        macBitSize = 384;
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        key = Hex.decode("2F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");

        expectedMac = Hex.decode("BEBFD8D730336F043ABACB41829E79A4D320AEDDD8D14024D5B805DA70C396FA295C281A38B30AE728A304B3F5AE490E");
        mac = new byte[macBitSize / 8];

        dstu7564mac = new DSTU7564Mac(macBitSize);

        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed mac test 2 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        //test 3
        macBitSize = 512;
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        key = Hex.decode("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");

        expectedMac = Hex.decode("F270043C06A5C37E65D9D791C5FBFB966E5EE709F8F54019C9A55B76CA40B70100579F269CEC24E347A9D864614CF3ABBF6610742E4DB3BD2ABC000387C49D24");
        mac = new byte[macBitSize / 8];

        dstu7564mac = new DSTU7564Mac(macBitSize);

        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed mac test 3 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        // check doFinal() has reset
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed mac test reset - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        // check that init reset correctly
        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed mac test double init - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        // check simple reset
        dstu7564mac = new DSTU7564Mac(macBitSize);
        dstu7564mac.reset();
    }

    private void hash512Tests()
    {

        int hashBitSize = 512;

        //test 1
        byte[] input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        byte[] expectedHash = Hex.decode("3813E2109118CDFB5A6D5E72F7208DCCC80A2DFB3AFDFB02F46992B5EDBE536B3560DD1D7E29C6F53978AF58B444E37BA685C0DD910533BA5D78EFFFC13DE62A");
        byte[] hash = new byte[hashBitSize / 8];


        DSTU7564Digest dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-512 test 1 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 2
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
        expectedHash = Hex.decode("76ED1AC28B1D0143013FFA87213B4090B356441263C13E03FA060A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE");
        hash = new byte[hashBitSize / 8];


        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-512 test 2 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 3
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        expectedHash = Hex.decode("0DD03D7350C409CB3C29C25893A0724F6B133FA8B9EB90A64D1A8FA93B56556611EB187D715A956B107E3BFC76482298133A9CE8CBC0BD5E1436A5B197284F7E");
        hash = new byte[hashBitSize / 8];


        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-512 test 3 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 4
        input = Hex.decode("FF");
        expectedHash = Hex.decode("871B18CF754B72740307A97B449ABEB32B64444CC0D5A4D65830AE5456837A72D8458F12C8F06C98C616ABE11897F86263B5CB77C420FB375374BEC52B6D0292");
        hash = new byte[hashBitSize / 8];


        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-512 test 4 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 5
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");
        expectedHash = Hex.decode("B189BFE987F682F5F167F0D7FA565330E126B6E592B1C55D44299064EF95B1A57F3C2D0ECF17869D1D199EBBD02E8857FB8ADD67A8C31F56CD82C016CF743121");
        hash = new byte[hashBitSize / 8];


        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-512 test 5 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }


        //test 6
        input = Hex.decode("");
        expectedHash = Hex.decode("656B2F4CD71462388B64A37043EA55DBE445D452AECD46C3298343314EF04019BCFA3F04265A9857F91BE91FCE197096187CEDA78C9C1C021C294A0689198538");
        hash = new byte[hashBitSize / 8];


        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-512 test 6 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }
    }

    private void hash384Tests()
    {

        int hashBitSize = 384;

        //test 1
        byte[] input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E");
        byte[] expectedHash = Hex.decode("D9021692D84E5175735654846BA751E6D0ED0FAC36DFBC0841287DCB0B5584C75016C3DECC2A6E47C50B2F3811E351B8");
        byte[] hash = new byte[hashBitSize / 8];


        DSTU7564Digest dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-384 test 1 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }
    }

    private void keySizeTest()
    {
        doKeySizeTest(new DSTU7564Mac(512));
        doKeySizeTest(new DSTU7564Mac(256));
    }

    private void doKeySizeTest(Mac dstuMac)
    {
        /* Define message */
        final byte[] myMessage = "1234567890123456".getBytes();

        /* Determine underlying engine size */
        final int myEngineSize = dstuMac.getMacSize() == 32 ? 64 : 128;

        /* Define key (can be any multiple of engineSize) */
        final byte[] myKey = new byte[myEngineSize];

        /* Initialise Mac (will fail with ArrayIndexOutOfBoundsException) */
        dstuMac.init(new KeyParameter(myKey));
        final int myOutSize = dstuMac.getMacSize();
        final byte[] myOut = new byte[myOutSize];
        dstuMac.update(myMessage, 0, myMessage.length);
        dstuMac.doFinal(myOut, 0);
    }

    private void hash256Tests()
    {

        int hashBitSize = 256;

        //test 1
        byte[] input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        byte[] expectedHash = Hex.decode("08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875");
        byte[] hash = new byte[hashBitSize / 8];


        DSTU7564Digest dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-256 test 1 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 2
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
        expectedHash = Hex.decode("0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882");
        hash = new byte[hashBitSize / 8];


        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-256 test 2 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 3
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        expectedHash = Hex.decode("D305A32B963D149DC765F68594505D4077024F836C1BF03806E1624CE176C08F");
        hash = new byte[hashBitSize / 8];

        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-256 test 3 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 4
        input = Hex.decode("FF");
        expectedHash = Hex.decode("EA7677CA4526555680441C117982EA14059EA6D0D7124D6ECDB3DEEC49E890F4");
        hash = new byte[hashBitSize / 8];

        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-256 test 4 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 5
        input = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E");
        expectedHash = Hex.decode("1075C8B0CB910F116BDA5FA1F19C29CF8ECC75CAFF7208BA2994B68FC56E8D16");
        hash = new byte[hashBitSize / 8];

        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-256 test 5 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }

        //test 6
        input = Hex.decode("");
        expectedHash = Hex.decode("CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6");
        hash = new byte[hashBitSize / 8];

        dstu7564 = new DSTU7564Digest(hashBitSize);
        dstu7564.update(input, 0, input.length);
        dstu7564.doFinal(hash, 0);

        if (!Arrays.areEqual(expectedHash, hash))
        {
            fail("Failed hash-256 test 6 - expected "
                + Hex.toHexString(expectedHash)
                + " got " + Hex.toHexString(hash));
        }
    }
}
