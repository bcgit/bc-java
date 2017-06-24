package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.macs.DSTU7564Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class DSTU7564Test
    extends DigestTest
{

    protected Digest cloneDigest(Digest digest)
    {
        return null;
    }

    public DSTU7564Test()
    {
        super(new DSTU7564Digest(256), new String[0], new String[0]);
    }

    public static void main(String[] args)
    {
        runTest(new DSTU7564Test());
    }


    @Override
    public void performTest()
    {
        hash256Tests();
        hash384Tests();
        hash512Tests();
        macTests();
        overflowTest();
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
            fail("Failed overflow test 2 - expected "
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

        expectedMac = Hex.decode("0e38a343a0f0b6727369943b9ae9ab7c199521413457a10735caeb47f76cd681");
        mac = new byte[macBitSize / 8];

        dstu7564mac = new DSTU7564Mac(macBitSize);

        dstu7564mac.init(new KeyParameter(key));
        dstu7564mac.update(input, 0, input.length);
        dstu7564mac.doFinal(mac, 0);

        if (!Arrays.areEqual(expectedMac, mac))
        {
            fail("Failed overflow test 3 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        DSTU7564Digest digest = new DSTU7564Digest(macBitSize);
        byte[] expectedDigest = Hex.decode("97e84ee3b7ca2e9b0148878e88da09152952de7dd66e45d1b50ec4640932f527");
        byte[] digestBuf = new byte[macBitSize / 8];

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 4 - expected "
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
            fail("Failed overflow test 5 - expected "
                + Hex.toHexString(expectedDigest)
                + " got " + Hex.toHexString(digestBuf));
        }

        input = new byte[52];
        for (int i = 0; i != input.length; i++)
        {
            input[i] = (byte)(i & 0xff);
        }

        expectedDigest = Hex.decode("2d60e14ead298848031a3321ebf9e8e5263228c498e2d8ba8a857d4979aca4b3");

        digest.update(input, 0, input.length);
        digest.doFinal(digestBuf, 0);

        if (!Arrays.areEqual(expectedDigest, digestBuf))
        {
            fail("Failed overflow test 6 - expected "
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
