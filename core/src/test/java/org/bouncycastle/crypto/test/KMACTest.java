package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * KMAC test vectors from:
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
 */
public class KMACTest
    extends SimpleTest
{
    public String getName()
    {
        return "KMAC";
    }

    public void performTest()
        throws Exception
    {
        KMAC kmac = new KMAC(128, Strings.toByteArray(""));

        isEquals("KMAC128", kmac.getAlgorithmName());

        kmac.init(new KeyParameter(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

        kmac.update(Hex.decode("00010203"), 0, 4);

        byte[] res = new byte[32];

        kmac.doFinal(res, 0, res.length);

        isTrue("oops: " + Hex.toHexString(res), Arrays.areEqual(Hex.decode("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"), res));

        kmac = new KMAC(128, Strings.toByteArray("My Tagged Application"));

        kmac.init(new KeyParameter(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

        kmac.update(Hex.decode("00010203"), 0, 4);

        res = new byte[32];

        kmac.doFinal(res, 0, res.length);

        isTrue("oops: " + Hex.toHexString(res), Arrays.areEqual(Hex.decode("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"), res));

        kmac = new KMAC(128, Strings.toByteArray("My Tagged Application"));

        kmac.init(new KeyParameter(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

        byte[] data = Hex.decode(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1" +
                "F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3" +
                "E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5" +
                "D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7" +
                "C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9" +
                "B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9B" +
                "ABBBCBDBEBFC0C1C2C3C4C5C6C7");
        kmac.update(data, 0, data.length);

        res = new byte[32];

        kmac.doFinal(res, 0, res.length);

        isTrue("oops:" + Hex.toHexString(res), Arrays.areEqual(Hex.decode("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"), res));

        kmac = new KMAC(256, Strings.toByteArray("My Tagged Application"));

        isEquals("KMAC256", kmac.getAlgorithmName());

        kmac.init(new KeyParameter(Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

        data = Hex.decode("00 01 02 03");
        kmac.update(data, 0, data.length);

        res = new byte[64];

        kmac.doFinal(res, 0, res.length);

        isTrue("oops:" + Hex.toHexString(res), Arrays.areEqual(Hex.decode("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"), res));

        kmac = new KMAC(256, Strings.toByteArray(""));

        kmac.init(new KeyParameter(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

        data = Hex.decode(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1" +
                "F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3" +
                "E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5" +
                "D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7" +
                "C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9" +
                "B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9B" +
                "ABBBCBDBEBFC0C1C2C3C4C5C6C7");
        kmac.update(data, 0, data.length);

        res = new byte[64];

        kmac.doFinal(res, 0, res.length);

        isTrue("oops:" + Hex.toHexString(res), Arrays.areEqual(Hex.decode("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"), res));

        kmac = new KMAC(256, Strings.toByteArray("My Tagged Application"));

        kmac.init(new KeyParameter(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

        data = Hex.decode(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1" +
                "F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3" +
                "E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5" +
                "D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7" +
                "C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9" +
                "B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9B" +
                "ABBBCBDBEBFC0C1C2C3C4C5C6C7");
        kmac.update(data, 0, data.length);

        res = new byte[64];

        kmac.doFinal(res, 0, res.length);

        isTrue("oops:" + Hex.toHexString(res), Arrays.areEqual(Hex.decode("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"), res));

        doFinalTest();
        longBlockTest();
        paddingCheckTest();

        checkKMAC(128, new KMAC(128, new byte[0]), Hex.decode("eeaabeef"));
        checkKMAC(256, new KMAC(256, null), Hex.decode("eeaabeef"));
        checkKMAC(128, new KMAC(128, new byte[0]), Hex.decode("eeaabeef"));
        checkKMAC(128, new KMAC(128, null), Hex.decode("eeaabeef"));
        checkKMAC(256, new KMAC(256,  null), Hex.decode("eeaabeef"));
    }

    private void doFinalTest()
    {
        KMAC kmac = new KMAC(128, Strings.toByteArray("My Tagged Application"));

        kmac.init(new KeyParameter(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));
        
        kmac.update(Hex.decode("00010203"), 0, 4);

        byte[] res = new byte[32];

        kmac.doOutput(res, 0, res.length);

        isTrue(Hex.toHexString(res), Arrays.areEqual(Hex.decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c"), res));

        kmac.doOutput(res, 0, res.length);

        isTrue(!Arrays.areEqual(Hex.decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c"), res));

        kmac.doFinal(res, 0, res.length);

        kmac.update(Hex.decode("00010203"), 0, 4);

        kmac.doFinal(res, 0, res.length);

        isTrue(Arrays.areEqual(Hex.decode("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"), res));

        kmac.update(Hex.decode("00010203"), 0, 4);

        kmac.doOutput(res, 0, res.length);

        isTrue(Arrays.areEqual(Hex.decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c"), res));

        kmac.doFinal(res, 0, res.length);

        isTrue(Hex.toHexString(res), Arrays.areEqual(Hex.decode("ffcb48c7620ccd67d1c83224186892cef2f2a99278d5cfdde10e48bdc89718c2"), res));
    }

    private void longBlockTest()
    {
        byte[] data = new byte[16000];
        byte[] res = new byte[64];

        for (int i = 0; i != data.length; i++)
        {
            data[i] = (byte)i;
        }

        for (int i = 10000; i != data.length; i++)
        {
            KMAC kmac = new KMAC(128, Arrays.copyOfRange(data, 0, i));

            kmac.init(new KeyParameter(new byte[0]));

            kmac.update(Hex.decode("00010203"), 0, 4);

            kmac.doFinal(res, 0);
        }

        KMAC kmac = new KMAC(256, new byte[200]);

        kmac.init(new KeyParameter(new byte[0]));

        kmac.update(Arrays.copyOfRange(data, 0, 200), 0, 200);

        kmac.doFinal(res, 0);

        isTrue(Hex.toHexString(res), Arrays.areEqual(Hex.decode("f9476d9b3e42bf23307af5ccb5287fd6f033b23c400566a2ebc5829bd119aa545cd9b6bde76ef61cd31c3c0f0aaf0945f44481e863b19e9c26fb46c8b2a8a9bb"), res));
    }

    private void paddingCheckTest()
    {
        byte[] data = Hex.decode("01880204187B3E43EDA8D51EC181D37DDE5B17ECCDD8BE84C268DC6C9500700857");
        byte[] out = new byte[32];

        KMAC k128 = new KMAC(128, new byte[0]);
        k128.init(new KeyParameter(new byte[163]));
        k128.update(data, 0, data.length);
        k128.doOutput(out, 0, out.length);

        isTrue("128 failed", Arrays.areEqual(out, Hex.decode("6e6ab56468c7445f81c679f89f45c90a95a9c01afbaab5f7065b7e2e96f7d2bb")));

        KMAC k256 = new KMAC(256, new byte[0]);
        k256.init(new KeyParameter(new byte[131]));
        k256.update(data, 0, data.length);
        k256.doOutput(out, 0, out.length);

        isTrue("256 failed", Arrays.areEqual(out, Hex.decode("f6302d4f854b4872e811b37993b6bfe027258089b6a9fbb26a755b1ebfc0d830")));
    }

    private void checkKMAC(int bitSize, KMAC kmac, byte[] msg)
    {
        KMAC ref = new KMAC(bitSize, null);

        ref.init(new KeyParameter(new byte[0]));
        kmac.init(new KeyParameter(new byte[0]));
        
        ref.update(msg, 0, msg.length);
        kmac.update(msg, 0, msg.length);

        byte[] res1 = new byte[32];
        byte[] res2 = new byte[32];

        ref.doFinal(res1, 0, res1.length);
        kmac.doFinal(res2, 0, res2.length);

        isTrue(Arrays.areEqual(res1, res2));
    }

    public static void main(
        String[] args)
    {
        runTest(new KMACTest());
    }
}
