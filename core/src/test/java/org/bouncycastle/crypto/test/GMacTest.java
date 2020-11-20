package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors for AES-GMAC, extracted from <a
 * href="https://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip">NIST CAVP GCM test
 * vectors</a>.
 *
 */
public class GMacTest extends SimpleTest
{
    private static class TestCase
    {
        private byte[] key;
        private byte[] iv;
        private byte[] ad;
        private byte[] tag;
        private String name;

        private TestCase(final String name, final String key, final String iv, final String ad, final String tag)
        {
            this.name = name;
            this.key = Hex.decode(key);
            this.iv = Hex.decode(iv);
            this.ad = Hex.decode(ad);
            this.tag = Hex.decode(tag);
        }

        public String getName()
        {
            return name;
        }

        public byte[] getKey()
        {
            return key;
        }

        public byte[] getIv()
        {
            return iv;
        }

        public byte[] getAd()
        {
            return ad;
        }

        public byte[] getTag()
        {
            return tag;
        }
    }

    private static TestCase[] TEST_VECTORS = new TestCase[] {
            // Count = 0, from each of the PTlen = 0 test vector sequences
            new TestCase("128/96/0/128", "11754cd72aec309bf52f7687212e8957", "3c819d9a9bed087615030b65", "",
                    "250327c674aaf477aef2675748cf6971"),
            new TestCase("128/96/0/120", "272f16edb81a7abbea887357a58c1917", "794ec588176c703d3d2a7a07", "",
                    "b6e6f197168f5049aeda32dafbdaeb"),
            new TestCase("128/96/0/112", "81b6844aab6a568c4556a2eb7eae752f", "ce600f59618315a6829bef4d", "",
                    "89b43e9dbc1b4f597dbbc7655bb5"),
            new TestCase("128/96/0/104", "cde2f9a9b1a004165ef9dc981f18651b", "29512c29566c7322e1e33e8e", "",
                    "2e58ce7dabd107c82759c66a75"),
            new TestCase("128/96/0/96", "b01e45cc3088aaba9fa43d81d481823f", "5a2c4a66468713456a4bd5e1", "",
                    "014280f944f53c681164b2ff"),

            new TestCase("128/96/128/128", "77be63708971c4e240d1cb79e8d77feb", "e0e00f19fed7ba0136a797f3",
                    "7a43ec1d9c0a5a78a0b16533a6213cab", "209fcc8d3675ed938e9c7166709dd946"),
            new TestCase("128/96/128/96", "bea48ae4980d27f357611014d4486625", "32bddb5c3aa998a08556454c",
                    "8a50b0b8c7654bced884f7f3afda2ead", "8e0f6d8bf05ffebe6f500eb1"),

            new TestCase("128/96/384/128", "99e3e8793e686e571d8285c564f75e2b", "c2dd0ab868da6aa8ad9c0d23",
                    "b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c5917ee476541809ac6867a8c399309fc",
                    "3f4fba100eaf1f34b0baadaae9995d85"),
            new TestCase("128/96/384/96", "c77acd1b0918e87053cb3e51651e7013", "39ff857a81745d10f718ac00",
                    "407992f82ea23b56875d9a3cb843ceb83fd27cb954f7c5534d58539fe96fb534502a1b38ea4fac134db0a42de4be1137",
                    "2a5dc173285375dc82835876"),

            new TestCase(
                    "128/1024/0/128",
                    "d0f1f4defa1e8c08b4b26d576392027c",
                    "42b4f01eb9f5a1ea5b1eb73b0fb0baed54f387ecaa0393c7d7dffc6af50146ecc021abf7eb9038d4303d91f8d741a11743166c0860208bcc02c6258fd9511a2fa626f96d60b72fcff773af4e88e7a923506e4916ecbd814651e9f445adef4ad6a6b6c7290cc13b956130eef5b837c939fcac0cbbcc9656cd75b13823ee5acdac",
                    "", "7ab49b57ddf5f62c427950111c5c4f0d"),
            new TestCase(
                    "128/1024/384/96",
                    "3cce72d37933394a8cac8a82deada8f0",
                    "aa2f0d676d705d9733c434e481972d4888129cf7ea55c66511b9c0d25a92a174b1e28aa072f27d4de82302828955aadcb817c4907361869bd657b45ff4a6f323871987fcf9413b0702d46667380cd493ed24331a28b9ce5bbfa82d3a6e7679fcce81254ba64abcad14fd18b22c560a9d2c1cd1d3c42dac44c683edf92aced894",
                    "5686b458e9c176f4de8428d9ebd8e12f569d1c7595cf49a4b0654ab194409f86c0dd3fdb8eb18033bb4338c70f0b97d1",
                    "a3a9444b21f330c3df64c8b6"), };

    public void performTest()
    {
        for (int i = 0; i < TEST_VECTORS.length; i++)
        {
            TestCase testCase = TEST_VECTORS[i];

            Mac mac = new GMac(new GCMBlockCipher(new AESEngine()), testCase.getTag().length * 8);
            CipherParameters key = new KeyParameter(testCase.getKey());
            mac.init(new ParametersWithIV(key, testCase.getIv()));

            testSingleByte(mac, testCase);

            mac = new GMac(new GCMBlockCipher(new AESEngine()), testCase.getTag().length * 8);
            mac.init(new ParametersWithIV(key, testCase.getIv()));
            testMultibyte(mac, testCase);
        }

        // Invalid mac size
        testInvalidMacSize(97);
        testInvalidMacSize(136);
        testInvalidMacSize(24);
    }

    private void testInvalidMacSize(int size)
    {
        try
        {
            GMac mac = new GMac(new GCMBlockCipher(new AESEngine()), size);
            mac.init(new ParametersWithIV(null, new byte[16]));
            fail("Expected failure for illegal mac size " + size);
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().startsWith("Invalid value for MAC size"))
            {
                fail("Illegal mac size failed with unexpected message");
            }
        }
    }

    private void testMultibyte(Mac mac, TestCase testCase)
    {
        mac.update(testCase.getAd(), 0, testCase.getAd().length);
        checkMac(mac, testCase);
    }

    private void testSingleByte(Mac mac, TestCase testCase)
    {
        final byte[] ad = testCase.getAd();
        for (int i = 0; i < ad.length; i++)
        {
            mac.update(ad[i]);
        }
        checkMac(mac, testCase);
    }

    private void checkMac(Mac mac, TestCase testCase)
    {
        final byte[] generatedMac = new byte[mac.getMacSize()];
        mac.doFinal(generatedMac, 0);
        if (!areEqual(testCase.getTag(), generatedMac))
        {
            fail("Failed " + testCase.getName() + " - expected " + new String(Hex.encode(testCase.getTag())) + " got "
                + new String(Hex.encode(generatedMac)));
        }
    }

    public String getName()
    {
        return "GMac";
    }

    public static void main(String[] args)
    {
        runTest(new GMacTest());
    }
}
