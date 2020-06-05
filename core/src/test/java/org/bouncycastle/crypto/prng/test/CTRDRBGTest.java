package org.bouncycastle.crypto.prng.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.drbg.CTRSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * CTR DRBG Test
 */
public class CTRDRBGTest
    extends SimpleTest
{
    public String getName()
    {
        return "CTRDRBGTest";
    }

    public static void main(String[] args)
    {
        runTest(new CTRDRBGTest());
    }
    
    private DRBGTestVector[] createTestVectorData()
    {
        return new DRBGTestVector[]
            {
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            false,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "ABC88224514D0316EA3D48AEE3C9A2B4",
                                    "D3D3F372E43E7ABDC4FA293743EED076"
                                }
                        ),
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            false,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "D4564EE072ACA5BD279536E14F94CB12",
                                    "1CCD9AFEF15A9679BA75E35225585DEA"
                                }
                        )
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBC"),
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            false,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "760BED7D92B083B10AF31CF0656081EB",
                                    "FD1AC41482384D823CF3FD6F0E6C88B3"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"),
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            false,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "7A4C1D7ADC8A67FDB50100ED23583A2C",
                                    "43044D311C0E07541CA5C8B0916976B2"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBC"),
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            true,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "8FB78ABCA75C9F284E974E36141866BC",
                                    "9D9745FF31C42A4488CBB771B13B5D86"
                                }
                        ),
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            true,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "0E389920A09B485AA4ABD0CA7E60D89C",
                                    "F4478EC6659A0D3577625B0C73A211DD"
                                }
                        )
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBC"),
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            true,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "64983055D014550B39DE699E43130B64",
                                    "035FDDA8582A2214EC722C410A8D95D3"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"),
                new DRBGTestVector(
                            new DESedeEngine(), 168,
                            new Bit232EntropyProvider().get(232),
                            true,
                            "20212223242526",
                            112,
                            new String[]
                                {
                                    "A29C1A8C42FBC562D7D1DBA7DC541FFE",
                                    "0BDA66B049429061C013E4228C2F44C6"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBC"),
                new DRBGTestVector(
                            new AESEngine(), 128,
                            new Bit256EntropyProvider().get(256),
                            false,
                            "2021222324252627",
                            128,
                            new String[]
                                {
                                    "8CF59C8CF6888B96EB1C1E3E79D82387AF08A9E5FF75E23F1FBCD4559B6B997E",
                                    "69CDEF912C692D61B1DA4C05146B52EB7B8849BD87937835328254EC25A9180E"
                                }
                        ),
                new DRBGTestVector(
                            new AESEngine(), 128,
                            new Bit256EntropyProvider().get(256),
                            false,
                            "2021222324252627",
                            128,
                            new String[]
                                {
                                    "E8C74A4B7BFFB53BEB80E78CA86BB6DF70E2032AEB473E0DD54D2339CEFCE9D0",
                                    "26B3F823B4DBAFC23B141375E10B3AEB7A0B5DEF1C7D760B6F827D01ECD17AC7"
                                }
                        )
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"),
                new DRBGTestVector(
                           new AESEngine(), 128,
                           new Bit256EntropyProvider().get(256),
                           false,
                           "2021222324252627",
                           128,
                           new String[]
                               {
                                   "18FDEFBDC43D7A36D5D6D862205765D1D701C9F237007030DF1B8E70EE4EEE29",
                                   "9888F1D38BB1CCE31B363AA1BD9B39616876C30DEE1FF0B7BD8C4C441715C833"
                               }
                       )
               .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"),
                new DRBGTestVector(
                            new AESEngine(), 128,
                            new Bit256EntropyProvider().get(256),
                            true,
                            "2021222324252627",
                            128,
                            new String[]
                                {
                                    "BFF4B85D68C84529F24F69F9ACF1756E29BA648DDEB825C225FA32BA490EF4A9",
                                    "9BD2635137A52AF7D0FCBEFEFB97EA93A0F4C438BD98956C0DACB04F15EE25B3"
                                }
                        ),
                new DRBGTestVector(
                            new AESEngine(), 128,
                            new Bit256EntropyProvider().get(256),
                            true,
                            "2021222324252627",
                            128,
                            new String[]
                                {
                                    "4573AC8BBB33D7CC4DBEF3EEDF6EAE748B536C3A1082CEE4948CDB51C83A7F9C",
                                    "99C628CDD87BD8C2F1FE443AA7F761DA16886436326323354DA6311FFF5BC678"
                                }
                        )
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"),
                new DRBGTestVector(
                           new AESEngine(), 128,
                           new Bit256EntropyProvider().get(256),
                           true,
                           "2021222324252627",
                           128,
                           new String[]
                               {
                                   "F324104E2FA14F79D8AA60DF06B93B3BC157324958F0A7EE1E193677A70E0250",
                                   "78F4C840134F40DC001BFAD3A90B5EF4DEBDBFAC3CFDF0CD69A89DC4FD34713F"
                               }
                       )
               .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"),
                new DRBGTestVector(
                            new AESEngine(), 192,
                            new Bit320EntropyProvider().get(320),
                            false,
                            "202122232425262728292A2B",
                            192,
                            new String[]
                                {
                                    "E231244B3235B085C81604424357E85201E3828B5C45568679A5555F867AAC8C",
                                    "DDD0F7BCCADADAA31A67652259CE569A271DD85CF66C3D6A7E9FAED61F38D219"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F6061626364656667"),
                new DRBGTestVector(
                        new AESEngine(), 192,
                        new Bit320EntropyProvider().get(320),
                        true,
                        "202122232425262728292A2B",
                        192,
                        new String[]
                            {
                                "F780D4A2C25CF8EE7407D948EC0B724A4235D8B20E65081392755CA7912AD7C0",
                                "BA14617F915BA964CB79276BDADC840C14B631BBD1A59097054FA6DFF863B238"
                            }
                    )
            .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F6061626364656667"),
                new DRBGTestVector(
                            new AESEngine(), 256,
                            new Bit384EntropyProvider().get(384),
                            false,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                                {
                                    "47111E146562E9AA2FB2A1B095D37A8165AF8FC7CA611D632BE7D4C145C83900",
                                    "98A28E3B1BA363C9DAF0F6887A1CF52B833D3354D77A7C10837DD63DD2E645F8"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
                new DRBGTestVector(
                            new AESEngine(), 256,
                            new Bit384EntropyProvider().get(384),
                            true,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                                {
                                    "71BB3F9C9CEAF4E6C92A83EB4C7225010EE150AC75E23F5F77AD5073EF24D88A",
                                    "386DEBBBF091BBF0502957B0329938FB836B82E594A2F5FDD5EB28D4E35528F4"
                                }
                        )
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
                new DRBGTestVector(
                            new AESEngine(), 256,
                            new Bit384EntropyProvider().get(384),
                            true,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                                {
                                    "1A2E3FEE9056E98D375525FDC2B63B95B47CE51FCF594D804BD5A17F2E01139B",
                                    "601F95384F0D85946301D1EACE8F645A825CE38F1E2565B0C0C439448E9CA8AC"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F"),
                new DRBGTestVector(
                            new AESEngine(), 256,
                            new Bit384EntropyProvider().get(384),
                            true,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                                {
                                    "EAE6BCE781807E524D26605EA198077932D01EEB445B9AC6C5D99C101D29F46E",
                                    "738E99C95AF59519AAD37FF3D5180986ADEBAB6E95836725097E50A8D1D0BD28"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
                new DRBGTestVector(
                            new AESEngine(), 256,
                            new Bit384EntropyProvider().get(384),
                            true,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                                {
                                    "eae6bce781807e524d26605ea198077932d01eeb445b9ac6c5d99c101d29f46e30b27377",
                                    "ec51b55b49904c3ff9e13939f1cf27398993e1b3acb2b0be0be8761261428f0aa8ba2657"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
            };
    }

    public void performTest()
        throws Exception
    {
        DRBGTestVector[] tests = createTestVectorData();

        for (int i = 0; i != tests.length; i++)
        {
            DRBGTestVector tv = tests[i];

            byte[] nonce = tv.nonce();
            byte[] personalisationString = tv.personalizationString();

            SP80090DRBG d = new CTRSP800DRBG(tv.getCipher(), tv.keySizeInBits(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!areEqual(expected, output))
            {
                fail("Test #" + (i + 1) + ".1 failed, expected " + new String(Hex.encode(tv.expectedValue(0))) + " got " + new String(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!areEqual(expected, output))
            {
                fail("Test #" + (i + 1) + ".2 failed, expected " + new String(Hex.encode(tv.expectedValue(1))) + " got " + new String(Hex.encode(output)));
            }
        }

        // DESede/TDEA key parity test
        DRBGTestVector tv = tests[0];

        SP80090DRBG drbg = new CTRSP800DRBG(new KeyParityCipher(tv.getCipher()), tv.keySizeInBits(), tv.securityStrength(), tv.entropySource(), tv.personalizationString(), tv.nonce());

        byte[] output = new byte[tv.expectedValue(0).length];

        drbg.generate(output, tv.additionalInput(0), tv.predictionResistance());

        // Exception tests
        SP80090DRBG d;
        try
        {
            d = new CTRSP800DRBG(new AESEngine(), 256, 256, new Bit232EntropyProvider().get(128), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("Not enough entropy for security strength required"))
            {
                fail("Wrong exception", e);
            }
        }

        try
        {
            d = new CTRSP800DRBG(new DESedeEngine(), 256, 256, new Bit232EntropyProvider().get(232), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("Requested security strength is not supported by block cipher and key size"))
            {
                fail("Wrong exception", e);
            }
        }

        try
        {
            d = new CTRSP800DRBG(new DESedeEngine(), 168, 256, new Bit232EntropyProvider().get(232), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("Requested security strength is not supported by block cipher and key size"))
            {
                fail("Wrong exception", e);
            }
        }

        try
        {
            d = new CTRSP800DRBG(new AESEngine(), 192, 256, new Bit232EntropyProvider().get(232), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("Requested security strength is not supported by block cipher and key size"))
            {
                fail("Wrong exception", e);
            }
        }
    }

    private class Bit232EntropyProvider
        extends TestEntropySourceProvider
    {
        Bit232EntropyProvider()
        {
            super(Hex.decode(
               "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C" +
               "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C" +
               "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDC"), true);
        }
    }

    private class Bit256EntropyProvider
        extends TestEntropySourceProvider
    {
        Bit256EntropyProvider()
        {
            super(Hex.decode(
                "0001020304050607"+
                "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"+
                "8081828384858687"+
                "88898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"+
                "C0C1C2C3C4C5C6C7"+
                "C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"), true);
        }
    }

    private class Bit320EntropyProvider
        extends TestEntropySourceProvider
    {
        Bit320EntropyProvider()
        {
            super(Hex.decode(
            "000102030405060708090A0B0C0D0E0F"+
            "101112131415161718191A1B1C1D1E1F2021222324252627"+
            "808182838485868788898A8B8C8D8E8F"+
            "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7"+
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"+
            "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7"), true);
        }
    }

    private class Bit384EntropyProvider
        extends TestEntropySourceProvider
    {
        Bit384EntropyProvider()
        {
            super(Hex.decode(
            "000102030405060708090A0B0C0D0E0F1011121314151617" +
            "18191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F" +
            "808182838485868788898A8B8C8D8E8F9091929394959697" +
            "98999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7" +
            "D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"), true);
        }
    }

    private class KeyParityCipher
        implements BlockCipher
    {
        private BlockCipher cipher;

        KeyParityCipher(BlockCipher cipher)
        {
            this.cipher = cipher;
        }

        public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException
        {
            byte[] k = Arrays.clone(((KeyParameter)params).getKey());

            DESedeParameters.setOddParity(k);

            if (!Arrays.areEqual(((KeyParameter)params).getKey(), k))
            {
                fail("key not odd parity");
            }

            cipher.init(forEncryption, params);
        }

        public String getAlgorithmName()
        {
            return cipher.getAlgorithmName();
        }

        public int getBlockSize()
        {
            return cipher.getBlockSize();
        }

        public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException
        {
            return cipher.processBlock(in, inOff, out, outOff);
        }

        public void reset()
        {
            cipher.reset();
        }
    }

}
