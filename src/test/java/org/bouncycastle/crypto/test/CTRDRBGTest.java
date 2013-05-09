package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.prng.CTRSP800DRBG;
import org.bouncycastle.crypto.prng.SP80090DRBG;
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
                                    "760BED7D92B083B10AF31CF0656081EB",
                                    "FD1AC41482384D823CF3FD6F0E6C88B3"
                                }
                        )
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"),
                new DRBGTestVector(
                            new AESFastEngine(), 192,
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
                            new AESFastEngine(), 256,
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

            SP80090DRBG d = new CTRSP800DRBG(tv.getCipher(), tv.getKeySizeInBits(), tv.entropySource(), nonce, personalisationString, tv.securityStrength());

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
}
