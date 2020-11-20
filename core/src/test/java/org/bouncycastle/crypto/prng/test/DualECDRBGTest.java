package org.bouncycastle.crypto.prng.test;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.drbg.DualECSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Dual EC SP800-90 DRBG test
 */
public class DualECDRBGTest
    extends SimpleTest
{
    public String getName()
    {
        return "DualECDRBG";
    }

    public static void main(String[] args)
    {
        runTest(new DualECDRBGTest());
    }

    private DRBGTestVector[] createTestVectorData()
    {
        return new DRBGTestVector[]
            {
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    false,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "FF5163C388F791E96F1052D5C8F0BD6FBF7144839C4890FF85487C5C12702E4C9849AF518AE68DEB14D3A62702BBDE4B98AB211765FD87ACA12FC2A6",
                            "9A0A11F2DFB88F7260559DD8DA6134EB2B34CC0415FA8FD0474DB6B85E1A08385F41B435DF81296B1B4EDF66E0107C0844E3D28A89B05046B89177F2"
                        }),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    false,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "C08E954FCD486D0B0934A0236692AC705A835D1A3C94D2ACD4684AB26E978D7D42E73CC06D6EC1472C63E51BED7F71518395836E2052BBD73A20CABB",
                            "1D76DEE36FCC5F9478C112EAFA1C4CCD0635435A6F3A247A3BA3849790B5245070E95C1A67BE7A39BFB213F2C0EFCC171A3253DA6D54DA4362EA2099"
                        })
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    false,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "3AB095CC493A8730D70DE923108B2E4710799044FFC27D0A1156250DDF97E8B05ACE055E49F3E3F5B928CCD18317A3E68FCB0B6F0459ADF9ECF79C87",
                            "7B902FC35B0AF50F57F8822936D08A96E41B16967C6B1AA0BC05032F0D53919DC587B664C883E2FE8F3948002FCD8BCBFC4706BCAA2075EF6BF41167"
                        })
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F"),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    false,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "3B68A1D95ED0312150AC1991189780F37EC50E75249F915CD806BBA0C44F9E3A919B2390805E1E90C1D2D1C823B17B96DB44535B72E0CFB62723529D",
                            "250B933475E3BD4FC85D97FD797834B599DEDEDF8B6F15474E1F31B4AF215CFA7A8C0A0296A2E374B3886BB0CC7E49DBB19324564B451E64F12864F9"
                        })
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    true,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "8C77288EDBEA9A742464F78D55E33593C1BF5F9D8CD8609D6D53BAC4E4B42252A227A99BAD0F2358B05955CD35723B549401C71C9C1F32F8A2018E24",
                            "56ECA61C64F69C1C232E992623C71418BD0B96D783118FAAD94A09E3A9DB74D15E805BA7F14625995CA77612B2EF7A05863699ECBABF70D3D422C014"
                        }),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    true,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "A5C397DFEB540E86F0470E9625D5C5AC2D50016FB201E8DF574F2201DFBB42A799FEB9E238AAD301A493382250EEE60D2E2927E500E848E57535ABD1",
                            "BF9894630BEBAF0A0EDFE726285EB055FD2ED678B76673803DD327F49DBEDE87D3E447A6EB73B5D5C52A40078132677F412E9E7DE32B9B1CB32421B9"
                        })
                    .addAdditionalInput("606162636465666768696A6B6C6D6E6F")
                    .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"),
                new DRBGTestVector(
                    new SHA384Digest(),
                    new SHA384EntropyProvider().get(192),
                    false,
                    "202122232425262728292A2B",
                    192,
                    new String[]
                        {
                            "1F858858B65357D6360E1ED8F8475767B08DAB30718CCA01C6FAE77A4BDCE2702C76D0FB4758EA1ED6AA587CFD26B9011DC8A75D0B4154193BB2C1798FFA52BCAB208310" +
                            "3CD2AAD44BEED56D042FC2B8915D7D9BED6437EFEB1582EE",
                            "6E4AAB63938212C870F24BB067A32CA9E7FC2343" +
                            "5D411729268C8BA6F90E87074D04888CE2CC5A916B7AC93F" +
                            "EDE85E2995645DFCC4CE44B9FB41F1BFCC5E9F59EE3A8E1B" +
                            "8F85247F741B7C480521EE6BF8BA319B59048E65F08FAA76"
                        }),
                new DRBGTestVector(
                    new SHA384Digest(),
                    new SHA384EntropyProvider().get(192),
                    false,
                    "202122232425262728292A2B",
                    192,
                    new String[]
                        {
                            "E6A30AB0C9AFCBA673E4F1C94B3DB1F0C7D78B3D" +
                            "87B967281BE1E7B3CAF5200AED502C26B84FC169FE8336BD" +
                            "23271CB299812F2CF1955AA63FC362044ABA246EF1610F9E" +
                            "DC613924A84A00F8DB3FC65C13373F3171EB20848FA9A70E",
                            "8585764DF1C86EA12ACCB882525BF6217B447486" +
                            "5EBFDA367B8657FA80471139BAC626172B9F219DF2CE9099" +
                            "F65833E07CD1A8DD80468779EA3C26620A2C9C9F5C7EFCDD" +
                            "C036E6F6C8BF70316D3C37FC246A4CC79B3F1DB971D72ED0"
                        })
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F5051525354555657"),
                new DRBGTestVector(
                    new SHA384Digest(),
                    new SHA384EntropyProvider().get(192),
                    false,
                    "202122232425262728292A2B",
                    192,
                    new String[]
                        {
                            "13F6EA9BBA7BABDC2A52A3B9FD73D65ECAA638A0" +
                            "4C74BCCA2ACDE6FD29FEA4B5D884E095E87D1B7C0DEB9D37" +
                            "7AD81FBFEEA2D5EF82C0F6F52B9FCC359E769AC9DF2A876C" +
                            "58BAF21657814F3E66D1680B1D4EBD65581E42534F85197D",
                            "FC0A36F4D20F8F83BE3430AA3C36A49191821A82" +
                            "072BBC3D5AFF8D7EC39484D646277CE87599B6FE8CCA9862" +
                            "559703A10F4DE1066BFD30B80C325E774B512525BC6D3734" +
                            "4C93906368243D31F89E99C4D2A6E9BEB24D5F7267360DCA"
                        })
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F5051525354555657")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F7071727374757677")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7"),
                new DRBGTestVector(
                    new SHA384Digest(),
                    new SHA384EntropyProvider().get(192),
                    true,
                    "202122232425262728292A2B",
                    192,
                    new String[]
                        {
                            "FE55601BF734493013705CCEB76E44AAD48373F7" +
                            "42E72B83D4701FA6549255F1CDE6217953522FF973BA4F6E" +
                            "C96D2BDCF14A76BE7DEB61781E34B99335BD714F17C91739" +
                            "B4E2AB57E36E9C3116E215D3D94FCFAD532636874875CAC7",
                            "F5E59D0ABADE81F62FFAB9D4A6A26FF200016608" +
                            "A7215E389858FFED83FBC75CFD33DBA6688C89AA32AD22E4" +
                            "80EA3D04EADFB35567B67564207E64B77844E8E4A87502D5" +
                            "02DBBB6D8277F1CACDB7CF8D293D09DB7DD59A950821507A"
                        })
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F7071727374757677")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7"),
                new DRBGTestVector(
                    new SHA384Digest(),
                    new SHA384EntropyProvider().get(192),
                    true,
                    "202122232425262728292A2B",
                    192,
                    new String[]
                        {
                            "CC788F70FB08F256D9604333630D85936D400F45" +
                            "718DC3F939A8B9F6F75D3E4EC17D68FBB924AEACB7021295" +
                            "48FA63CE9BCB82176639B64DE890A47025B5582312FE934E" +
                            "F0D0A12697C0F05D2DA108CCADB511BA0EB62F4051BB2354",
                            "2C922EA620D76E4137B315EBC29E518F80951B3F" +
                            "0E6173FA2BFD94A230EE513EE2E4EB330D802F620DD24911" +
                            "534EC0F95A1F1D44A2125F5D57476A666FC372092B55D0D6" +
                            "8B49738F5BC466EC206AB3CF6A972B38BCFAE5FCD53C7E21 "
                        }),
                new DRBGTestVector(
                    new SHA512Digest(),
                    new SHA512EntropyProvider().get(256),
                    false,
                    "202122232425262728292A2B2C2D2E2F",
                    256,
                    new String[]
                        {
                            "7A8313798EE1" +
                            "D1898712683F2D0B0DEE5804146ABA64FDA8DB4E539CC8D1" +
                            "E59C74EE5AA48E73E958C8EC85DD529D42E68B4F7E02FFAF" +
                            "3E3EF8312AEA68BC08A414885E60A7DF0B55F9D90210B319" +
                            "E9B8FD23E078A4153636F29AA3CAC8198CB1D5D846151653" +
                            "ECE275A591089261238014E5058410065AB8229EB9115E8E",
                            "918B5D79E646" +
                            "64966D954BC5E2946BF48F061BF0C2701C3C2D1F75EA821E" +
                            "1DA05D5B3C2C4EEA246E806B53BF6BDB3F3D53A3AE756C2A" +
                            "45C72603973A3DE1BC367C283CA124A5589CEAB30E5D2D74" +
                            "8A40DD874FF15B032CF4F4B2AAD590B0DB91A0D38FCE93C5" +
                            "AAD4E55AC482F86FF06FAE66B7C7CCA7E45557E1A5A3B85D"
                        }),
                new DRBGTestVector(
                    new SHA512Digest(),
                    new SHA512EntropyProvider().get(256),
                    true,
                    "202122232425262728292A2B2C2D2E2F",
                    256,
                    new String[]
                        {
                            "C7ED88A2C690" +
                            "1C04802BA2BB04262921B19664835A4A3C002CB9F13E35E3" +
                            "DEB3698A436BF1C85B070E9E6977CA78A5130905AA0C01A9" +
                            "4130F5133DF904A4ACF59A7DD01227E8FCA1C8D51F093839" +
                            "46ECD950113104760D7E216CAF581FE9D3AACE6FC4CDDC4C" +
                            "CD736D26A60BE8BE2A6A78CD752D1EC7CCC802638B177307",
                            "83B78B206785" +
                            "4412EEB24AEA86064D510C68FD96DBF94EAC1BC2022752D7" +
                            "558AEB9F97B9CBC1B9648FE4D88E2C82A6F530675E1DB92D" +
                            "396D6D85BDAD2A23CBD10AD808ECCCFBFC811EB68AE835E4" +
                            "912E011DD10A4399C8DE2D9D88F81B6168B05D282B9DAC1E" +
                            "65E0A45F61043E1FA047870DD582295E6C50DD1185B13594 "
                        })
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"),
                new DRBGTestVector(
                    new SHA512Digest(),
                    new SHA512EntropyProvider().get(256),
                    true,
                    "202122232425262728292A2B2C2D2E2F",
                    256,
                    new String[]
                        {
                            "CC7035C73040" +
                            "5CF5DF7137ED9E10744B75B540AFFC68EB564B71C0F737E8" +
                            "F656B6171940497FA90D8F383EFB6FC6717BA14AAA164EF5" +
                            "6641C0F513312551DCD21D0A5B0DBDCD97F627E968DFD752" +
                            "56C11CF2BCCA5822EAACE796A34CB7D2F8CD8CC6DBE76274" +
                            "498289BBC4C2F1CADA6185D82605CF992EC285BC4945EE9E",
                            "0E6C329AD1BE" +
                            "681EB1E6F5E03A89E3D80153D6CCDD5A3ECF865003EE4A2D" +
                            "E5A23B7F43681361CFAFC3A3FEF17777E75CF9D6685573C8" +
                            "87A3962CB955076D45D6F1E45EE4B8CB31A4731CDA031FA2" +
                            "815B6D34E29F2603526CE186576F4CCA3FEDF7F8ACDB37C9" +
                            "9D762706ABE4967D44739C8CFCFCC76C58B1ED243AC394C0"
                        }),
                // From https://csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors.zip
                // modified to test partial block processing.
                new DRBGTestVector(
                    new SHA256Digest(),
                    new TestEntropySourceProvider(Hex.decode("a826f1cd3fa24b9e71c316e5bf2bafff"), false).get(128),
                    false,
                    "82bc3bf050614b34",
                    128,
                    new String[]
                        {
                            "14949b876e30f832331f59f2e687350bea9ba22b78549521a70748ca916c74ebff0b638266aa" +
                            "d81e089545eb60bfe332f7d134d91ed3c104f975fae0f71391add71e3380a725251ed5552a84" +
                            "650637eddfc88b5ab26311277cbc429aa152b2cfac61c67846512d7564114177a622f25e870a" +
                            "acec37c0977d",
                            "7050bf74a887809673ecd295071f7a457d1e2e227f68ef4b4445e34f3904b95d4833180ee522" +
                            "104bfc996234063e2c76173937b883c66b0e64a56643877228cad5212cddbf839270ef80889b" +
                            "c83424c141c2419f2231004c8860f8fd95435e2c9f8ac7409fcbfb6a74851fadc7d99bf5d68b" +
                            "591892f0e3a1"
                        }),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new TestEntropySourceProvider(Hex.decode("a826f1cd3fa24b9e71c316e5bf2bafff"), false).get(128),
                    false,
                    "82bc3bf050614b34",
                    128,
                    new String[]
                        {
                            "14949b876e30f832331f59f2e687350bea9ba22b78549521a70748ca916c74ebff0b638266aa" +
                            "d81e089545eb60bfe332f7d134d91ed3c104f975fae0f71391add71e3380a725251ed5552a84" +
                            "650637eddfc88b5ab26311277cbc429aa152b2cfac61c67846512d7564114177a622f25e870a" +
                            "acec37c0977d",
                            "7050bf74a887809673ecd295071f7a457d1e2e227f68ef4b4445e34f3904b95d4833180ee522" +
                            "104bfc996234063e2c76173937b883c66b0e64a56643877228cad5212cddbf839270ef80889b" +
                            "c83424c141c2419f2231004c8860f8fd95435e2c9f8ac7409fcbfb6a74851fadc7d99bf5d68b" +
                            "591892f0e3"
                        })
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

            SP80090DRBG d = new DualECSP800DRBG(tv.getDigest(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

            byte[] output = new byte[tv.expectedValue(0).length];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = tv.expectedValue(0);

            if (!areEqual(expected, output))
            {
                fail("Test #" + (i + 1) + ".1 failed, expected " + new String(Hex.encode(tv.expectedValue(0))) + " got " + new String(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue(1).length];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = tv.expectedValue(1);
            if (!areEqual(expected, output))
            {
                fail("Test #" + (i + 1) + ".2 failed, expected " + new String(Hex.encode(tv.expectedValue(1))) + " got " + new String(Hex.encode(output)));
            }
        }

        // Exception tests
        //
        SP80090DRBG d;

        try
        {
            d = new DualECSP800DRBG(new SHA256Digest(), 256, new SHA256EntropyProvider().get(128), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("EntropySource must provide between 256 and 4096 bits"))
            {
                fail("Wrong exception", e);
            }
        }

        try
        {
            d = new DualECSP800DRBG(new SHA256Digest(), 256, new SHA256EntropyProvider().get(1 << (13 - 1) + 1), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("EntropySource must provide between 256 and 4096 bits"))
            {
                fail("Wrong exception", e);
            }
        }

        try
        {
            d = new DualECSP800DRBG(new SHA1Digest(), 256, new SHA256EntropyProvider().get(256), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("Requested security strength is not supported by digest"))
            {
                fail("Wrong exception", e);
            }
        }
    }

    private class SHA256EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA256EntropyProvider()
        {
            super(Hex.decode(
                "000102030405060708090A0B0C0D0E0F " +
                    "808182838485868788898A8B8C8D8E8F" +
                    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"), true);
        }
    }

    private class SHA384EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA384EntropyProvider()
        {
            super(Hex.decode(
                "000102030405060708090A0B0C0D0E0F1011121314151617" +
                "808182838485868788898A8B8C8D8E8F9091929394959697" +
                "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7"), true);
        }
    }

    private class SHA512EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA512EntropyProvider()
        {
            super(Hex.decode(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F" +
                "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"), true);
        }
    }
}
