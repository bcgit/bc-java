package org.bouncycastle.crypto.prng.test;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * DRBG Test
 */
public class HashDRBGTest
    extends SimpleTest
{
    public String getName()
    {
        return "HashDRBG";
    }

    public static void main(String[] args)
    {
        runTest(new HashDRBGTest());
    }

    private DRBGTestVector[] createTestVectorData()
    {
        return new DRBGTestVector[]
            {
                new DRBGTestVector(
                            new SHA1Digest(),
                            new SHA1EntropyProvider().get(440),
                            false,
                            "2021222324",
                            80,
                            new String[]
                                {
                                    "9F7CFF1ECA23E750F66326969F11800F12088BA68E441D15D888B3FE12BF66FE057494F4546DE2F1",
                                    "B77AA5C0CD55BBCEED7574AF223AFD988C7EEC8EFF4A94E5E89D26A04F58FA79F5E0D3702D7A9A6A"
                                }
                        ),
                new DRBGTestVector(
                    new SHA1Digest(),
                    new SHA1EntropyProvider().get(440),
                    false,
                    "2021222324",
                    80,
                    new String[]
                        {
                            "AB438BD3B01A0AF85CFEE29F7D7B71621C4908B909124D430E7B406FB1086EA994C582E0D656D989",
                            "29D9098F987E7005314A0F51B3DD2B8122F4AED706735DE6AD5DDBF223177C1E5F3AEBC52FAB90B9"
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576"),
                new DRBGTestVector(
                    new SHA1Digest(),
                    new SHA1EntropyProvider().get(440),
                    false,
                    "2021222324",
                    80,
                    new String[]
                        {
                            "E76B4EDD5C865BC8AFD809A59B69B429AC7F4352A579BCF3F75E56249A3491F87C3CA6848B0FAB25",
                            "6577B6B4F87A93240B199FE51A3B335313683103DECE171E3256FB7E803586CA4E45DD242EB01F70"
                        })
                    .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90919293949596")
                    .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6"),
                new DRBGTestVector(
                    new SHA1Digest(),
                    new SHA1EntropyProvider().get(440),
                    true,
                    "2021222324",
                    80,
                    new String[]
                        {
                            "56EF4913373994D5539F4D7D17AFE7448CDF5E72416CC6A71A340059FA0D5AE526B23250C46C0944",
                            "575B37A2739814F966C63B60A2C4F149CA9ACC84FC4B25493289B085C67B2E30F5F0B99A2C349E2A"
                        }),
                new DRBGTestVector(
                    new SHA1Digest(),
                    new SHA1EntropyProvider().get(440),
                    true,
                    "2021222324",
                    80,
                    new String[]
                        {
                            "532CA1165DCFF21C55592687639884AF4BC4B057DF8F41DE653AB44E2ADEC7C9303E75ABE277EDBF",
                            "73C2C67C696D686D0C4DBCEB5C2AF7DDF6F020B6874FAE4390F102117ECAAFF54418529A367005A0"
                        })
                .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576"),
                new DRBGTestVector(
                    new SHA1Digest(),
                    new SHA1EntropyProvider().get(440),
                    true,
                    "2021222324",
                    80,
                    new String[]
                        {
                            "183C242A1430E46C4ED70B4DBE1BF9AB0AB8721CDCA2A2D1820AD6F6C956858543B2AA191D8D1287",
                            "F196F9BD021C745CBD5AC7BFCE48EAAF0D0E7C091FBF436940E63A198EE770D9A4F0718669AF2BC9"
                        })
                    .addAdditionalInput("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90919293949596")
                    .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6"),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(440),
                    false,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "77E05A0E7DC78AB5D8934D5E93E82C06" +
                            "A07C04CEE6C9C53045EEB485872777CF3B3E35C474F976B8" +
                            "94BF301A86FA651F463970E89D4A0534B2ECAD29EC044E7E",
                            "5FF4BA493C40CFFF3B01E472C575668C" +
                            "CE3880B9290B05BFEDE5EC96ED5E9B2898508B09BC800EEE" +
                            "099A3C90602ABD4B1D4F343D497C6055C87BB956D53BF351"
                        }
                ),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(440),
                    true,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "92275523C70E567BCF9B35EC50B933F8" +
                            "12616DF586B7F72EE1BC7735A5C2654373CBBC72316DFF84" +
                            "20A33BF02B97AC8D1952583F270ACD7005CC027F4CF1187E",
                            "681A46B2AA8694A0FE4DEEA720927A84" +
                            "EAAA985E59C19F8BE0984D8CBEF8C69B754167641946E040" +
                            "EE2043E1CCB29DCF063C0A50830E428E6DCA262ECD77C542"
                        }),
                new DRBGTestVector(
                            new SHA384Digest(),
                            new SHA384EntropyProvider().get(888),
                            false,
                            "202122232425262728292A2B",
                            192,
                            new String[]
                                {
                                    "04FF23AD15E78790ADD36B438BBC097C7A11747CC2CCEEDE" +
                                    "2C978B23B3DC63B732C953061D7764990ABFEFC47A581B92" +
                                    "1BC0428C4F12212460E406A0F0651E7F0CB9A90ABFDB07B5" +
                                    "25565C74F0AA085082F6CF213AAFAD0C0646895078F1E1FE",
                                    "4F35B85F95DEE3E873054905CFD02341653E18F529930CBE" +
                                    "14D909F37FEAF2C790D22FAE7516B4590BE35D53E2FE1A35" +
                                    "AFE4B6607CB358589C3B4D094A1D81FE0717F1DF5BDDEB3E" +
                                    "114F130BB781E66C22B5B770E8AE115FF39F8ADAF66DEEDF"
                                }
                        ),
                new DRBGTestVector(
                        new SHA384Digest(),
                        new SHA384EntropyProvider().get(888),
                        true,
                        "202122232425262728292A2B",
                        192,
                        new String[]
                            {
                                "97993B78F7C31C0E876DC92EB7D6C408E09D608AD6B99D0E" +
                                "A2229B05A578C426334FCC8A1C7E676ED2D89A5B4CDF5B3F" +
                                "4ADF11936BF14F4E10909DBA9C24F4FDFFDE72351DA8E2CC" +
                                "3B135A395373899E5F1A5955B880CA9B9E9DD4C9CA7FA4D4",
                                "F5983946320E36C64EF283CA1F65D197CF81624EC6778E77" +
                                "0E78949D84EF21A45CDD62D1DB76920D4C2836FC6AE5299F" +
                                "AF1357D9701FAD10FBD88D1E2832239436D76EB271BDC3CA" +
                                "04425EC88BC0E89A4D5C37FFCE7C6C3ABDE9C413AE6D3FEA"
                            }
                    ),
                new DRBGTestVector(
                            new SHA512Digest(),
                            new SHA512EntropyProvider().get(888),
                            false,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                            {
                                "DA126CF95C6BF97E" +
                                "2F731F2137A907ACC70FD7AC9EBACD1C6E31C74029B052E3" +
                                "AABC48F3B00993F2B2381F7650A55322A968C86E05DE88E6" +
                                "367F6EF89A601DB4342E9086C7AC13B5E56C32E9E668040B" +
                                "73847893C5BFD38A1CF44F348B4EEE4CD68ADB7E7B8C837F" +
                                "19BC4F902761F7CFF24AB1D704FD11C4E929D8553753B55D",
                                "400B977CE8A2BB6A" +
                                "84C6FD1CF901459685ABF5408CFF4588CEDF52E2D2DC300A" +
                                "A9B4FAED8CD0161C2172B1FD269253195883D6EBF21020F2" +
                                "C20E5F2C81AE60C8595B834A229B1F5B726C1125717E6207" +
                                "8886EF38E61E32707AD5F8116C6393DFB6E7C7AE0E8E92BB" +
                                "D7E0C3D04BBA02F5169F2F569A58158915FEE4C9D28D45DB"
                            }
                        )
                    .setPersonalizationString(
                        "404142434445464748494A4B4C4D4E" +
                        "4F505152535455565758595A5B5C5D5E5F60616263646566" +
                        "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
                        "7F808182838485868788898A8B8C8D8E8F90919293949596" +
                        "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE")
                    .addAdditionalInput(
                        "606162636465666768696A6B6C6D6E" +
                        "6F707172737475767778797A7B7C7D7E7F80818283848586" +
                        "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E" +
                        "9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6" +
                        "B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCE")
                    .addAdditionalInput(
                        "A0A1A2A3A4A5A6A7A8A9AAABACADAE" +
                        "AFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6" +
                        "C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE" +
                        "DFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6" +
                        "F7F8F9FAFBFCFDFEFF000102030405060708090A0B0C0D0E"),
                new DRBGTestVector(
                        new SHA512Digest(),
                        new SHA512EntropyProvider().get(888),
                        true,
                        "202122232425262728292A2B2C2D2E2F",
                        256,
                        new String[]
                        {
                            "F93CA6855590A77F" +
                            "07354097E90E026648B6115DF008FFEDBD9D9811F54E8286" +
                            "EF00FDD6BA1E58DF2535E3FBDD9A9BA3754A97F36EE83322" +
                            "1582060A1F37FCE4EE8826636B28EAD589593F4CA8B64738" +
                            "8F24EB3F0A34796968D21BDEE6F81FD5DF93536F935937B8" +
                            "025EC8CBF57DDB0C61F2E41463CC1516D657DA2829C6BF90",
                            "4817618F48C60FB1" +
                            "CE5BFBDA0CAF4591882A31F6EE3FE0F78779992A06EC60F3" +
                            "7FB9A8D6108C231F0A927754B0599FA4FA27A4E25E065EF0" +
                            "3085B892979DC0E7A1080883CAEBFDFD3665A8F2D061C521" +
                            "F7D6E3DA2AF8B97B6B43B6EC831AF515070A83BBB9AC95ED" +
                            "4EF49B756A2377A5F0833D847E27A88DDB0C2CE4AD782E7B "
                        }
                    ),
                new DRBGTestVector(
                        new SHA512Digest(),
                        new SHA512EntropyProvider().get(888),
                        true,
                        "202122232425262728292A2B2C2D2E2F",
                        256,
                        new String[]
                        {
                            "0455DD4AD7DBACB2" +
                            "410BE58DF7248D765A4547ABAEE1743B0BCAD37EBD06DA7C" +
                            "F7CE5E2216E525327E9E2005EBEF2CE53BD733B18128627D" +
                            "3FD6153089373AF2606A1584646A0EA488BFEF45228699A0" +
                            "89CEA8AEC44502D86D9591F3552C688B7F7B45FCB0C3C2B9" +
                            "43C1CD8A6FC63DF4D81C3DA543C9CF2843855EA84E4F959C",
                            "C047D46D7F614E4E" +
                            "4A7952C79A451F8F7ACA379967E2977C401C626A2ED70D74" +
                            "A63660579A354115BC8C8C8CC3AEA3050686A0CFCDB6FA9C" +
                            "F78D4C2165BAF851C6F9B1CD16A2E14C15C6DAAC56C16E75" +
                            "FC84A14D58B41622E88B0F1B1995587FD8BAA999CBA98025" +
                            "4C8AB9A9691DF7B84D88B639A9A3106DEABEB63748B99C09"
                        }
                    )
                .addAdditionalInput(
                    "606162636465666768696A6B6C6D6E" +
                    "6F707172737475767778797A7B7C7D7E7F80818283848586" +
                    "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E" +
                    "9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6" +
                    "B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCE")
                .addAdditionalInput(
                    "A0A1A2A3A4A5A6A7A8A9AAABACADAE" +
                    "AFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6" +
                    "C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE" +
                    "DFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6" +
                    "F7F8F9FAFBFCFDFEFF000102030405060708090A0B0C0D0E"),
                new DRBGTestVector(
                            new SHA512Digest(),
                            new SHA512EntropyProvider().get(888),
                            true,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                            {
                                "22EB93A67911DA73" +
                                "85D9180C78127DE1A04FF713114C07C9C615F7CC5EF72744" +
                                "A2DDCD7C3CB85E65DED8EF5F240FBDCBEBBDE2BAAC8ECF7D" +
                                "CBC8AC333E54607AD41DC495D83DF72A05EF55B127C1441C" +
                                "9A0EFFDA2C7954DB6C2D04342EB812E5E0B11D6C395F41ED" +
                                "A2702ECE5BA479E2DFA18F953097492636C12FE30CE5C968",
                                "E66698CFBF1B3F2E" +
                                "919C03036E584EAA81CF1C6666240AF05F70637043733954" +
                                "D8A1E5A66A04C53C6900FDC145D4A3A80A31F5868ACE9AC9" +
                                "4E14E2051F624A05EEA1F8B684AA5410BCE315E76EA07C71" +
                                "5D6F34731320FF0DCF78D795E6EFA2DF92B98BE636CDFBA2" +
                                "9008DD392112AEC202F2E481CB9D83F987FEA69CD1B368BB"
                            }
                        )
                    .setPersonalizationString(
                        "404142434445464748494A4B4C4D4E" +
                            "4F505152535455565758595A5B5C5D5E5F60616263646566" +
                            "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
                            "7F808182838485868788898A8B8C8D8E8F90919293949596" +
                            "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE"),
                new DRBGTestVector(
                            new SHA512Digest(),
                            new SHA512EntropyProvider().get(888),
                            true,
                            "202122232425262728292A2B2C2D2E2F",
                            256,
                            new String[]
                            {
                                "7596A76372308BD5" +
                                "A5613439934678B35521A94D81ABFE63A21ACF61ABB88B61" +
                                "E86A12C37F308F2BBBE32BE4B38D03AE808386494D70EF52" +
                                "E9E1365DD18B7784CAB826F31D47579E4D57F69D8BF3152B" +
                                "95741946CEBE58571DF58ED39980D9AF44E69F01E8989759" +
                                "8E40171101A0E3302838E0AD9E849C01988993CF9F6E5263",
                                "DBE5EE36FCD85301" +
                                "303E1C3617C1AC5E23C08885D0BEFAAD0C85A0D89F85B9F1" +
                                "6ECE3D88A24EB96504F2F13EFA7049621782F5DE2C416A0D" +
                                "294CCFE53545C4E309C48E1E285A2B829A574B72B3C2FBE1" +
                                "34D01E3706B486F2401B9820E17298A342666918E15B8462" +
                                "87F8C5AF2D96B20FAF3D0BB392E15F4A06CDB0DECD1B6AD7"
                            }
                        )
                    .setPersonalizationString(
                        "404142434445464748494A4B4C4D4E" +
                            "4F505152535455565758595A5B5C5D5E5F60616263646566" +
                            "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
                            "7F808182838485868788898A8B8C8D8E8F90919293949596" +
                            "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE")
                    .addAdditionalInput(
                        "606162636465666768696A6B6C6D6E" +
                            "6F707172737475767778797A7B7C7D7E7F80818283848586" +
                            "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E" +
                            "9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6" +
                            "B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCE")
                    .addAdditionalInput(
                        "A0A1A2A3A4A5A6A7A8A9AAABACADAE" +
                            "AFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6" +
                            "C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE" +
                            "DFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6" +
                            "F7F8F9FAFBFCFDFEFF000102030405060708090A0B0C0D0E")
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

            SP80090DRBG d = new HashSP800DRBG(tv.getDigest(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

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

        // Exception tests
        //
        SP80090DRBG d;
        try
        {
            d = new HashSP800DRBG(new SHA256Digest(), 256, new SHA256EntropyProvider().get(128), null, null);
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
            d = new HashSP800DRBG(new SHA1Digest(), 256, new SHA256EntropyProvider().get(256), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("Requested security strength is not supported by the derivation function"))
            {
                fail("Wrong exception", e);
            }
        }
    }

    private class SHA1EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA1EntropyProvider()
        {
            super(
                Hex.decode(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536"
                        + "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6"
                        + "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6"), true);
        }
    }

    private class SHA256EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA256EntropyProvider()
        {
            super(Hex.decode(
                "00010203040506" +
                    "0708090A0B0C0D0E0F101112131415161718191A1B1C1D1E" +
                    "1F202122232425262728292A2B2C2D2E2F30313233343536" +
                    "80818283848586" +
                    "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E" +
                    "9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6" +
                    "C0C1C2C3C4C5C6" +
                    "C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE" +
                    "DFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6"), true);
        }
    }

    private class SHA384EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA384EntropyProvider()
        {
            super(Hex.decode(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223242526"
                    + "2728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50515253545556"
                    + "5758595A5B5C5D5E5F606162636465666768696A6B6C6D6E" +
                    "808182838485868788898A8B8C8D8E" +
                    "8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6" +
                    "A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBE" +
                    "BFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6" +
                    "D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEE" +
                    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCE" +
                    "CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6" +
                    "E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE" +
                    "FF000102030405060708090A0B0C0D0E0F10111213141516" +
                    "1718191A1B1C1D1E1F202122232425262728292A2B2C2D2E"), true);
        }
    }

    private class SHA512EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA512EntropyProvider()
        {
            super(Hex.decode(
                "000102030405060708090A0B0C0D0E" +
                    "0F101112131415161718191A1B1C1D1E1F20212223242526" +
                    "2728292A2B2C2D2E2F303132333435363738393A3B3C3D3E" +
                    "3F404142434445464748494A4B4C4D4E4F50515253545556" +
                    "5758595A5B5C5D5E5F606162636465666768696A6B6C6D6E" +
                    "808182838485868788898A8B8C8D8E" +
                    "8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6" +
                    "A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBE" +
                    "BFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6" +
                    "D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEE" +
                    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCE" +
                    "CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6" +
                    "E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE" +
                    "FF000102030405060708090A0B0C0D0E0F10111213141516" +
                    "1718191A1B1C1D1E1F202122232425262728292A2B2C2D2E"), true);
        }
    }
}
