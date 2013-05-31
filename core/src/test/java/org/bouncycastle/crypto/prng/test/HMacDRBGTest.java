package org.bouncycastle.crypto.prng.test;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.prng.drbg.HMacSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HMAC SP800-90 DRBG
 */
public class HMacDRBGTest
    extends SimpleTest
{
    public String getName()
    {
        return "HMacDRBG";
    }

    public static void main(String[] args)
    {
        runTest(new HMacDRBGTest());
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
                            "5A7D3B449F481CB38DF79AD2B1FCC01E57F8135E8C0B22CD0630BFB0127FB5408C8EFC17A929896E",
                            "82cf772ec3e84b00fc74f5df104efbfb2428554e9ce367d03aeade37827fa8e9cb6a08196115d948"
                        }),
                new DRBGTestVector(
                    new SHA1Digest(),
                    new SHA1EntropyProvider().get(440),
                    false,
                    "2021222324",
                    80,
                    new String[]
                        {
                            "B3BD05246CBA12A64735A4E3FDE599BC1BE30F439BD060208EEA7D71F9D123DF47B3CE069D98EDE6",
                            "B5DADA380E2872DF935BCA55B882C8C9376902AB639765472B71ACEBE2EA8B1B6B49629CB67317E0"
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
                            "C7AAAC583C6EF6300714C2CC5D06C148CFFB40449AD0BB26FAC0497B5C57E161E36681BCC930CE80",
                            "6EBD2B7B5E0A2AD7A24B1BF9A1DBA47D43271719B9C37B7FE81BA94045A14A7CB514B446666EA5A7"
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
                            "FEC4597F06A3A8CC8529D59557B9E661053809C0BC0EFC282ABD87605CC90CBA9B8633DCB1DAE02E",
                            "84ADD5E2D2041C01723A4DE4335B13EFDF16B0E51A0AD39BD15E862E644F31E4A2D7D843E57C5968"
                        }),
                new DRBGTestVector(
                    new SHA1Digest(),
                    new SHA1EntropyProvider().get(440),
                    true,
                    "2021222324",
                    80,
                    new String[]
                        {
                            "6C37FDD729AA40F80BC6AB08CA7CC649794F6998B57081E4220F22C5C283E2C91B8E305AB869C625",
                            "CAF57DCFEA393B9236BF691FA456FEA7FDF1DF8361482CA54D5FA723F4C88B4FA504BF03277FA783"
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
                            "A1BA8FA58BB5013F43F7B6ED52B4539FA16DC77957AEE815B9C07004C7E992EB8C7E591964AFEEA2",
                            "84264A73A818C95C2F424B37D3CC990B046FB50C2DC64A164211889A010F2471A0912FFEA1BF0195"
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
                            "D67B8C1734F46FA3F763CF57C6F9F4F2" +
                                "DC1089BD8BC1F6F023950BFC5617635208C8501238AD7A44" +
                                "00DEFEE46C640B61AF77C2D1A3BFAA90EDE5D207406E5403",
                            "8FDAEC20F8B421407059E3588920DA7E" +
                                "DA9DCE3CF8274DFA1C59C108C1D0AA9B0FA38DA5C792037C" +
                                "4D33CD070CA7CD0C5608DBA8B885654639DE2187B74CB263"
                        }),
                new DRBGTestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(440),
                    true,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "FABD0AE25C69DC2EFDEFB7F20C5A31B5" +
                            "7AC938AB771AA19BF8F5F1468F665C938C9A1A5DF0628A56" +
                            "90F15A1AD8A613F31BBD65EEAD5457D5D26947F29FE91AA7",
                            "6BD925B0E1C232EFD67CCD84F722E927" +
                            "ECB46AB2B740014777AF14BA0BBF53A45BDBB62B3F7D0B9C" +
                            "8EEAD057C0EC754EF8B53E60A1F434F05946A8B686AFBC7A"
                        }),
                new DRBGTestVector(
                    new SHA384Digest(),
                    new SHA384EntropyProvider().get(888),
                    false,
                    "202122232425262728292A2B",
                    192,
                    new String[]{
                        "03AB8BCE4D1DBBB636C5C5B7E1C58499FEB1C619CDD11D35" +
                        "CD6CF6BB8F20EF27B6F5F9054FF900DB9EBF7BF30ED4DCBB" +
                        "BC8D5B51C965EA226FFEE2CA5AB2EFD00754DC32F357BF7A" +
                        "E42275E0F7704DC44E50A5220AD05AB698A22640AC634829",
                        "B907E77144FD55A54E9BA1A6A0EED0AAC780020C41A15DD8" +
                        "9A6C163830BA1D094E6A17100FF71EE30A96E1EE04D2A966" +
                        "03832A4E404F1966C2B5F4CB61B9927E8D12AC1E1A24CF23" +
                        "88C14E8EC96C35181EAEE32AAA46330DEAAFE5E7CE783C74"})
                    .setPersonalizationString(
                        "404142434445464748494A4B4C4D4E" +
                        "4F505152535455565758595A5B5C5D5E5F60616263646566" +
                        "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
                        "7F808182838485868788898A8B8C8D8E8F90919293949596" +
                        "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE"),
                new DRBGTestVector(
                    new SHA384Digest(),
                    new SHA384EntropyProvider().get(888),
                    true,
                    "202122232425262728292A2B",
                    192,
                    new String[]{
                        "804A3AD720F4FCE8738D0632514FEF16430CB7D63A8DF1A5" +
                        "F02A3CE3BD7ED6A668B69E63E2BB93F096EE753D6194A0F1" +
                        "A32711063653009636337D22167CC4402D019AC216FA574F" +
                        "091CF6EA283568D737A77BE38E8F09382C69E76B142ABC3A",
                        "73B8E55C753202176A17B9B9754A9FE6F23B01861FCD4059" +
                        "6AEAA301AF1AEF8AF0EAF22FBF34541EFFAB1431666ACACC" +
                        "759338C7E28672819D53CFEF10A3E19DAFBD53295F1980A9" +
                        "F491504A2725506784B7AC826D92C838A8668171CAAA86E7"})
                    .setPersonalizationString(
                        "404142434445464748494A4B4C4D4E" +
                            "4F505152535455565758595A5B5C5D5E5F60616263646566" +
                            "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
                            "7F808182838485868788898A8B8C8D8E8F90919293949596" +
                            "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE"),
                new DRBGTestVector(
                    new SHA512Digest(),
                    new SHA512EntropyProvider().get(888),
                    false,
                    "202122232425262728292A2B2C2D2E2F",
                    256,
                    new String[]{
                        "2A5FF6520C20F66E" +
                            "D5EA431BD4AEAC58F975EEC9A015137D5C94B73AA09CB8B5" +
                            "9D611DDEECEB34A52BB999424009EB9EAC5353F92A6699D2" +
                            "0A02164EEBBC6492941E10426323898465DFD731C7E04730" +
                            "60A5AA8973841FDF3446FB6E72A58DA8BDA2A57A36F3DD98" +
                            "6DF85C8A5C6FF31CDE660BF8A841B21DD6AA9D3AC356B87B",
                        "0EDC8D7D7CEEC7FE" +
                            "36333FB30C0A9A4B27AA0BECBF075568B006C1C3693B1C29" +
                            "0F84769C213F98EB5880909EDF068FDA6BFC43503987BBBD" +
                            "4FC23AFBE982FE4B4B007910CC4874EEC217405421C8D8A1" +
                            "BA87EC684D0AF9A6101D9DB787AE82C3A6A25ED478DF1B12" +
                            "212CEC325466F3AC7C48A56166DD0B119C8673A1A9D54F67"})
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
                    new String[]{
                        "AAE4DC3C9ECC74D9" +
                        "061DD527117EF3D29E1E52B26853C539D6CA797E8DA3D0BB" +
                        "171D8E30B8B194D8C28F7F6BE3B986B88506DC6A01B294A7" +
                        "165DD1C3470F7BE7B396AA0DB7D50C4051E7C7E1C8A7D21A" +
                        "2B5878C0BCB163CAA79366E7A1162FDC88429616CD3E6977" +
                        "8D327520A6BBBF71D8AA2E03EC4A9DAA0E77CF93E1EE30D2 ",
                        "129FF6D31A23FFBC" +
                        "870632B35EE477C2280DDD2ECDABEDB900C78418BE2D243B" +
                        "B9D8E5093ECE7B6BF48638D8F704D134ADDEB7F4E9D5C142" +
                        "CD05683E72B516486AF24AEC15D61E81E270DD4EBED91B62" +
                        "12EB8896A6250D5C8BC3A4A12F7E3068FBDF856F47EB23D3" +
                        "79F82C1EBCD1585FB260B9C0C42625FBCEE68CAD773CD5B1"})
                .setPersonalizationString(
                    "404142434445464748494A4B4C4D4E" +
                        "4F505152535455565758595A5B5C5D5E5F60616263646566" +
                        "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
                        "7F808182838485868788898A8B8C8D8E8F90919293949596" +
                        "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE"),
                new DRBGTestVector(
                    new SHA512Digest(),
                    new SHA512EntropyProvider().get(888),
                    false,
                    "202122232425262728292A2B2C2D2E2F",
                    256,
                    new String[]{
                        "7AE31A2DEC31075F" +
                        "E5972660C16D22ECC0D415C5693001BE5A468B590BC1AE2C" +
                        "43F647F8D681AEEA0D87B79B0B4E5D089CA2C9D327534234" +
                        "0254E6B04690D77A71A294DA9568479EEF8BB2A2110F18B6" +
                        "22F60F35235DE0E8F9D7E98105D84AA24AF0757AF005DFD5" +
                        "2FA51DE3F44FCE0C5F3A27FCE8B0F6E4A3F7C7B53CE34A3D",
                        "D83A8084630F286D" +
                        "A4DB49B9F6F608C8993F7F1397EA0D6F4A72CF3EF2733A11" +
                        "AB823C29F2EBDEC3EDE962F93D920A1DB59C84E1E879C29F" +
                        "5F9995FC3A6A3AF9B587CA7C13EA197D423E81E1D6469942" +
                        "B6E2CA83A97E91F6B298266AC148A1809776C26AF5E239A5" +
                        "5A2BEB9E752203A694E1F3FE2B3E6A0C9C314421CDB55FBD "})
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
                    new String[]{
                        "28FD6060C4F35F4D" +
                            "317AB2060EE32019E0DAA330F3F5650BBCA57CB67EE6AF1C" +
                            "6F25D1B01F3601EDA85DC2ED29A9B2BA4C85CF491CE7185F" +
                            "1A2BD9378AE3C655BD1CEC2EE108AE7FC382989F6D4FEA8A" +
                            "B01499697C2F07945CE02C5ED617D04287FEAF3BA638A4CE" +
                            "F3BB6B827E40AF16279580FCF1FDAD830930F7FDE341E2AF",
                        "C0B1601AFE39338B" +
                            "58DC2BE7C256AEBE3C21C5A939BEEC7E97B3528AC420F0C6" +
                            "341847187666E0FF578A8EB0A37809F877365A28DF2FA0F0" +
                            "6354A6F02496747369375B9A9D6B756FDC4A8FB308E08256" +
                            "9D79A85BB960F747256626389A3B45B0ABE7ECBC39D5CD7B" +
                            "2C18DF2E5FDE8C9B8D43474C54B6F9839468445929B438C7"}),
                new DRBGTestVector(
                    new SHA512Digest(),
                    new SHA512EntropyProvider().get(888),
                    true,
                    "202122232425262728292A2B2C2D2E2F",
                    256,
                    new String[]{
                        "72691D2103FB567C" +
                        "CD30370715B36666F63430087B1C688281CA0974DB456BDB" +
                        "A7EB5C48CFF62EA05F9508F3B530CE995A272B11EC079C13" +
                        "923EEF8E011A93C19B58CC6716BC7CB8BD886CAA60C14D85" +
                        "C023348BD77738C475D6C7E1D9BFF4B12C43D8CC73F838DC" +
                        "4F8BD476CF8328EEB71B3D873D6B7B859C9B21065638FF95",
                        "8570DA3D47E1E160" +
                        "5CF3E44B8D328B995EFC64107B6292D1B1036B5F88CE3160" +
                        "2F12BEB71D801C0942E7C0864B3DB67A9356DB203490D881" +
                        "24FE86BCE38AC2269B4FDA6ABAA884039DF80A0336A24D79" +
                        "1EB3067C8F5F0CF0F18DD73B66A7B316FB19E02835CC6293" +
                        "65FCD1D3BE640178ED9093B91B36E1D68135F2785BFF505C"})
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
                    new String[]{
                        "AAE4DC3C9ECC74D9" +
                        "061DD527117EF3D29E1E52B26853C539D6CA797E8DA3D0BB" +
                        "171D8E30B8B194D8C28F7F6BE3B986B88506DC6A01B294A7" +
                        "165DD1C3470F7BE7B396AA0DB7D50C4051E7C7E1C8A7D21A" +
                        "2B5878C0BCB163CAA79366E7A1162FDC88429616CD3E6977" +
                        "8D327520A6BBBF71D8AA2E03EC4A9DAA0E77CF93E1EE30D2 ",
                        "129FF6D31A23FFBC" +
                        "870632B35EE477C2280DDD2ECDABEDB900C78418BE2D243B" +
                        "B9D8E5093ECE7B6BF48638D8F704D134ADDEB7F4E9D5C142" +
                        "CD05683E72B516486AF24AEC15D61E81E270DD4EBED91B62" +
                        "12EB8896A6250D5C8BC3A4A12F7E3068FBDF856F47EB23D3" +
                        "79F82C1EBCD1585FB260B9C0C42625FBCEE68CAD773CD5B1"})
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
                    new String[]{
                        "B8E827652175E6E0" +
                        "6E513C7BE94B5810C14ED94AD903647940CAEB7EE014C848" +
                        "8DCBBE6D4D6616D06656A3DC707CDAC4F02EE6D8408C065F" +
                        "CB068C0760DA47C5D60E5D70D09DC3929B6979615D117F7B" +
                        "EDCC661A98514B3A1F55B2CBABDCA59F11823E4838065F1F" +
                        "8431CBF28A577738234AF3F188C7190CC19739E72E9BBFFF",
                        "7ED41B9CFDC8C256" +
                        "83BBB4C553CC2DC61F690E62ABC9F038A16B8C519690CABE" +
                        "BD1B5C196C57CF759BB9871BE0C163A57315EA96F615136D" +
                        "064572F09F26D659D24211F9610FFCDFFDA8CE23FFA96735" +
                        "7595182660877766035EED800B05364CE324A75EB63FD9B3" +
                        "EED956D147480B1D0A42DF8AA990BB628666F6F61D60CBE2"})
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

            SP80090DRBG d = new HMacSP800DRBG(new HMac(tv.getDigest()), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

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
            d = new HMacSP800DRBG(new HMac(new SHA256Digest()), 256, new SHA256EntropyProvider().get(128), null, null);
            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("Not enough entropy for security strength required"))
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
