package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests are taken from RFC 6979 - "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)"
 */
public class DeterministicDSATest
    extends SimpleTest
{

    public static final byte[] SAMPLE = Hex.decode("73616d706c65"); // "sample"
    public static final byte[] TEST = Hex.decode("74657374"); // "test"

    // test vectors from appendix in RFC 6979
    private void testHMacDeterministic()
    {
        DSAParameters dsaParameters = new DSAParameters(
            new BigInteger("86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447" +
                           "E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88" +
                           "73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C" +
                           "881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779", 16),
            new BigInteger("996F967F6C8E388D9E28D01E205FBA957A5698B1", 16),
            new BigInteger("07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D" +
                           "89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD" +
                           "87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4" +
                           "17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD", 16));

        DSAPrivateKeyParameters privKey = new DSAPrivateKeyParameters(new BigInteger("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7", 16), dsaParameters);

        doTestHMACDetDSASample(new SHA1Digest(), privKey, new BigInteger("2E1A0C2562B2912CAAF89186FB0F42001585DA55", 16), new BigInteger("29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5", 16));
        doTestHMACDetDSASample(new SHA224Digest(), privKey, new BigInteger("4BC3B686AEA70145856814A6F1BB53346F02101E", 16), new BigInteger("410697B92295D994D21EDD2F4ADA85566F6F94C1", 16));
        doTestHMACDetDSASample(new SHA256Digest(), privKey, new BigInteger("81F2F5850BE5BC123C43F71A3033E9384611C545", 16), new BigInteger("4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89", 16));
        doTestHMACDetDSASample(new SHA384Digest(), privKey, new BigInteger("07F2108557EE0E3921BC1774F1CA9B410B4CE65A", 16), new BigInteger("54DF70456C86FAC10FAB47C1949AB83F2C6F7595", 16));
        doTestHMACDetDSASample(new SHA512Digest(), privKey, new BigInteger("16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B", 16), new BigInteger("02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C", 16));

        doTestHMACDetDSATest(new SHA1Digest(), privKey, new BigInteger("42AB2052FD43E123F0607F115052A67DCD9C5C77", 16), new BigInteger("183916B0230D45B9931491D4C6B0BD2FB4AAF088", 16));
        doTestHMACDetDSATest(new SHA224Digest(), privKey, new BigInteger("6868E9964E36C1689F6037F91F28D5F2C30610F2", 16), new BigInteger("49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F", 16));
        doTestHMACDetDSATest(new SHA256Digest(), privKey, new BigInteger("22518C127299B0F6FDC9872B282B9E70D0790812", 16), new BigInteger("6837EC18F150D55DE95B5E29BE7AF5D01E4FE160", 16));
        doTestHMACDetDSATest(new SHA384Digest(), privKey, new BigInteger("854CF929B58D73C3CBFDC421E8D5430CD6DB5E66", 16), new BigInteger("91D0E0F53E22F898D158380676A871A157CDA622", 16));
        doTestHMACDetDSATest(new SHA512Digest(), privKey, new BigInteger("8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0", 16), new BigInteger("7C670C7AD72B6C050C109E1790008097125433E8", 16));

        doTestHMACDetDSATest(new SHA3Digest(224), privKey, new BigInteger("58748b6ca41d25e41f7bfa51fed204a10a1bd1d3", 16), new BigInteger("86de2fdad0bc848dd20ddd9dc6253fc6d7553268", 16));
        doTestHMACDetDSATest(new SHA3Digest(256), privKey, new BigInteger("98c7a7906ada494285b3ab15cf9188a425f26bd4", 16), new BigInteger("21c5ed876037470d3959fa12f918674a4bf190e9", 16));
        doTestHMACDetDSATest(new SHA3Digest(384), privKey, new BigInteger("445ec584ec15c14abc67c99886a30a286cc83b33", 16), new BigInteger("21f564d5bb4b175e89a1a6fb2f27cd34c861142d", 16));
        doTestHMACDetDSATest(new SHA3Digest(512), privKey, new BigInteger("16918083f4c3ff4fc9b327e9e120a30ec39faaf6", 16), new BigInteger("1e9183a1dc7c20dbb596920cd94da3844a087203", 16));

        dsaParameters = new DSAParameters(
                                new BigInteger("9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48" +
                                    "C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F" +
                                    "FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5" +
                                    "B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2" +
                                    "35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41" +
                                    "F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE" +
                                    "92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15" +
                                    "3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B", 16),
                                new BigInteger("F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F", 16),
                                new BigInteger("5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613" +
                                    "D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4" +
                                    "6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472" +
                                    "085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5" +
                                    "AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA" +
                                    "3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71" +
                                    "BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0" +
                                    "DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7", 16));

        privKey = new DSAPrivateKeyParameters(new BigInteger("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC", 16), dsaParameters);

        doTestHMACDetDSASample(new SHA1Digest(), privKey, new BigInteger("3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A", 16), new BigInteger("D26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF", 16));
        doTestHMACDetDSASample(new SHA224Digest(), privKey, new BigInteger("DC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C", 16), new BigInteger("A65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC", 16));
        doTestHMACDetDSASample(new SHA256Digest(), privKey, new BigInteger("EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809", 16), new BigInteger("7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53", 16));
        doTestHMACDetDSASample(new SHA384Digest(), privKey, new BigInteger("B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B", 16), new BigInteger("19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B", 16));
        doTestHMACDetDSASample(new SHA512Digest(), privKey, new BigInteger("2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E", 16), new BigInteger("D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351", 16));

        doTestHMACDetDSATest(new SHA1Digest(), privKey, new BigInteger("C18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0", 16), new BigInteger("414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA", 16));
        doTestHMACDetDSATest(new SHA224Digest(), privKey, new BigInteger("272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3", 16), new BigInteger("E9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806", 16));
        doTestHMACDetDSATest(new SHA256Digest(), privKey, new BigInteger("8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0", 16), new BigInteger("7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E", 16));
        doTestHMACDetDSATest(new SHA384Digest(), privKey, new BigInteger("239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE", 16), new BigInteger("6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961", 16));
        doTestHMACDetDSATest(new SHA512Digest(), privKey, new BigInteger("89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307", 16), new BigInteger("C9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1", 16));
    }

    private void doTestHMACDetDSASample(Digest digest, DSAPrivateKeyParameters privKey, BigInteger r, BigInteger s)
    {
        doTestHMACDetECDSA(new DSASigner(new HMacDSAKCalculator(digest)), digest, SAMPLE, privKey, r, s);
    }

    private void doTestHMACDetDSATest(Digest digest, DSAPrivateKeyParameters privKey, BigInteger r, BigInteger s)
    {
        doTestHMACDetECDSA(new DSASigner(new HMacDSAKCalculator(digest)), digest, TEST, privKey, r, s);
    }

    // test vectors from appendix in RFC 6979
    private void testECHMacDeterministic()
    {
        X9ECParameters x9ECParameters = NISTNamedCurves.getByName("P-192");
        ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(new BigInteger("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF", 16), new BigInteger("57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("A1F00DAD97AEEC91C95585F36200C65F3C01812AA60378F5", 16), new BigInteger("E07EC1304C7C6C9DEBBE980B9692668F81D4DE7922A0F97A", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55", 16), new BigInteger("CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("DA63BF0B9ABCF948FBB1E9167F136145F7A20426DCC287D5", 16), new BigInteger("C3AA2C960972BD7A2003A57E1C4C77F0578F8AE95E31EC5E", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8", 16), new BigInteger("3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey,   new BigInteger("0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D", 16), new BigInteger("EB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("6945A1C1D1B2206B8145548F633BB61CEF04891BAF26ED34", 16), new BigInteger("B7FB7FDFC339C0B9BD61A9F5A8EAF9BE58FC5CBA2CB15293", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE", 16), new BigInteger("5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("B234B60B4DB75A733E19280A7A6034BD6B1EE88AF5332367", 16), new BigInteger("7994090B2D59BB782BE57E74A44C9A1C700413F8ABEFE77A", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("FE4F4AE86A58B6507946715934FE2D8FF9D95B6B098FE739", 16), new BigInteger("74CF5605C98FBA0E1EF34D4B5A1577A7DCF59457CAE52290", 16));

        doTestHMACDetECDSATest(new SHA3Digest(224), privKey, new BigInteger("abfcb817d04cc223f0d9c02c6db9230a91f955bf4556e0c6", 16), new BigInteger("ec2c29065a50d8ea39533d49472ccf538a5388cb31900e8f", 16));
        doTestHMACDetECDSATest(new SHA3Digest(256), privKey, new BigInteger("a2c2d5362d3cea77191edb239bf22a14dcc59d6500a744fc", 16), new BigInteger("6c63f3012353082026be7e2c6f37e6d7811066ddc9b9ee47", 16));
        doTestHMACDetECDSATest(new SHA3Digest(384), privKey, new BigInteger("2ff2c37d48cd6691c8adb9d2b1c1af203a1a6b8769c588dd", 16), new BigInteger("79c8171097f845c608dafd218ba096a51e0e4882faf2c08d", 16));
        doTestHMACDetECDSATest(new SHA3Digest(512), privKey, new BigInteger("384619b82461f4cc852dfa1e87cd87105e8eb3cfd0fb6461", 16), new BigInteger("d0aac03f72e90942821e3af1f77fd8a6ae82d1ed31b8ed06", 16));

        x9ECParameters = NISTNamedCurves.getByName("P-224");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("22226F9D40A96E19C4A301CE5B74B115303C0F3A4FD30FC257FB57AC", 16), new BigInteger("66D1CDD83E3AF75605DD6E2FEFF196D30AA7ED7A2EDF7AF475403D69", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E", 16), new BigInteger("A6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA", 16), new BigInteger("BC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("0B115E5E36F0F9EC81F1325A5952878D745E19D7BB3EABFABA77E953", 16), new BigInteger("830F34CCDFE826CCFDC81EB4129772E20E122348A2BBD889A1B1AF1D", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("074BD1D979D5F32BF958DDC61E4FB4872ADCAFEB2256497CDAC30397", 16), new BigInteger("A4CECA196C3D5A1FF31027B33185DC8EE43F288B21AB342E5D8EB084", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey,   new BigInteger("DEAA646EC2AF2EA8AD53ED66B2E2DDAA49A12EFD8356561451F3E21C", 16), new BigInteger("95987796F6CF2062AB8135271DE56AE55366C045F6D9593F53787BD2", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("C441CE8E261DED634E4CF84910E4C5D1D22C5CF3B732BB204DBEF019", 16), new BigInteger("902F42847A63BDC5F6046ADA114953120F99442D76510150F372A3F4", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("AD04DDE87B84747A243A631EA47A1BA6D1FAA059149AD2440DE6FBA6", 16), new BigInteger("178D49B1AE90E3D8B629BE3DB5683915F4E8C99FDF6E666CF37ADCFD", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("389B92682E399B26518A95506B52C03BC9379A9DADF3391A21FB0EA4", 16), new BigInteger("414A718ED3249FF6DBC5B50C27F71F01F070944DA22AB1F78F559AAB", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("049F050477C5ADD858CAC56208394B5A55BAEBBE887FDF765047C17C", 16), new BigInteger("077EB13E7005929CEFA3CD0403C7CDCC077ADF4E44F3C41B2F60ECFF", 16));

        x9ECParameters = NISTNamedCurves.getByName("P-256");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32", 16), new BigInteger("6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F", 16), new BigInteger("B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16), new BigInteger("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719", 16), new BigInteger("4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00", 16), new BigInteger("2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey,   new BigInteger("0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89", 16), new BigInteger("01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692", 16), new BigInteger("C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", 16), new BigInteger("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6", 16), new BigInteger("8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04", 16), new BigInteger("39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55", 16));

        x9ECParameters = NISTNamedCurves.getByName("P-384");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8" +
                                                            "96D5724E4C70A825F872C9EA60D2EDF5", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey, new BigInteger("EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA3" +
                                                                    "7B9BA002899F6FDA3A4A9386790D4EB2", 16),
                                                            new BigInteger("A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF" +
                                                                    "26F49CA031D4857570CCB5CA4424A443", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366" +
                                                                        "450F76EE3DE43F5A125333A6BE060122", 16),
                                                              new BigInteger("9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E483" +
                                                                        "4C082C03D83028EFBF93A3C23940CA8D", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33" +
                                                                        "BDE1E888E63355D92FA2B3C36D8FB2CD", 16),
                                                                new BigInteger("F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEB" +
                                                                        "EFDC63ECCD1AC42EC0CB8668A4FA0AB0", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C" +
                                                                        "81A648152E44ACF96E36DD1E80FABE46", 16),
                                                                new BigInteger("99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F" +
                                                                        "A329C145786E679E7B82C71A38628AC8", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799C" +
                                                                        "FE30F35CC900056D7C99CD7882433709", 16),
                                                                new BigInteger("512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112" +
                                                                        "DC7CC3EF3446DEFCEB01A45C2667FDD5", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey, new BigInteger("4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F7789A8B8E43D0678" +
                                                                    "ACD9D29876DAF46638645F7F404B11C7", 16),
                                                            new BigInteger("D5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8C4B7186201A29916" +
                                                                    "95BA1C84541327E966FA7B50F7382282", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("E8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE888FC5BF954B5E624" +
                                                                    "64A9A817C47FF78B8C11066B24080E72", 16),
                                                            new BigInteger("07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3286B2BD43FA8C614" +
                                                                    "1C53EA5ABEF0D8231077A04540A96B66", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559" +
                                                                    "F918EEDAF2293BE5B475CC8F0188636B", 16),
                                                            new BigInteger("2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D" +
                                                                    "51AB373F9845C0514EEFB14024787265", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB" +
                                                                    "0542A7F0812998DA8F1DD3CA3CF023DB", 16),
                                                            new BigInteger("DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E0" +
                                                                    "6A739F040649A667BF3B828246BAA5A5", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D0" +
                                                                    "6FB6495CD21B4B6E340FC236584FB277", 16),
                                                            new BigInteger("976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B22463" +
                                                                    "4A2092CD3792E0159AD9CEE37659C736", 16));

        x9ECParameters = NISTNamedCurves.getByName("P-521");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C" +
                                                            "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83" +
                                                            "538", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910" +
                                                                             "FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D" +
                                                                             "75D", 16),
                                                              new BigInteger("0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D" +
                                                                             "5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5" +
                                                                             "D16", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A3" +
                                                                            "0715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2E" +
                                                                            "D2E", 16),
                                                              new BigInteger("050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17B" +
                                                                            "A41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B" +
                                                                            "41F", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659" +
                                                                             "D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E" +
                                                                             "1A7", 16),
                                                              new BigInteger("04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916" +
                                                                              "E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7E" +
                                                                              "CFC", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4" +
                                                                            "B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67" +
                                                                            "451", 16),
                                                              new BigInteger("1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5" +
                                                                              "FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65" +
                                                                              "D61", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1" +
                                                                            "74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37" +
                                                                            "7FA", 16),
                                                              new BigInteger("0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2" +
                                                                              "82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A" +
                                                                              "67A", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey,   new BigInteger("13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0" +
                                                                    "693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0" +
                                                                    "367", 16),
                                                              new BigInteger("1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90" +
                                                                  "F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC91679" +
                                                                  "7FF", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086" +
                                                                    "BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE1" +
                                                                    "7FB", 16),
                                                              new BigInteger("177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5" +
                                                                  "BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD51" +
                                                                  "9A4", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D807104" +
                                                                    "2EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656" +
                                                                    "AA8", 16),
                                                              new BigInteger("0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9" +
                                                                  "FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694" +
                                                                  "E86", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C" +
                                                                    "89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF60755" +
                                                                    "78C", 16),
                                                              new BigInteger("133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0E" +
                                                                  "D94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B" +
                                                                  "979", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10" +
                                                                    "CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47E" +
                                                                    "E6D", 16),
                                                              new BigInteger("1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78" +
                                                                  "A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4D" +
                                                                  "CE3", 16));

        x9ECParameters = NISTNamedCurves.getByName("B-163");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("35318FC447D48D7E6BC93B48617DDDEDF26AA658F", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("153FEBD179A69B6122DEBF5BC61EB947B24C93526", 16), new BigInteger("37AC9C670F8CF18045049BAE7DD35553545C19E49", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("0A379E69C44F9C16EA3215EA39EB1A9B5D58CC955", 16), new BigInteger("04BAFF5308DA2A7FE2C1742769265AD3ED1D24E74", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("134E00F78FC1CB9501675D91C401DE20DDF228CDC", 16), new BigInteger("373273AEC6C36CB7BAFBB1903A5F5EA6A1D50B624", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("29430B935AF8E77519B0CA4F6903B0B82E6A21A66", 16), new BigInteger("1EA1415306E9353FA5AA54BC7C2581DFBB888440D", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("0B2F177A99F9DF2D51CCAF55F015F326E4B65E7A0", 16), new BigInteger("0DF1FB4487E9B120C5E970EFE48F55E406306C3A1", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey,   new BigInteger("256D4079C6C7169B8BC92529D701776A269D56308", 16), new BigInteger("341D3FFEC9F1EB6A6ACBE88E3C86A1C8FDEB8B8E1", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("28ECC6F1272CE80EA59DCF32F7AC2D861BA803393", 16), new BigInteger("0AD4AE2C06E60183C1567D2B82F19421FE3053CE2", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("227DF377B3FA50F90C1CB3CDCBBDBA552C1D35104", 16), new BigInteger("1F7BEAD92583FE920D353F368C1960D0E88B46A56", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("11811DAFEEA441845B6118A0DFEE8A0061231337D", 16), new BigInteger("36258301865EE48C5C6F91D63F62695002AB55B57", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("3B6BB95CA823BE2ED8E3972FF516EB8972D765571", 16), new BigInteger("13DC6F420628969DF900C3FCC48220B38BE24A541", 16));

        x9ECParameters = NISTNamedCurves.getByName("B-233");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("07ADC13DD5BF34D1DDEEB50B2CE23B5F5E6D18067306D60C5F6FF11E5D3", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("015CC6FD78BB06E0878E71465515EA5A21A2C18E6FC77B4B158DBEB3944", 16), new BigInteger("0822A4A6C2EB2DF213A5E90BF40377956365EE8C4B4A5A4E2EB9270CB6A", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("05D9920B53471148E10502AB49AB7A3F11084820A074FD89883CF51BC1A", 16), new BigInteger("04D3938900C0A9AAA7080D1DFEB56CFB0FADABE4214536C7ED5117ED13A", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("0A797F3B8AEFCE7456202DF1E46CCC291EA5A49DA3D4BDDA9A4B62D5E0D", 16), new BigInteger("01F6F81DA55C22DA4152134C661588F4BD6F82FDBAF0C5877096B070DC2", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("015E85A8D46225DD7E314A1C4289731FC14DECE949349FE535D11043B85", 16), new BigInteger("03F189D37F50493EFD5111A129443A662AB3C6B289129AD8C0CAC85119C", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("03B62A4BF783919098B1E42F496E65F7621F01D1D466C46940F0F132A95", 16), new BigInteger("0F4BE031C6E5239E7DAA014CBBF1ED19425E49DAEB426EC9DF4C28A2E30", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey,   new BigInteger("02F1FEDC57BE203E4C8C6B8C1CEB35E13C1FCD956AB41E3BD4C8A6EFB1F", 16), new BigInteger("05738EC8A8EDEA8E435EE7266AD3EDE1EEFC2CEBE2BE1D614008D5D2951", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("0CCE175124D3586BA7486F7146894C65C2A4A5A1904658E5C7F9DF5FA5D", 16), new BigInteger("08804B456D847ACE5CA86D97BF79FD6335E5B17F6C0D964B5D0036C867E", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("035C3D6DFEEA1CFB29B93BE3FDB91A7B130951770C2690C16833A159677", 16), new BigInteger("0600F7301D12AB376B56D4459774159ADB51F97E282FF384406AFD53A02", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("061602FC8068BFD5FB86027B97455D200EC603057446CCE4D76DB8EF42C", 16), new BigInteger("03396DD0D59C067BB999B422D9883736CF9311DFD6951F91033BD03CA8D", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("07E12CB60FDD614958E8E34B3C12DDFF35D85A9C5800E31EA2CC2EF63B1", 16), new BigInteger("0E8970FD99D836F3CC1C807A2C58760DE6EDAA23705A82B9CB1CE93FECC", 16));

        x9ECParameters = NISTNamedCurves.getByName("B-283");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("14510D4BC44F2D26F4553942C98073C1BD35545CEABB5CC138853C5158D2729EA408836", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("201E18D48C6DB3D5D097C4DCE1E25587E1501FC3CF47BDB5B4289D79E273D6A9" +
            "ACB8285", 16), new BigInteger("151AE05712B024CE617358260774C8CA8B0E7A7E72EF8229BF2ACE7609560CB3" +
            "0322C4F", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("143E878DDFD4DF40D97B8CD638B3C4706501C2201CF7108F2FB91478C11D6947" +
            "3246925", 16), new BigInteger("0CBF1B9717FEEA3AABB09D9654110144267098E0E1E8D0289A6211BE0EEDFDD8" +
            "6A3DB79", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("29FD82497FB3E5CEF65579272138DE59E2B666B8689466572B3B69A172CEE83B" +
            "E145659", 16), new BigInteger("05A89D9166B40795AF0FE5958201B9C0523E500013CA12B4840EA2BC53F25F9B" +
            "3CE87C0", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("2F00689C1BFCD2A8C7A41E0DE55AE182E6463A152828EF89FE3525139B660329" +
            "4E69353", 16), new BigInteger("1744514FE0A37447250C8A329EAAADA81572226CABA16F39270EE5DD03F27B1F" +
            "665EB5D", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("0DA43A9ADFAA6AD767998A054C6A8F1CF77A562924628D73C62761847AD8286E" +
            "0D91B47", 16), new BigInteger("1D118733AE2C88357827CAFC6F68ABC25C80C640532925E95CFE66D40F8792F3" +
            "AC44C42", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey,   new BigInteger("05A408133919F2CDCDBE5E4C14FBC706C1F71BADAFEF41F5DE4EC27272FC1CA9" +
            "366FBB2", 16), new BigInteger("012966272872C097FEA7BCE64FAB1A81982A773E26F6E4EF7C99969846E67CA9" +
            "CBE1692", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("08F3824E40C16FF1DDA8DC992776D26F4A5981AB5092956C4FDBB4F1AE0A711E" +
            "EAA10E5", 16), new BigInteger("0A64B91EFADB213E11483FB61C73E3EF63D3B44EEFC56EA401B99DCC60CC28E9" +
            "9F0F1FA", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("3597B406F5329D11A79E887847E5EC60861CCBB19EC61F252DB7BD549C699951" +
            "C182796", 16), new BigInteger("0A6A100B997BC622D91701D9F5C6F6D3815517E577622DA69D3A0E8917C1CBE6" +
            "3ACD345", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("1BB490926E5A1FDC7C5AA86D0835F9B994EDA315CA408002AF54A298728D422E" +
            "BF59E4C", 16), new BigInteger("36C682CFC9E2C89A782BFD3A191609D1F0C1910D5FD6981442070393159D65FB" +
            "CC0A8BA", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("19944AA68F9778C2E3D6E240947613E6DA60EFCE9B9B2C063FF5466D72745B5A" +
            "0B25BA2", 16), new BigInteger("03F1567B3C5B02DF15C874F0EE22850824693D5ADC4663BAA19E384E550B1DD4" +
            "1F31EE6", 16));

        x9ECParameters = NISTNamedCurves.getByName("B-409");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("0494994CC325B08E7B4CE038BD9436F90B5E59A2C13C3140CD3AE07C04A01FC489F572CE0569A6DB7B8060393DE76330C624177", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey,   new BigInteger("0D8783188E1A540E2022D389E1D35B32F56F8C2BB5636B8ABF7718806B27A713" +
            "EBAE37F63ECD4B61445CEF5801B62594EF3E982", 16), new BigInteger("03A6B4A80E204DB0DE12E7415C13C9EC091C52935658316B4A0C591216A38791" +
            "54BEB1712560E346E7EF26517707435B55C3141", 16));
        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("0EE4F39ACC2E03CE96C3D9FCBAFA5C22C89053662F8D4117752A9B10F09ADFDA" +
            "59DB061E247FE5321D6B170EE758ACE1BE4D157", 16), new BigInteger("00A2B83265B456A430A8BF27DCC8A9488B3F126C10F0D6D64BF7B8A218FAAF20" +
            "E51A295A3AE78F205E5A4A6AE224C3639F1BB34", 16));
        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("02D8B1B31E33E74D7EB46C30FDE5AD2CA04EC8FE08FBA0E73BA5E568953AC5EA" +
            "307C072942238DFC07F4A4D7C7C6A9F86436D17", 16), new BigInteger("079F7D471E6CB73234AF7F7C381D2CE15DE35BAF8BB68393B73235B3A26EC2DF" +
            "4842CE433FB492D6E074E604D4870024D42189A", 16));
        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("07BC638B7E7CE6FEE5E9C64A0F966D722D01BB4BC3F3A35F30D4CDDA92DFC5F7" +
            "F0B4BBFE8065D9AD452FD77A1914BE3A2440C18", 16), new BigInteger("06D904429850521B28A32CBF55C7C0FDF35DC4E0BDA2552C7BF68A171E970E67" +
            "88ACC0B9521EACB4796E057C70DD9B95FED5BFB", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("05D178DECAFD2D02A3DA0D8BA1C4C1D95EE083C760DF782193A9F7B4A8BE6FC5" +
            "C21FD60613BCA65C063A61226E050A680B3ABD4", 16), new BigInteger("013B7581E98F6A63FBBCB3E49BCDA60F816DB230B888506D105DC229600497C3" +
            "B46588C784BE3AA9343BEF82F7C9C80AEB63C3B", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey, new BigInteger("049F54E7C10D2732B4638473053782C6919218BBEFCEC8B51640FC193E832291" +
            "F05FA12371E9B448417B3290193F08EE9319195", 16), new BigInteger("0499E267DEC84E02F6F108B10E82172C414F15B1B7364BE8BFD66ADC0C5DE23F" +
            "EE3DF0D811134C25AFE0E05A6672F98889F28F1", 16));
        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("0B1527FFAA7DD7C7E46B628587A5BEC0539A2D04D3CF27C54841C2544E1BBDB4" +
            "2FDBDAAF8671A4CA86DFD619B1E3732D7BB56F2", 16), new BigInteger("0442C68C044868DF4832C807F1EDDEBF7F5052A64B826FD03451440794063F52" +
            "B022DF304F47403D4069234CA9EB4C964B37C02", 16));
        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("0BB27755B991D6D31757BCBF68CB01225A38E1CFA20F775E861055DD108ED7EA" +
            "455E4B96B2F6F7CD6C6EC2B3C70C3EDDEB9743B", 16), new BigInteger("0C5BE90980E7F444B5F7A12C9E9AC7A04CA81412822DD5AD1BE7C45D5032555E" +
            "A070864245CF69266871FEB8CD1B7EDC30EF6D5", 16));
        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("04EFEB7098772187907C87B33E0FBBA4584226C50C11E98CA7AAC6986F8D3BE0" +
            "44E5B52D201A410B852536527724CA5F8CE6549", 16), new BigInteger("09574102FEB3EF87E6D66B94119F5A6062950FF4F902EA1E6BD9E2037F33FF99" +
            "1E31F5956C23AFE48FCDC557FD6F088C7C9B2B3", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("07E0249C68536AE2AEC2EC30090340DA49E6DC9E9EEC8F85E5AABFB234B6DA7D" +
            "2E9524028CF821F21C6019770474CC40B01FAF6", 16), new BigInteger("08125B5A03FB44AE81EA46D446130C2A415ECCA265910CA69D55F2453E16CD7B" +
            "2DFA4E28C50FA8137F9C0C6CEE4CD37ABCCF6D8", 16));

        x9ECParameters = NISTNamedCurves.getByName("B-571");
        ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

        privKey = new ECPrivateKeyParameters(new BigInteger("028A04857F24C1C082DF0D909C0E72F453F2E2340CCB071F0E389BCA2575DA19" +
                                                            "124198C57174929AD26E348CF63F78D28021EF5A9BF2D5CBEAF6B7CCB6C4DA82" +
                                                            "4DD5C82CFB24E11", 16), ecDomainParameters);

        doTestHMACDetECDSASample(new SHA1Digest(), privKey, new BigInteger("147D3EB0EDA9F2152DFD014363D6A9CE816D7A1467D326A625FC4AB0C786E1B7" +
                                                                            "4DDF7CD4D0E99541391B266C704BB6B6E8DCCD27B460802E0867143727AA4155" +
                                                                            "55454321EFE5CB6", 16),
                                                              new BigInteger("17319571CAF533D90D2E78A64060B9C53169AB7FC908947B3EDADC54C79CCF0A" +
                                                                              "7920B4C64A4EAB6282AFE9A459677CDA37FD6DD50BEF18709590FE18B923BDF7" +
                                                                              "4A66B189A850819", 16));

        doTestHMACDetECDSASample(new SHA224Digest(), privKey, new BigInteger("10F4B63E79B2E54E4F4F6A2DBC786D8F4A143ECA7B2AD97810F6472AC6AE2085" +
                                                                            "3222854553BE1D44A7974599DB7061AE8560DF57F2675BE5F9DD94ABAF3D47F1" +
                                                                            "582B318E459748B", 16),
                                                              new BigInteger("3BBEA07C6B269C2B7FE9AE4DDB118338D0C2F0022920A7F9DCFCB7489594C03B" +
                                                                              "536A9900C4EA6A10410007222D3DAE1A96F291C4C9275D75D98EB290DC0EEF17" +
                                                                              "6037B2C7A7A39A3", 16));

        doTestHMACDetECDSASample(new SHA256Digest(), privKey, new BigInteger("213EF9F3B0CFC4BF996B8AF3A7E1F6CACD2B87C8C63820000800AC787F17EC99" +
                                                                            "C04BCEDF29A8413CFF83142BB88A50EF8D9A086AF4EB03E97C567500C21D8657" +
                                                                            "14D832E03C6D054", 16),
                                                              new BigInteger("3D32322559B094E20D8935E250B6EC139AC4AAB77920812C119AF419FB62B332" +
                                                                              "C8D226C6C9362AE3C1E4AABE19359B8428EA74EC8FBE83C8618C2BCCB6B43FBA" +
                                                                              "A0F2CCB7D303945", 16));

        doTestHMACDetECDSASample(new SHA384Digest(), privKey, new BigInteger("375D8F49C656A0BBD21D3F54CDA287D853C4BB1849983CD891EF6CD6BB56A62B" +
                                                                            "687807C16685C2C9BCA2663C33696ACCE344C45F3910B1DF806204FF731ECB28" +
                                                                            "9C100EF4D1805EC", 16),
                                                              new BigInteger("1CDEC6F46DFEEE44BCE71D41C60550DC67CF98D6C91363625AC2553E4368D2DF" +
                                                                            "B734A8E8C72E118A76ACDB0E58697940A0F3DF49E72894BD799450FC9E550CC0" +
                                                                            "4B9FF9B0380021C", 16));
        doTestHMACDetECDSASample(new SHA512Digest(), privKey, new BigInteger("1C26F40D940A7EAA0EB1E62991028057D91FEDA0366B606F6C434C361F04E545" +
                                                                            "A6A51A435E26416F6838FFA260C617E798E946B57215284182BE55F29A355E60" +
                                                                            "24FE32A47289CF0", 16),
                                                              new BigInteger("3691DE4369D921FE94EDDA67CB71FBBEC9A436787478063EB1CC778B3DCDC1C4" +
                                                                            "162662752D28DEEDF6F32A269C82D1DB80C87CE4D3B662E03AC347806E3F19D1" +
                                                                            "8D6D4DE7358DF7E", 16));

        doTestHMACDetECDSATest(new SHA1Digest(), privKey, new BigInteger("133F5414F2A9BC41466D339B79376038A64D045E5B0F792A98E5A7AA87E0AD01" +
            "6419E5F8D176007D5C9C10B5FD9E2E0AB8331B195797C0358BA05ECBF24ACE59" +
            "C5F368A6C0997CC", 16),
            new BigInteger("3D16743AE9F00F0B1A500F738719C5582550FEB64689DA241665C4CE4F328BA0" +
                "E34A7EF527ED13BFA5889FD2D1D214C11EB17D6BC338E05A56F41CAFF1AF7B8D" +
                "574DB62EF0D0F21", 16));

        doTestHMACDetECDSATest(new SHA224Digest(), privKey, new BigInteger("3048E76506C5C43D92B2E33F62B33E3111CEEB87F6C7DF7C7C01E3CDA28FA5E8" +
            "BE04B5B23AA03C0C70FEF8F723CBCEBFF0B7A52A3F5C8B84B741B4F6157E69A5" +
            "FB0524B48F31828", 16),
            new BigInteger("2C99078CCFE5C82102B8D006E3703E020C46C87C75163A2CD839C885550BA5CB" +
                "501AC282D29A1C26D26773B60FBE05AAB62BFA0BA32127563D42F7669C97784C" +
                "8897C22CFB4B8FA", 16));

        doTestHMACDetECDSATest(new SHA256Digest(), privKey, new BigInteger("184BC808506E11A65D628B457FDA60952803C604CC7181B59BD25AEE1411A66D" +
                                                                    "12A777F3A0DC99E1190C58D0037807A95E5080FA1B2E5CCAA37B50D401CFFC34" +
                                                                    "17C005AEE963469", 16),
                                                              new BigInteger("27280D45F81B19334DBDB07B7E63FE8F39AC7E9AE14DE1D2A6884D2101850289" +
                                                                  "D70EE400F26ACA5E7D73F534A14568478E59D00594981ABE6A1BA18554C13EB5" +
                                                                  "E03921E4DC98333", 16));

        doTestHMACDetECDSATest(new SHA384Digest(), privKey, new BigInteger("319EE57912E7B0FAA1FBB145B0505849A89C6DB1EC06EA20A6A7EDE072A6268A" +
            "F6FD9C809C7E422A5F33C6C3326EAD7402467DF3272A1B2726C1C20975950F0F" +
            "50D8324578F13EC", 16),
            new BigInteger("2CF3EA27EADD0612DD2F96F46E89AB894B01A10DF985C5FC099CFFE0EA083EB4" +
                "4BE682B08BFE405DAD5F37D0A2C59015BA41027E24B99F8F75A70B6B7385BF39" +
                "BBEA02513EB880C", 16));
        doTestHMACDetECDSATest(new SHA512Digest(), privKey, new BigInteger("2AA1888EAB05F7B00B6A784C4F7081D2C833D50794D9FEAF6E22B8BE728A2A90" +
            "BFCABDC803162020AA629718295A1489EE7ED0ECB8AAA197B9BDFC49D18DDD78" +
            "FC85A48F9715544", 16),
            new BigInteger("0AA5371FE5CA671D6ED9665849C37F394FED85D51FEF72DA2B5F28EDFB2C6479" +
                "CA63320C19596F5E1101988E2C619E302DD05112F47E8823040CE540CD3E90DC" +
                "F41DBC461744EE9", 16));

    }

    private void doTestHMACDetECDSASample(Digest digest, ECPrivateKeyParameters privKey, BigInteger r, BigInteger s)
    {
        doTestHMACDetECDSA(new ECDSASigner(new HMacDSAKCalculator(digest)), digest, SAMPLE, privKey, r, s);
    }

    private void doTestHMACDetECDSATest(Digest digest, ECPrivateKeyParameters privKey, BigInteger r, BigInteger s)
    {
        doTestHMACDetECDSA(new ECDSASigner(new HMacDSAKCalculator(digest)), digest, TEST, privKey, r, s);
    }

    private void doTestHMACDetECDSA(DSA detSigner, Digest digest, byte[] data, CipherParameters privKey, BigInteger r, BigInteger s)
    {
        byte[] m = new byte[digest.getDigestSize()];

        digest.update(data, 0, data.length);

        digest.doFinal(m, 0);

        detSigner.init(true, privKey);

        BigInteger[] rs = detSigner.generateSignature(m);

        if (!r.equals(rs[0]))
        {
            fail("r value wrong, got " + rs[0].toString(16));
        }
        if (!s.equals(rs[1]))
        {
            fail("s value wrong, got " + rs[1].toString(16));
        }
    }

    public String getName()
    {
        return "DeterministicDSA";
    }

    public void performTest()
    {
        testHMacDeterministic();
        testECHMacDeterministic();
    }


    public static void main(
        String[] args)
    {
        runTest(new DeterministicDSATest());
    }
}

