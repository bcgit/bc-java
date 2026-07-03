package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSABlindSignatureParameters;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSABlindSignatureClient;
import org.bouncycastle.crypto.signers.RSABlindSignatureServer;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Known-answer tests for {@link RSABlindSignatureClient} /
 * {@link RSABlindSignatureServer} against the four named variants of RFC 9474
 * sec. 5, using the test vectors in RFC 9474 Appendix A.
 */
public class RSABlindSignatureTest
    extends SimpleTest
{
    // RFC 9474 Appendix A — shared RSA key
    private static final BigInteger N = bi(
        "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047" +
        "a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f96" +
        "3be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a" +
        "9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1e" +
        "ec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe" +
        "2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c" +
        "03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236" +
        "cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704c" +
        "d8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd" +
        "2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bd" +
        "a33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646" +
        "388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa" +
        "11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b" +
        "398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17" +
        "e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e" +
        "2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5");

    private static final BigInteger E = new BigInteger("010001", 16);

    private static final BigInteger D = bi(
        "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a2870771" +
        "80b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a31" +
        "3f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad" +
        "88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83f" +
        "bcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82" +
        "e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29" +
        "b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1ab" +
        "f1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648" +
        "fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c368" +
        "0a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861" +
        "ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc545" +
        "1ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca" +
        "9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463" +
        "db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae0" +
        "42249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7" +
        "f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051");

    private static final BigInteger P = bi(
        "e1f4d7a34802e27c7392a3cea32a262a34dc3691bd87f3f310dc7567348893055" +
        "9c120fd0410194fb8a0da55bd0b81227e843fdca6692ae80e5a5d414116d4803f" +
        "ca7d8c30eaaae57e44a1816ebb5c5b0606c536246c7f11985d731684150b63c9a" +
        "3ad9e41b04c0b5b27cb188a692c84696b742a80d3cd00ab891f2457443dadfeba" +
        "6d6daf108602be26d7071803c67105a5426838e6889d77e8474b29244cefaf418" +
        "e381b312048b457d73419213063c60ee7b0d81820165864fef93523c9635c2221" +
        "0956e53a8d96322493ffc58d845368e2416e078e5bcb5d2fd68ae6acfa54f9627" +
        "c42e84a9d3f2774017e32ebca06308a12ecc290c7cd1156dcccfb2311");

    private static final BigInteger Q = bi(
        "c601a9caea66dc3835827b539db9df6f6f5ae77244692780cd334a006ab353c80" +
        "6426b60718c05245650821d39445d3ab591ed10a7339f15d83fe13f6a3dfb20b9" +
        "452c6a9b42eaa62a68c970df3cadb2139f804ad8223d56108dfde30ba7d367e9b" +
        "0a7a80c4fdba2fd9dde6661fc73fc2947569d2029f2870fc02d8325acf28c9afa" +
        "19ecf962daa7916e21afad09eb62fe9f1cf91b77dc879b7974b490d3ebd2e9542" +
        "6057f35d0a3c9f45f79ac727ab81a519a8b9285932d9b2e5ccd347e59f3f32ad9" +
        "ca359115e7da008ab7406707bd0e8e185a5ed8758b5ba266e8828f8d863ae1338" +
        "46304a2936ad7bc7c9803879d2fc4a28e69291d73dbd799f8bc238385");

    // RFC 9474 Appendix A — common to all four variants (same r reused)
    private static final BigInteger INV = bi(
        "80682c48982407b489d53d1261b19ec8627d02b8cda5336750b8cee332ae260d" +
        "e57b02d72609c1e0e9f28e2040fc65b6f02d56dbd6aa9af8fde656f70495dfb7" +
        "23ba01173d4707a12fddac628ca29f3e32340bd8f7ddb557cf819f6b01e445ad" +
        "96f874ba235584ee71f6581f62d4f43bf03f910f6510deb85e8ef06c7f09d979" +
        "4a008be7ff2529f0ebb69decef646387dc767b74939265fec0223aa6d84d2a8a" +
        "1cc912d5ca25b4e144ab8f6ba054b54910176d5737a2cff011da431bd5f2a0d2" +
        "d66b9e70b39f4b050e45c0d9c16f02deda9ddf2d00f3e4b01037d7029cd49c2d" +
        "46a8e1fc2c0c17520af1f4b5e25ba396afc4cd60c494a4c426448b35b49635b3" +
        "37cfb08e7c22a39b256dd032c00adddafb51a627f99a0e1704170ac1f1912e49" +
        "d9db10ec04c19c58f420212973e0cb329524223a6aa56c7937c5dffdb5d966b6" +
        "cd4cbc26f3201dd25c80960a1a111b32947bb78973d269fac7f5186530930ed1" +
        "9f68507540eed9e1bab8b00f00d8ca09b3f099aae46180e04e3584bd7ca054df" +
        "18a1504b89d1d1675d0966c4ae1407be325cdf623cf13ff13e4a28b594d59e3e" +
        "adbadf6136eee7a59d6a444c9eb4e2198e8a974f27a39eb63af2c9af3870488b" +
        "8adaad444674f512133ad80b9220e09158521614f1faadfe8505ef57b7df6813" +
        "048603f0dd04f4280177a11380fbfc861dbcbd7418d62155248dad5fdec0991f");

    private static final byte[] MSG = hex(
        "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6" +
        "b59f8cfec5fdbb36331372ebefedae7d");

    // RFC 9474 A.1 — RSABSSA-SHA384-PSS-Deterministic
    private static final byte[] DET_PSS_SALT = hex(
        "051722b35f458781397c3a671a7d3bd3096503940e4c4f1aaa269d60300ce449" +
        "555cd7340100df9d46944c5356825abf");
    private static final byte[] DET_PSS_BLINDED = hex(
        "10c166c6a711e81c46f45b18e5873cc4f494f003180dd7f115585d871a289302" +
        "59654fe28a54dab319cc5011204c8373b50a57b0fdc7a678bd74c523259dfe4f" +
        "d5ea9f52f170e19dfa332930ad1609fc8a00902d725cfe50685c95e5b2968c9a" +
        "2828a21207fcf393d15f849769e2af34ac4259d91dfd98c3a707c509e1af5564" +
        "7efaa31290ddf48e0133b798562af5eabd327270ac2fb6c594734ce339a14ea4" +
        "fe1b9a2f81c0bc230ca523bda17ff42a377266bc2778a274c0ae5ec5a8cbbe36" +
        "4fcf0d2403f7ee178d77ff28b67a20c7ceec009182dbcaa9bc99b51ebbf13b7d" +
        "542be337172c6474f2cd3561219fe0dfa3fb207cff89632091ab841cf38d8aa8" +
        "8af6891539f263adb8eac6402c41b6ebd72984e43666e537f5f5fe27b2b5aa11" +
        "4957e9a580730308a5f5a9c63a1eb599f093ab401d0c6003a451931b6d124180" +
        "305705845060ebba6b0036154fcef3e5e9f9e4b87e8f084542fd1dd67e7782a5" +
        "585150181c01eb6d90cb95883837384a5b91dbb606f266059ecc51b5acbaa280" +
        "e45cfd2eec8cc1cdb1b7211c8e14805ba683f9b78824b2eb005bc8a7d7179a36" +
        "c152cb87c8219e5569bba911bb32a1b923ca83de0e03fb10fba75d85c55907dd" +
        "a5a2606bf918b056c3808ba496a4d95532212040a5f44f37e1097f26dc27b98a" +
        "51837daa78f23e532156296b64352669c94a8a855acf30533d8e0594ace7c442");
    private static final byte[] DET_PSS_BLIND_SIG = hex(
        "364f6a40dbfbc3bbb257943337eeff791a0f290898a6791283bba581d9eac90a" +
        "6376a837241f5f73a78a5c6746e1306ba3adab6067c32ff69115734ce014d354" +
        "e2f259d4cbfb890244fd451a497fe6ecf9aa90d19a2d441162f7eaa7ce3fc4e8" +
        "9fd4e76b7ae585be2a2c0fd6fb246b8ac8d58bcb585634e30c9168a434786fe5" +
        "e0b74bfe8187b47ac091aa571ffea0a864cb906d0e28c77a00e8cd8f6aba4317" +
        "a8cc7bf32ce566bd1ef80c64de041728abe087bee6cadd0b7062bde5ceef308a" +
        "23bd1ccc154fd0c3a26110df6193464fc0d24ee189aea8979d722170ba945fdc" +
        "ce9b1b4b63349980f3a92dc2e5418c54d38a862916926b3f9ca270a8cf40dfb9" +
        "772bfbdd9a3e0e0892369c18249211ba857f35963d0e05d8da98f1aa0c6bba58" +
        "f47487b8f663e395091275f82941830b050b260e4767ce2fa903e75ff8970c98" +
        "bfb3a08d6db91ab1746c86420ee2e909bf681cac173697135983c3594b2def67" +
        "3736220452fde4ddec867d40ff42dd3da36c84e3e52508b891a00f50b4f62d11" +
        "2edb3b6b6cc3dbd546ba10f36b03f06c0d82aeec3b25e127af545fac28e1613a" +
        "0517a6095ad18a98ab79f68801e05c175e15bae21f821e80c80ab4fdec6fb34c" +
        "a315e194502b8f3dcf7892b511aee45060e3994cd15e003861bc7220a2babd7b" +
        "40eda03382548a34a7110f9b1779bf3ef6011361611e6bc5c0dc851e1509de1a");
    private static final byte[] DET_PSS_SIG = hex(
        "6fef8bf9bc182cd8cf7ce45c7dcf0e6f3e518ae48f06f3c670c649ac737a8b81" +
        "19a34d51641785be151a697ed7825fdfece82865123445eab03eb4bb91cecf4d" +
        "6951738495f8481151b62de869658573df4e50a95c17c31b52e154ae26a04067" +
        "d5ecdc1592c287550bb982a5bb9c30fd53a768cee6baabb3d483e9f1e2da954c" +
        "7f4cf492fe3944d2fe456c1ecaf0840369e33fb4010e6b44bb1d721840513524" +
        "d8e9a3519f40d1b81ae34fb7a31ee6b7ed641cb16c2ac999004c2191de020145" +
        "7523f5a4700dd649267d9286f5c1d193f1454c9f868a57816bf5ff76c838a2ee" +
        "b616a3fc9976f65d4371deecfbab29362caebdff69c635fe5a2113da4d4d8c24" +
        "f0b16a0584fa05e80e607c5d9a2f765f1f069f8d4da21f27c2a3b5c984b4ab24" +
        "899bef46c6d9323df4862fe51ce300fca40fb539c3bb7fe2dcc9409e425f2d3b" +
        "95e70e9c49c5feb6ecc9d43442c33d50003ee936845892fb8be475647da9a080" +
        "f5bc7f8a716590b3745c2209fe05b17992830ce15f32c7b22cde755c8a2fe50b" +
        "d814a0434130b807dc1b7218d4e85342d70695a5d7f29306f25623ad1e8aa08e" +
        "f71b54b8ee447b5f64e73d09bdd6c3b7ca224058d7c67cc7551e9241688ada12" +
        "d859cb7646fbd3ed8b34312f3b49d69802f0eaa11bc4211c2f7a29cd5c01ed01" +
        "a39001c5856fab36228f5ee2f2e1110811872fe7c865c42ed59029c706195d52");

    // RFC 9474 A.2 — RSABSSA-SHA384-PSSZERO-Deterministic (empty salt)
    private static final byte[] DET_PSSZERO_BLINDED = hex(
        "982790826556aabe6004467671a864397eea3b95740e9a11c8b80b99ee0cf4db" +
        "c50af860bda81b601a2eceaa6943ef104f13325ad0be2e37f42030b3120e87cf" +
        "ee8cfe59cde1acfb25485a43275ebe777292e2518181ae531e596f988ff16f45" +
        "8daa5a42408939cbe60e7271391a21657276427d195bee6a20054101d4ceb892" +
        "ecdea402ea1a866acf0e451a3336f07e7589330d96c3883fd5bc1a829a715b61" +
        "8b74a86b2a898764246ad081d4c9f1edb8ab5077e315fde2417ec2dd33cad93e" +
        "120340b49be89c18a63e62c6bb289037283d3bf18608be11ee4c823c710b0c6b" +
        "89235fed3f03a7b96ddd25a8f54f20dac37ce8905093ad8e066810f354fb1773" +
        "236e3d3788ba755de2c9bce8d340078bb1831ddc7314a5018673427ced65cb35" +
        "6281aae08b5e6636f3eb2417e09d6ae476a9abcc410bc8c90813d0740e39ae75" +
        "efae4c02eed49dbb7aa51258bb71197445d17a6029bf566ba6b36282173af2c4" +
        "2e9b9631366f22eb6a19ef1d92bd3ce0631d3a7fb3288195b0ba380a3828d541" +
        "1cefd5eba83e52198c001ac9946a333a33d89d4d235fc833239d59837f04eaf0" +
        "65e9563659b00c7624a6263b727d8f2c07959ba2bb592e7ff251b8f09c85995f" +
        "d2e4474e743586576b518230986b6076b762ae77088a37e4bffd2ef41ae68d6d" +
        "4e79205290b4f76c42ef039638c41cdc6fe8af9b429c0dee45b2942e3861da2a");
    private static final byte[] DET_PSSZERO_BLIND_SIG = hex(
        "362ef369f9b8c1487e285514702a7cd6fe03e4a2fb854881f3d3f986b7742a0c" +
        "9bfab6562a6cd5ed71c574af67d7e77e71b33420c08ebb0ff37886b858297f95" +
        "62fc366066c6d8e77bad1918b04756ba03f5c385d44f06759daf1b7a38b2a642" +
        "48dee95d0e3886c8afa1f74afd8ac3c56520d0f3fd206df8e0d257312756803b" +
        "09a79d0cc38112592c3aec32de5a9bc3284c5a0a2d0808b102deafa5cc60f04e" +
        "3d71c0284cba04f17f88aa8e07d5544fe0265807d515877f79d30ed26d522b9d" +
        "9c56597647b0dbca5a69d6418f8d1b51481723f272c2a3d48f6f4fd6beeac357" +
        "6c3edb00e8779964548aeab8e004c7c4f8ef9cb6e680e2d2d49792004bb3e697" +
        "4fa48f241a361ca449c02bd4c0ad4e66252c55e656f16049908efe59acbafa11" +
        "71895dfac64d909808e5420469d622c7253ec1de7522b41634d383bf8786bf88" +
        "1cbf1561627f1e62b2d93300ec30ec0f5f0ab32036fce068bc76b0b0c6452079" +
        "537f8d7f8dcee4b42bbf2d9ad7499d3835cd93cfc7e8ebea3554ab5241e181e5" +
        "d73241b7bebf0a281b63594a35f4993e2b416d60db966b58b648cfcba2c4bee4" +
        "c2830aae4a70ff55012480298f549c13b1b2684277bca12f592471b8a9928517" +
        "4f1c0ebb38fc80e74a10b3f02ec3e6682ba873f7ff0e1e79718b470927c74ed7" +
        "54d4f7c3d9a55e22246e829cdb5a1c6fb2a0a6c896df303063c918bcf5eb0017");
    private static final byte[] DET_PSSZERO_SIG = hex(
        "4454b6983ff01cb28545329f394936efa42ed231e15efbc025fdaca00277acf0" +
        "c8e00e3d8b0ecebd35b057b8ebfc14e1a7097368a4abd20b555894ccef3d1b95" +
        "28c6bcbda6b95376bef230d0f1feff0c1064c62c60a7ae7431d1fdfa43a81eed" +
        "9235e363e1ffa0b2797aba6aad6082fcd285e14fc8b71de6b9c87cb4059c7dc1" +
        "e96ae1e63795a1e9af86b9073d1d848aef3eca8a03421bcd116572456b53bcfd" +
        "4dabb0a9691f1fabda3ed0ce357aee2cfee5b1a0eb226f69716d4e011d96eede" +
        "5e38a9acb531a64336a0d5b0bae3ab085b658692579a376740ff6ce69e89b06f" +
        "360520b864e33d82d029c808248a19e18e31f0ecd16fac5cd4870f8d3ebc1c32" +
        "c718124152dc905672ab0b7af48bf7d1ac1ff7b9c742549c91275ab105458ae3" +
        "7621757add83482bbcf779e777bbd61126e93686635d4766aedf5103cf7978f3" +
        "856ccac9e28d21a850dbb03c811128616d315d717be1c2b6254f8509acae8620" +
        "42c034530329ce15ca2e2f6b1f5fd59272746e3918c748c0eb810bf76884fa10" +
        "fcf749326bbfaa5ba285a0186a22e4f628dbf178d3bb5dc7e165ca73f6a55ecc" +
        "14c4f5a26c4693ce5da032264cbec319b12ddb9787d0efa4fcf1e5ccee35ad85" +
        "ecd453182df9ed735893f830b570faae8be0f6fe2e571a4e0d927cba4debd368" +
        "d3b4fca33ec6251897a137cf75474a32ac8256df5e5ffa518b88b43fb6f63a24");

    // RFC 9474 A.3 — RSABSSA-SHA384-PSS-Randomized
    private static final byte[] RND_PSS_PREFIX = hex(
        "8417e699b219d583fb6216ae0c53ca0e9723442d02f1d1a34295527e7d929e8b");
    private static final byte[] RND_PSS_SALT = hex(
        "051722b35f458781397c3a671a7d3bd3096503940e4c4f1aaa269d60300ce449" +
        "555cd7340100df9d46944c5356825abf");
    private static final byte[] RND_PSS_BLINDED = hex(
        "aa3ee045138d874669685ffaef962c7694a9450aa9b4fd6465db9b3b75a522bb" +
        "921c4c0fdcdfae9667593255099cff51f5d3fd65e8ffb9d3b3036252a6b51b6e" +
        "dfb3f40382b2bbf34c0055e4cbcc422850e586d84f190cd449af11dc65545f5f" +
        "e26fd89796eb87da4bda0c545f397cddfeeb56f06e28135ec74fd477949e7677" +
        "f6f36cfae8fd5c1c5898b03b9c244cf6d1a4fb7ad1cb43aff5e80cb462fac541" +
        "e72f67f0a50f1843d1759edfaae92d1a916d3f0efaf4d650db416c3bf8abdb54" +
        "14a78cebc97de676723cb119e77aea489f2bbf530c440ebc5a75dccd3ebf5a41" +
        "2a5f346badd61bee588e5917bdcce9dc33c882e39826951b0b8276c620397194" +
        "7072b726e935816056ff5cb11a71ca2946478584126bb877acdf87255f26e6cc" +
        "a4e0878801307485d3b7bb89b289551a8b65a7a6b93db010423d1406e149c877" +
        "31910306e5e410b41d4da3234624e74f92845183e323cf7eb244f212a695f885" +
        "6c675fbc3a021ce649e22c6f0d053a9d238841cf3afdc2739f99672a419ae13c" +
        "17f1f8a3bc302ec2e7b98e8c353898b7150ad8877ec841ea6e4b288064c254fe" +
        "fd0d049c3ad196bf7ffa535e74585d0120ce728036ed500942fbd5e6332c298f" +
        "1ffebe9ff60c1e117b274cf0cb9d70c36ee4891528996ec1ed0b178e9f3c0c0e" +
        "6120885f39e8ccaadbb20f3196378c07b1ff22d10049d3039a7a92fe7efdd95d");
    private static final byte[] RND_PSS_BLIND_SIG = hex(
        "3f4a79eacd4445fca628a310d41e12fcd813c4d43aa4ef2b81226953248d6d00" +
        "adfee6b79cb88bfa1f99270369fd063c023e5ed546719b0b2d143dd1bca46b0e" +
        "0e615fe5c63d95c5a6b873b8b50bc52487354e69c3dfbf416e7aca18d5842c89" +
        "b676efdd38087008fa5a810161fcdec26f20ccf2f1e6ab0f9d2bb93e051cb9e8" +
        "6a9b28c5bb62fd5f5391379f887c0f706a08bcc3b9e7506aaf02485d688198f5" +
        "e22eefdf837b2dd919320b17482c5cc54271b4ccb41d267629b3f844fd63750b" +
        "01f5276c79e33718bb561a152acb2eb36d8be75bce05c9d1b94eb609106f3822" +
        "6fb2e0f5cd5c5c39c59dda166862de498b8d92f6bcb41af433d65a2ac23da87f" +
        "39764cb64e79e74a8f4ce4dd567480d967cefac46b6e9c06434c371563583435" +
        "7edd2ce6f105eea854ac126ccfa3de2aac5607565a4e5efaac5eed491c335f6f" +
        "c97e6eb7e9cea3e12de38dfb315220c0a3f84536abb2fdd722813e083feda010" +
        "391ac3d8fd1cd9212b5d94e634e69ebcc800c4d5c4c1091c64afc37acf563c7f" +
        "c0a6e4c082bc55544f50a7971f3fb97d5853d72c3af34ffd5ce123998be5360d" +
        "1059820c66a81e1ee6d9c1803b5b62af6bc877526df255b6d1d835d8c840bebb" +
        "cd6cc0ee910f17da37caf8488afbc08397a1941fcc79e76a5888a95b3d5405e1" +
        "3f737bea5c78d716a48eb9dc0aec8de39c4b45c6914ad4a8185969f70b1adf46");
    private static final byte[] RND_PSS_SIG = hex(
        "191e941c57510e22d29afad257de5ca436d2316221fe870c7cb75205a6c071c2" +
        "735aed0bc24c37f3d5bd960ab97a829a508f966bbaed7a82645e65eadaf24ab5" +
        "e6d9421392c5b15b7f9b640d34fec512846a3100b80f75ef51064602118c1a77" +
        "d28d938f6efc22041d60159a518d3de7c4d840c9c68109672d743d299d8d2577" +
        "ef60c19ab463c716b3fa75fa56f5735349d414a44df12bf0dd44aa3e10822a65" +
        "1ed4cb0eb6f47c9bd0ef14a034a7ac2451e30434d513eb22e68b7587a8de9b4e" +
        "63a059d05c8b22c7c51e2cfee2d8bef511412e93c859a13726d87c57d1bc4c2e" +
        "68ab121562f839c3a3d233e87ed63c69b7e57525367753fbebcc2a9805a28026" +
        "59f5888b2c69115bf865559f10d906c09d048a0d71bfee4b33857393ec2b69e4" +
        "51433496d02c9a7910abb954317720bbde9e69108eafc3e90bad3d5ca4066d7b" +
        "1e49013fa04e948104a1dd82b12509ecb146e948c54bd8bfb5e6d18127cd1f7a" +
        "93c3cf9f2d869d5a78878c03fe808a0d799e910be6f26d18db61c485b303631d" +
        "3568368fc41986d08a95ea6ac0592240c19d7b22416b9c82ae6241e211dd5610" +
        "d0baaa9823158f9c32b66318f5529491b7eeadcaa71898a63bac9d95f4aa548d" +
        "5e97568d744fc429104e32edd9c87519892a198a30d333d427739ffb9607b092" +
        "e910ae37771abf2adb9f63bc058bf58062ad456cb934679795bbdfcdfad5e0f2");

    // RFC 9474 A.4 — RSABSSA-SHA384-PSSZERO-Randomized
    private static final byte[] RND_PSSZERO_PREFIX = hex(
        "84ea86c8cf3beedfed73beceabd792027c609d1100bf041fdd60d826a718130d");
    private static final byte[] RND_PSSZERO_BLINDED = hex(
        "4c1b82d9b97b968b2ce0754e326abd49e3d723ed937d84bead34b6a834483b43" +
        "d510bf62ca47683ed366d94d3d357b270a85cf2cc2ddd171141b45d7549d5373" +
        "cf67d14f6f462c14ebded906793144faba37f129c0f3172854ec0f854e555552" +
        "eec5a30c87788f1039814594f04348709e26a883be82affff207b1886b75c037" +
        "f43f847f45d89bcbf210c22ffcdf8118ce8a526b3723e6209c26319f8f5d2adc" +
        "f0b637031c9fdf53470a915c587e30287ba88ed4f1cd5e93cf3d4990acf31fff" +
        "dbfddec80ae0b728d5b4c612a396fd81acaa65566a4dc1c24624f44fd10cdba0" +
        "5f3d0bed2e69bb0d13d41a9f1b4e67aa566520778733ced5e6260f4d1982f63b" +
        "b835442acffe3cb87f5f8ec6bb84226e0eab787159d08e57604b13557ceea97f" +
        "2c4ad0631accf898f302df86f0b64354ec0b3bdf1b4e2a4deb4d38f655ea8d80" +
        "de4cc19aa06ffcd56e348faf894c8774c53235ddcc152d80cf66b417eee4d182" +
        "781bab8c979937a3c7502d8f39c57c4f09884de5a7247f2539910a96e4b15f9a" +
        "3df88edc21a13030af357467a99dca50dba4afe4a6185a240ac8f1d8aab2e834" +
        "43025f94e1af930f56f78661369cc6790701f31b83aec40f96a72c7f7ba13b4e" +
        "bdd8e24e7351f4ffba0a7c072cb28f13aff06cd02368491044fcc536213b2e3b" +
        "1cf6ca81cf2097b7b19d2b36bd246f390f53768f1c2e56113ea91b33c7cfa647");
    private static final byte[] RND_PSSZERO_BLIND_SIG = hex(
        "4894f64d7214c216282d9842cbf7e7cccd9c0dcb1f4294a6bdeccd4c4c244616" +
        "0d7cac7892f01b70dfa69f533891d2fbb447f7cf7541d1b504a2d46fc1bb6de2" +
        "6b345972aada8ebce280b906f3a10a13208f77ef896fbe6bc4504327fd4c5c8f" +
        "03211d45ae9672e9f4be0f4900762ba2a7177a58b90d6dd1263faf2b7a5f15d5" +
        "0a7b00e733742c1b6a1ea4eb5fbfb407abf14496ab26b50cf1a5a56dea616b7a" +
        "6a5595777400571a751c682b9fdd6badb3f72292f314f4ba2ba0f394f91676a4" +
        "bb12e60ea08c977f7082be6357c1ca82fe3301fe5fb4128609bee2410db0481a" +
        "ea3a5737fb0bce9381272c2202644f662e99f64bf1190d66e230cc0371ec33fe" +
        "32fe725dfd872041914d39462a909414a780c9aab394af443199eba56c83986d" +
        "22d57d4421b41ff8e5bec537d271223adb34d26c64989048a88d8f352a06a7cc" +
        "153e216a6bed9548bb38d2a1600b2f3403289df6df74aec525ef9e413b7140a7" +
        "c1a914dedd74a336f1beed39a8e5e2cef76cac094df0dbb3fa55d4b7ee781c74" +
        "bed3bd8bc7aa6ef3f1dbfa4674945720ec93dafa6d0650229ab75e3fae687327" +
        "fac081cf4bb376e02a2b73314c54c12f88572c28980f13aba5731bc5a3a60575" +
        "ea116c8ea2fe5009168deb1255026c9310783ff7f644255d3e1691e194db1bab" +
        "d7780b9a5dc0cb3de2b700d12f49cbe4db51ca2f3c8a58b09e854cc71e8070ab");
    private static final byte[] RND_PSSZERO_SIG = hex(
        "195363ba25e4bf763f6538c86865785f93f4ea6092da3ad200d41b99eb0eb086" +
        "9fa792df619fd8fa5923d5d03d5882faae6d25054118deef5e4a6a252dd5afb0" +
        "dac262b74c391090b1575fbafd959d26bc294f47fb45a2c1c209932c4f94b243" +
        "94eded91fbdd015e1a85dde63c9e77a0283f812cad1192d86432c51331e46fd4" +
        "f3771bbafb929f847a19cb05e5f79b6b519d67e8f005951e53656be97cb612d2" +
        "f506618b366403b34648451d6fbc7318c2f3f583cc6fa17bf2108398f9284e06" +
        "02187904406a9322f1e7b8016ca9ad11b835756df862c465c420535e25faa48b" +
        "f341f7ee8192be47fa875791f32f56d5e631d237060688f052426dee5b0b2b74" +
        "ca5f830e82a453379eedb541fa4fcdaa19dae6509401e3cdd4c40f5c9243db3f" +
        "6d7115c4e8cd6db8290723ab01d9d0d7e355a97a01547800e43f11736668c3f8" +
        "908848d759c33a67a2f506abc3f6871cbe625b1bc71eb06d785a59501396712c" +
        "581a60d6ccc450d2f4eb4cf08ae0dbfa45c2860425be90cc4cd4c989495bbd29" +
        "63e19c59ae5d90d1ca884e80d654b5f2cd6a80c3588b514ee91c802736f594c3" +
        "40397b316a97e9c70b0609955b6c3ee06f4760d9377f0797a0411a244db395bb" +
        "8b711ef79fbcb5589226174029be79a72dcd6f4ca566b7b1b9a27e43b5c02a9a" +
        "579d60bdda183398d66d76e0e8eceb1af2f27633589d043bcdc041683b31f7f1");

    public String getName()
    {
        return "RSABlindSignature";
    }

    public void performTest()
        throws Exception
    {
        RSAKeyParameters publicKey = new RSAKeyParameters(false, N, E);
        RSAPrivateCrtKeyParameters privateKey = makePrivateKey();

        BigInteger r = BigIntegers.modOddInverse(N, INV);

        runKat(publicKey, privateKey, r,
            RSABlindSignatureParameters.RSABSSA_SHA384_PSS_DETERMINISTIC,
            null, MSG, DET_PSS_SALT, DET_PSS_BLINDED, DET_PSS_BLIND_SIG, DET_PSS_SIG);

        runKat(publicKey, privateKey, r,
            RSABlindSignatureParameters.RSABSSA_SHA384_PSSZERO_DETERMINISTIC,
            null, MSG, new byte[0], DET_PSSZERO_BLINDED, DET_PSSZERO_BLIND_SIG, DET_PSSZERO_SIG);

        runKat(publicKey, privateKey, r,
            RSABlindSignatureParameters.RSABSSA_SHA384_PSS_RANDOMIZED,
            RND_PSS_PREFIX, MSG, RND_PSS_SALT, RND_PSS_BLINDED, RND_PSS_BLIND_SIG, RND_PSS_SIG);

        runKat(publicKey, privateKey, r,
            RSABlindSignatureParameters.RSABSSA_SHA384_PSSZERO_RANDOMIZED,
            RND_PSSZERO_PREFIX, MSG, new byte[0], RND_PSSZERO_BLINDED, RND_PSSZERO_BLIND_SIG, RND_PSSZERO_SIG);

        testRoundTrip();
        testRandomizedPrefix();
        testWrongLengthRejected(publicKey, privateKey);
        testMessageEdgeCases();
        testConstructorSecureRandom();
    }

    private void runKat(RSAKeyParameters publicKey, RSAPrivateCrtKeyParameters privateKey, BigInteger r,
        RSABlindSignatureParameters params, byte[] msgPrefix, byte[] msg, byte[] salt,
        byte[] expectedBlinded, byte[] expectedBlindSig, byte[] expectedSig)
        throws Exception
    {
        String tag = params.getName();

        byte[] preparedMsg = params.isRandomized()
            ? concat(msgPrefix, msg)
            : (byte[])msg.clone();

        // RFC 9474 Blind, composed exactly as RSABlindSignatureClient.blind() does
        // (PSSSigner over RSABlindingEngine) but with the fixed Appendix A salt and
        // blinding factor r pinned through the public PSSSigner + RSABlindingParameters
        // surface — the same way PSSBlindTest drives the toolkit — so no test-only client
        // entry point is needed. client.blind() draws its own random salt and r and so
        // cannot reproduce these fixed vectors; it is exercised end-to-end in
        // testRoundTrip(). Keep this composition in lockstep with the client's blind().
        PSSSigner blindEncoder = new PSSSigner(new RSABlindingEngine(), params.createDigest(), salt);
        blindEncoder.init(true, new RSABlindingParameters(publicKey, r));
        blindEncoder.update(preparedMsg, 0, preparedMsg.length);
        byte[] blindedMsg = blindEncoder.generateSignature();
        isTrue(tag + " blinded_msg", areEqual(expectedBlinded, blindedMsg));

        RSABlindSignatureServer server = new RSABlindSignatureServer(privateKey);
        byte[] blindSig = server.blindSign(blindedMsg);
        isTrue(tag + " blind_sig", areEqual(expectedBlindSig, blindSig));

        // Finalize == unblind (s = z * inv mod n) then a standard RSASSA-PSS verify. Composed
        // here through public BigInteger ops because the client cannot be handed the fixed
        // Appendix A r; RSABlindSignatureClient.finalize performs this exact unblind.
        BigInteger inv = BigIntegers.modOddInverse(N, r);
        BigInteger z = BigIntegers.fromUnsignedByteArray(blindSig);
        byte[] sig = BigIntegers.asUnsignedByteArray(BigIntegers.getUnsignedByteLength(N), z.multiply(inv).mod(N));
        isTrue(tag + " sig", areEqual(expectedSig, sig));

        // Independent verification through a vanilla PSSSigner instance — proves the
        // resulting signature is a standard RSASSA-PSS signature over the prepared
        // message, exactly as RFC 9474 sec. 4.5 requires.
        PSSSigner verifier = new PSSSigner(new RSAEngine(), params.createDigest(), params.getSaltLength());
        verifier.init(false, publicKey);
        verifier.update(preparedMsg, 0, preparedMsg.length);
        isTrue(tag + " independent verify", verifier.verifySignature(sig));
    }

    private void testRoundTrip()
        throws Exception
    {
        RSAKeyParameters publicKey = new RSAKeyParameters(false, N, E);
        RSAPrivateCrtKeyParameters privateKey = makePrivateKey();
        SecureRandom random = new SecureRandom();
        byte[] msg = Hex.decode("c0ffee");

        RSABlindSignatureParameters[] variants = new RSABlindSignatureParameters[] {
            RSABlindSignatureParameters.RSABSSA_SHA384_PSS_RANDOMIZED,
            RSABlindSignatureParameters.RSABSSA_SHA384_PSSZERO_RANDOMIZED,
            RSABlindSignatureParameters.RSABSSA_SHA384_PSS_DETERMINISTIC,
            RSABlindSignatureParameters.RSABSSA_SHA384_PSSZERO_DETERMINISTIC,
        };

        for (int i = 0; i != variants.length; i++)
        {
            RSABlindSignatureParameters params = variants[i];
            RSABlindSignatureClient client = new RSABlindSignatureClient(params, publicKey, random);

            RSABlindSignatureClient.Blinded blinded = client.blind(msg);
            byte[] preparedMsg = blinded.getPreparedMessage();

            if (params.isRandomized())
            {
                isTrue(params.getName() + " prepared length", preparedMsg.length == 32 + msg.length);
            }
            else
            {
                isTrue(params.getName() + " prepared identity", areEqual(msg, preparedMsg));
            }

            RSABlindSignatureServer server = new RSABlindSignatureServer(privateKey);
            byte[] blindSig = server.blindSign(blinded.getBlindedMessage());

            byte[] sig = client.finalize(blinded, blindSig);

            // Unblinding must left-pad to modulus_len; a short signature here would mean
            // s = z * inv mod n dropped a leading zero (RFC 9474 returns modulus_len bytes).
            isTrue(params.getName() + " sig length", sig.length == BigIntegers.getUnsignedByteLength(N));

            PSSSigner verifier = new PSSSigner(new RSAEngine(), params.createDigest(), params.getSaltLength());
            verifier.init(false, publicKey);
            verifier.update(preparedMsg, 0, preparedMsg.length);
            isTrue(params.getName() + " round-trip verify", verifier.verifySignature(sig));
        }
    }

    private void testRandomizedPrefix()
        throws CryptoException
    {
        RSAKeyParameters publicKey = new RSAKeyParameters(false, N, E);
        byte[] msg = Hex.decode("c0ffee");
        byte[] prefix = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        // The randomized Prepare (RFC 9474 sec. 4.1) prepends a fresh 32-byte prefix, drawn from the
        // supplied SecureRandom ahead of everything else, in front of the message. Feed a fixed random
        // whose first 32 bytes are a known prefix and confirm the prepared message is exactly
        // prefix || msg — pinning prefix provenance, its offset-0 placement, and its width. PSSZERO
        // draws no PSS salt; the trailing budget is sized generously to cover the blinding-factor
        // draw (and any candidate retries, each ~modulus_len bytes).
        byte[] randomBytes = new byte[prefix.length + 4096];
        System.arraycopy(prefix, 0, randomBytes, 0, prefix.length);
        for (int i = prefix.length; i != randomBytes.length; i++)
        {
            randomBytes[i] = (byte)i;
        }

        RSABlindSignatureClient client = new RSABlindSignatureClient(
            RSABlindSignatureParameters.RSABSSA_SHA384_PSSZERO_RANDOMIZED, publicKey, new FixedSecureRandom(randomBytes));
        byte[] prepared = client.blind(msg).getPreparedMessage();

        isTrue("randomized prepared = prefix || msg", areEqual(concat(prefix, msg), prepared));
    }

    private void testWrongLengthRejected(RSAKeyParameters publicKey, RSAPrivateCrtKeyParameters privateKey)
        throws CryptoException
    {
        RSABlindSignatureClient client = new RSABlindSignatureClient(
            RSABlindSignatureParameters.RSABSSA_SHA384_PSS_DETERMINISTIC, publicKey, new SecureRandom());

        // finalize takes a Blinded; produce a valid one, then feed a wrong-length blind_sig.
        RSABlindSignatureClient.Blinded blinded = client.blind(MSG);
        try
        {
            client.finalize(blinded, new byte[10]);
            fail("finalize accepted blind_sig of wrong length");
        }
        catch (Exception e)
        {
            isTrue("finalize wrong-length message",
                e.getMessage() != null && e.getMessage().indexOf("unexpected input size") >= 0);
        }

        RSABlindSignatureServer server = new RSABlindSignatureServer(privateKey);
        try
        {
            server.blindSign(new byte[10]);
            fail("BlindSign accepted blinded_msg of wrong length");
        }
        catch (Exception e)
        {
            isTrue("BlindSign wrong-length message",
                e.getMessage() != null && e.getMessage().indexOf("wrong length") >= 0);
        }
    }

    private void testMessageEdgeCases()
        throws Exception
    {
        RSAKeyParameters publicKey = new RSAKeyParameters(false, N, E);
        RSAPrivateCrtKeyParameters privateKey = makePrivateKey();
        RSABlindSignatureServer server = new RSABlindSignatureServer(privateKey);
        RSABlindSignatureParameters params = RSABlindSignatureParameters.RSABSSA_SHA384_PSS_DETERMINISTIC;

        // The 2-arg constructor exercises the CryptoServicesRegistrar default SecureRandom.
        RSABlindSignatureClient client = new RSABlindSignatureClient(params, publicKey);

        // A zero-length message is allowed: RFC 9474 / EMSA-PSS only bound the message length from
        // above, and hashing an empty input is well-defined — so an empty msg signs and verifies.
        RSABlindSignatureClient.Blinded blinded = client.blind(new byte[0]);
        byte[] sig = client.finalize(blinded, server.blindSign(blinded.getBlindedMessage()));
        PSSSigner verifier = new PSSSigner(new RSAEngine(), params.createDigest(), params.getSaltLength());
        verifier.init(false, publicKey);
        verifier.update(blinded.getPreparedMessage(), 0, blinded.getPreparedMessage().length);
        isTrue("empty message round-trip", verifier.verifySignature(sig));

        // A null message is rejected with the documented NPE.
        try
        {
            client.blind(null);
            fail("blind accepted a null message");
        }
        catch (NullPointerException e)
        {
            isTrue("null message rejected", "'msg' cannot be null".equals(e.getMessage()));
        }
    }

    private void testConstructorSecureRandom()
        throws Exception
    {
        RSAKeyParameters publicKey = new RSAKeyParameters(false, N, E);
        RSABlindSignatureParameters params = RSABlindSignatureParameters.RSABSSA_SHA384_PSS_RANDOMIZED;
        byte[] msg = Hex.decode("c0ffee");
        int modulusLen = BigIntegers.getUnsignedByteLength(N);

        // Both constructors yield a client whose blind() can draw randomness: the
        // (parameters, publicKey) form from the CryptoServicesRegistrar default, the 3-arg form
        // from the supplied SecureRandom.
        byte[] defaultRandom = new RSABlindSignatureClient(params, publicKey).blind(msg).getBlindedMessage();
        isTrue("2-arg constructor (default SecureRandom)", defaultRandom.length == modulusLen);

        byte[] suppliedRandom =
            new RSABlindSignatureClient(params, publicKey, new SecureRandom()).blind(msg).getBlindedMessage();
        isTrue("3-arg constructor (supplied SecureRandom)", suppliedRandom.length == modulusLen);

        // The 3-arg constructor rejects a null SecureRandom.
        try
        {
            new RSABlindSignatureClient(params, publicKey, null);
            fail("constructor accepted a null SecureRandom");
        }
        catch (NullPointerException e)
        {
            isTrue("null SecureRandom rejected", "'random' cannot be null".equals(e.getMessage()));
        }
    }

    private static RSAPrivateCrtKeyParameters makePrivateKey()
    {
        BigInteger one = BigInteger.ONE;
        BigInteger pMinus1 = P.subtract(one);
        BigInteger qMinus1 = Q.subtract(one);
        BigInteger dP = D.mod(pMinus1);
        BigInteger dQ = D.mod(qMinus1);
        BigInteger qInv = Q.modInverse(P);
        return new RSAPrivateCrtKeyParameters(N, E, D, P, Q, dP, dQ, qInv);
    }

    private static BigInteger bi(String hex)
    {
        return new BigInteger(1, hex(hex));
    }

    private static byte[] hex(String s)
    {
        return Hex.decode(s.replaceAll("\\s+", ""));
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    public static void main(String[] args)
    {
        runTest(new RSABlindSignatureTest());
    }
}
