package org.bouncycastle.crypto.hash2curve.test;

/**
 * Functions to obtain test vector data
 */
public class TestVectors {

  public static final TestVectorData P256_HTC_TEST_VECTOR_DATA;
  public static final TestVectorData P256_ETC_TEST_VECTOR_DATA;
  public static final TestVectorData P384_HTC_TEST_VECTOR_DATA;
  public static final TestVectorData P384_ETC_TEST_VECTOR_DATA;
  public static final TestVectorData P521_HTC_TEST_VECTOR_DATA;
  public static final TestVectorData P521_ETC_TEST_VECTOR_DATA;
  public static final TestVectorData curve25519_HTC_TEST_VECTOR_DATA;
  public static final TestVectorData curve25519_ETC_TEST_VECTOR_DATA;
  public static final TestVectorData curve448_TEST_VECTOR_DATA;
  public static final TestVectorData edwards25519_TEST_VECTOR_DATA;
  public static final TestVectorData edwards448_TEST_VECTOR_DATA;

  static {
    P256_HTC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x30")
        .Z("0xffffffff00000001000000000000000000000000fffffffffffffffffffffff5")
        .ciphersuite("P256_XMD:SHA-256_SSWU_RO_")
        .curve("NIST P-256")
        .dst("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_")
        .expand("XMD")
        .field("0x1",
            "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
        .hash("sha256")
        .k("0x80")
        .addMap("name", "SSWU")
        .randomOracle(true)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4")
                .addP("y", "0x8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415")
                .addQ0("x", "0xab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5")
                .addQ0("y", "0xdccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1")
                .addQ1("x", "0x51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5")
                .addQ1("y", "0xb45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac")
                .addU("0xad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")
                .addU("0x8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f")
                .addP("y", "0x5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e")
                .addQ0("x", "0x5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48")
                .addQ0("y", "0x7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d93ecf")
                .addQ1("x", "0x019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f")
                .addQ1("y", "0x589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4252715446e")
                .addU("0xafe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1")
                .addU("0x379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80")
                .addP("y", "0xcad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3")
                .addQ0("x", "0xa17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2")
                .addQ0("y", "0x4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e")
                .addQ1("x", "0x7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66")
                .addQ1("y", "0xb765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9")
                .addU("0x0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c")
                .addU("0xb68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d")
                .addP("y", "0x98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e")
                .addQ0("x", "0xc76aaa823aeadeb3f356909cb08f97eee46ecb157c1f56699b5efebddf0e6398")
                .addQ0("y", "0x776a6f45f528a0e8d289a4be12c4fab80762386ec644abf2bffb9b627e4352b1")
                .addQ1("x", "0x418ac3d85a5ccc4ea8dec14f750a3a9ec8b85176c95a7022f391826794eb5a75")
                .addQ1("y", "0xfd6604f69e9d9d2b74b072d14ea13050db72c932815523305cb9e807cc900aff")
                .addU("0x3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f6f8d805919")
                .addU("0x76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e3be1bf1d33")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5")
                .addP("y", "0xecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc")
                .addQ0("x", "0xd88b989ee9d1295df413d4456c5c850b8b2fb0f5402cc5c4c7e815412e926db8")
                .addQ0("y", "0xbb4a1edeff506cf16def96afff41b16fc74f6dbd55c2210e5b8f011ba32f4f40")
                .addQ1("x", "0xa281e34e628f3a4d2a53fa87ff973537d68ad4fbc28d3be5e8d9f6a2571c5a4b")
                .addQ1("y", "0xf6ed88a7aab56a488100e6f1174fa9810b47db13e86be999644922961206e184")
                .addU("0x4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee51adb29fec")
                .addU("0x4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d20b4e269ee")
                .build()
        )
        .build();

    P256_ETC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x30")
        .Z("0xffffffff00000001000000000000000000000000fffffffffffffffffffffff5")
        .ciphersuite("P256_XMD:SHA-256_SSWU_NU_")
        .curve("NIST P-256")
        .dst("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_")
        .expand("XMD")
        .field("0x1",
            "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
        .hash("sha256")
        .k("0x80")
        .addMap("name", "SSWU")
        .randomOracle(false)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0xf871caad25ea3b59c16cf87c1894902f7e7b2c822c3d3f73596c5ace8ddd14d1")
                .addP("y", "0x87b9ae23335bee057b99bac1e68588b18b5691af476234b8971bc4f011ddc99b")
                .addQ0("x", "0xf871caad25ea3b59c16cf87c1894902f7e7b2c822c3d3f73596c5ace8ddd14d1")
                .addQ0("y", "0x87b9ae23335bee057b99bac1e68588b18b5691af476234b8971bc4f011ddc99b")
                .addU("0xb22d487045f80e9edcb0ecc8d4bf77833e2bf1f3a54004d7df1d57f4802d311f")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0xfc3f5d734e8dce41ddac49f47dd2b8a57257522a865c124ed02b92b5237befa4")
                .addP("y", "0xfe4d197ecf5a62645b9690599e1d80e82c500b22ac705a0b421fac7b47157866")
                .addQ0("x", "0xfc3f5d734e8dce41ddac49f47dd2b8a57257522a865c124ed02b92b5237befa4")
                .addQ0("y", "0xfe4d197ecf5a62645b9690599e1d80e82c500b22ac705a0b421fac7b47157866")
                .addU("0xc7f96eadac763e176629b09ed0c11992225b3a5ae99479760601cbd69c221e58")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0xf164c6674a02207e414c257ce759d35eddc7f55be6d7f415e2cc177e5d8faa84")
                .addP("y", "0x3aa274881d30db70485368c0467e97da0e73c18c1d00f34775d012b6fcee7f97")
                .addQ0("x", "0xf164c6674a02207e414c257ce759d35eddc7f55be6d7f415e2cc177e5d8faa84")
                .addQ0("y", "0x3aa274881d30db70485368c0467e97da0e73c18c1d00f34775d012b6fcee7f97")
                .addU("0x314e8585fa92068b3ea2c3bab452d4257b38be1c097d58a21890456c2929614d")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x324532006312be4f162614076460315f7a54a6f85544da773dc659aca0311853")
                .addP("y", "0x8d8197374bcd52de2acfefc8a54fe2c8d8bebd2a39f16be9b710e4b1af6ef883")
                .addQ0("x", "0x324532006312be4f162614076460315f7a54a6f85544da773dc659aca0311853")
                .addQ0("y", "0x8d8197374bcd52de2acfefc8a54fe2c8d8bebd2a39f16be9b710e4b1af6ef883")
                .addU("0x752d8eaa38cd785a799a31d63d99c2ae4261823b4a367b133b2c6627f48858ab")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x5c4bad52f81f39c8e8de1260e9a06d72b8b00a0829a8ea004a610b0691bea5d9")
                .addP("y", "0xc801e7c0782af1f74f24fc385a8555da0582032a3ce038de637ccdcb16f7ef7b")
                .addQ0("x", "0x5c4bad52f81f39c8e8de1260e9a06d72b8b00a0829a8ea004a610b0691bea5d9")
                .addQ0("y", "0xc801e7c0782af1f74f24fc385a8555da0582032a3ce038de637ccdcb16f7ef7b")
                .addU("0x0e1527840b9df2dfbef966678ff167140f2b27c4dccd884c25014dce0e41dfa3")
                .build()
        )
        .build();

    P384_HTC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x48")
        .Z("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffff3")
        .ciphersuite("P384_XMD:SHA-384_SSWU_RO_")
        .curve("NIST P-384")
        .dst("QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_")
        .expand("XMD")
        .field("0x1",
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")
        .hash("sha384")
        .k("0xc0")
        .addMap("name", "SSWU")
        .randomOracle(true)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0xeb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83")
                .addP("y", "0x0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a")
                .addQ0("x", "0xe4717e29eef38d862bee4902a7d21b44efb58c464e3e1f0d03894d94de310f8ffc6de86786dd3e15a1541b18d4eb2846")
                .addQ0("y", "0x6b95a6e639822312298a47526bb77d9cd7bcf76244c991c8cd70075e2ee6e8b9a135c4a37e3c0768c7ca871c0ceb53d4")
                .addQ1("x", "0x509527cfc0750eedc53147e6d5f78596c8a3b7360e0608e2fab0563a1670d58d8ae107c9f04bcf90e89489ace5650efd")
                .addQ1("y", "0x33337b13cb35e173fdea4cb9e8cce915d836ff57803dbbeb7998aa49d17df2ff09b67031773039d09fbd9305a1566bc4")
                .addU("0x25c8d7dc1acd4ee617766693f7f8829396065d1b447eedb155871feffd9c6653279ac7e5c46edb7010a0e4ff64c9f3b4")
                .addU("0x59428be4ed69131df59a0c6a8e188d2d4ece3f1b2a3a02602962b47efa4d7905945b1e2cc80b36aa35c99451073521ac")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0xe02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81d413003c4d4e7fd59af0826dfaad4200ac6f60abe1")
                .addP("y", "0x01f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c04530d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6")
                .addQ0("x", "0xfc853b69437aee9a19d5acf96a4ee4c5e04cf7b53406dfaa2afbdd7ad2351b7f554e4bbc6f5db4177d4d44f933a8f6ee")
                .addQ0("y", "0x7e042547e01834c9043b10f3a8221c4a879cb156f04f72bfccab0c047a304e30f2aa8b2e260d34c4592c0c33dd0c6482")
                .addQ1("x", "0x57912293709b3556b43a2dfb137a315d256d573b82ded120ef8c782d607c05d930d958e50cb6dc1cc480b9afc38c45f1")
                .addQ1("y", "0xde9387dab0eef0bda219c6f168a92645a84665c4f2137c14270fb424b7532ff84843c3da383ceea24c47fa343c227bb8")
                .addU("0x53350214cb6bef0b51abb791b1c4209a2b4c16a0c67e1ab1401017fad774cd3b3f9a8bcdf7f6229dd8dd5a075cb149a0")
                .addU("0xc0473083898f63e03f26f14877a2407bd60c75ad491e7d26cbc6cc5ce815654075ec6b6898c7a41d74ceaf720a10c02e")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0xbdecc1c1d870624965f19505be50459d363c71a699a496ab672f9a5d6b78676400926fbceee6fcd1780fe86e62b2aa89")
                .addP("y", "0x57cf1f99b5ee00f3c201139b3bfe4dd30a653193778d89a0accc5e0f47e46e4e4b85a0595da29c9494c1814acafe183c")
                .addQ0("x", "0x0ceece45b73f89844671df962ad2932122e878ad2259e650626924e4e7f132589341dec1480ebcbbbe3509d11fb570b7")
                .addQ0("y", "0xfafd71a3115298f6be4ae5c6dfc96c400cfb55760f185b7b03f3fa45f3f91eb65d27628b3c705cafd0466fafa54883ce")
                .addQ1("x", "0xdea1be8d3f9be4cbf4fab9d71d549dde76875b5d9b876832313a083ec81e528cbc2a0a1d0596b3bcb0ba77866b129776")
                .addQ1("y", "0xeb15fe71662214fb03b65541f40d3eb0f4cf5c3b559f647da138c9f9b7484c48a08760e02c16f1992762cb7298fa52cf")
                .addU("0xaab7fb87238cf6b2ab56cdcca7e028959bb2ea599d34f68484139dde85ec6548a6e48771d17956421bdb7790598ea52e")
                .addU("0x26e8d833552d7844d167833ca5a87c35bcfaa5a0d86023479fb28e5cd6075c18b168bf1f5d2a0ea146d057971336d8d1")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x03c3a9f401b78c6c36a52f07eeee0ec1289f178adf78448f43a3850e0456f5dd7f7633dd31676d990eda32882ab486c0")
                .addP("y", "0xcc183d0d7bdfd0a3af05f50e16a3f2de4abbc523215bf57c848d5ea662482b8c1f43dc453a93b94a8026db58f3f5d878")
                .addQ0("x", "0x051a22105e0817a35d66196338c8d85bd52690d79bba373ead8a86dd9899411513bb9f75273f6483395a7847fb21edb4")
                .addQ0("y", "0xf168295c1bbcff5f8b01248e9dbc885335d6d6a04aea960f7384f746ba6502ce477e624151cc1d1392b00df0f5400c06")
                .addQ1("x", "0x6ad7bc8ed8b841efd8ad0765c8a23d0b968ec9aa360a558ff33500f164faa02bee6c704f5f91507c4c5aad2b0dc5b943")
                .addQ1("y", "0x47313cc0a873ade774048338fc34ca5313f96bbf6ae22ac6ef475d85f03d24792dc6afba8d0b4a70170c1b4f0f716629")
                .addU("0x04c00051b0de6e726d228c85bf243bf5f4789efb512b22b498cde3821db9da667199b74bd5a09a79583c6d353a3bb41c")
                .addU("0x97580f218255f899f9204db64cd15e6a312cb4d8182375d1e5157c8f80f41d6a1a4b77fb1ded9dce56c32058b8d5202b")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x7b18d210b1f090ac701f65f606f6ca18fb8d081e3bc6cbd937c5604325f1cdea4c15c10a54ef303aabf2ea58bd9947a4")
                .addP("y", "0xea857285a33abb516732915c353c75c576bf82ccc96adb63c094dde580021eddeafd91f8c0bfee6f636528f3d0c47fd2")
                .addQ0("x", "0x42e6666f505e854187186bad3011598d9278b9d6e3e4d2503c3d236381a56748dec5d139c223129b324df53fa147c4df")
                .addQ0("y", "0x8ee51dbda46413bf621838cc935d18d617881c6f33f3838a79c767a1e5618e34b22f79142df708d2432f75c7366c8512")
                .addQ1("x", "0x4ff01ceeba60484fa1bc0d825fe1e5e383d8f79f1e5bb78e5fb26b7a7ef758153e31e78b9d60ce75c5e32e43869d4e12")
                .addQ1("y", "0x0f84b978fac8ceda7304b47e229d6037d32062e597dc7a9b95bcd9af441f3c56c619a901d21635f9ec6ab4710b9fcd0e")
                .addU("0x480cb3ac2c389db7f9dac9c396d2647ae946db844598971c26d1afd53912a1491199c0a5902811e4b809c26fcd37a014")
                .addU("0xd28435eb34680e148bf3908536e42231cba9e1f73ae2c6902a222a89db5c49c97db2f8fa4d4cd6e424b17ac60bdb9bb6")
                .build()
        )
        .build();

    P384_ETC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x48")
        .Z("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffff3")
        .ciphersuite("P384_XMD:SHA-384_SSWU_NU_")
        .curve("NIST P-384")
        .dst("QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_")
        .expand("XMD")
        .field("0x1",
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff")
        .hash("sha384")
        .k("0xc0")
        .addMap("name", "SSWU")
        .randomOracle(false)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0xde5a893c83061b2d7ce6a0d8b049f0326f2ada4b966dc7e72927256b033ef61058029a3bfb13c1c7ececd6641881ae20")
                .addP("y", "0x63f46da6139785674da315c1947e06e9a0867f5608cf24724eb3793a1f5b3809ee28eb21a0c64be3be169afc6cdb38ca")
                .addQ0("x", "0xde5a893c83061b2d7ce6a0d8b049f0326f2ada4b966dc7e72927256b033ef61058029a3bfb13c1c7ececd6641881ae20")
                .addQ0("y", "0x63f46da6139785674da315c1947e06e9a0867f5608cf24724eb3793a1f5b3809ee28eb21a0c64be3be169afc6cdb38ca")
                .addU("0xbc7dc1b2cdc5d588a66de3276b0f24310d4aca4977efda7d6272e1be25187b001493d267dc53b56183c9e28282368e60")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x1f08108b87e703c86c872ab3eb198a19f2b708237ac4be53d7929fb4bd5194583f40d052f32df66afe5249c9915d139b")
                .addP("y", "0x1369dc8d5bf038032336b989994874a2270adadb67a7fcc32f0f8824bc5118613f0ac8de04a1041d90ff8a5ad555f96c")
                .addQ0("x", "0x1f08108b87e703c86c872ab3eb198a19f2b708237ac4be53d7929fb4bd5194583f40d052f32df66afe5249c9915d139b")
                .addQ0("y", "0x1369dc8d5bf038032336b989994874a2270adadb67a7fcc32f0f8824bc5118613f0ac8de04a1041d90ff8a5ad555f96c")
                .addU("0x9de6cf41e6e41c03e4a7784ac5c885b4d1e49d6de390b3cdd5a1ac5dd8c40afb3dfd7bb2686923bab644134483fc1926")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x4dac31ec8a82ee3c02ba2d7c9fa431f1e59ffe65bf977b948c59e1d813c2d7963c7be81aa6db39e78ff315a10115c0d0")
                .addP("y", "0x845333cdb5702ad5c525e603f302904d6fc84879f0ef2ee2014a6b13edd39131bfd66f7bd7cdc2d9ccf778f0c8892c3f")
                .addQ0("x", "0x4dac31ec8a82ee3c02ba2d7c9fa431f1e59ffe65bf977b948c59e1d813c2d7963c7be81aa6db39e78ff315a10115c0d0")
                .addQ0("y", "0x845333cdb5702ad5c525e603f302904d6fc84879f0ef2ee2014a6b13edd39131bfd66f7bd7cdc2d9ccf778f0c8892c3f")
                .addU("0x84e2d430a5e2543573e58e368af41821ca3ccc97baba7e9aab51a84543d5a0298638a22ceee6090d9d642921112af5b7")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x13c1f8c52a492183f7c28e379b0475486718a7e3ac1dfef39283b9ce5fb02b73f70c6c1f3dfe0c286b03e2af1af12d1d")
                .addP("y", "0x57e101887e73e40eab8963324ed16c177d55eb89f804ec9df06801579820420b5546b579008df2145fd770f584a1a54c")
                .addQ0("x", "0x13c1f8c52a492183f7c28e379b0475486718a7e3ac1dfef39283b9ce5fb02b73f70c6c1f3dfe0c286b03e2af1af12d1d")
                .addQ0("y", "0x57e101887e73e40eab8963324ed16c177d55eb89f804ec9df06801579820420b5546b579008df2145fd770f584a1a54c")
                .addU("0x504e4d5a529333b9205acaa283107bd1bffde753898f7744161f7dd19ba57fbb6a64214a2e00ddd2613d76cd508ddb30")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0xaf129727a4207a8cb9e9dce656d88f79fce25edbcea350499d65e9bf1204537bdde73c7cefb752a6ed5ebcd44e183302")
                .addP("y", "0xce68a3d5e161b2e6a968e4ddaa9e51504ad1516ec170c7eef3ca6b5327943eca95d90b23b009ba45f58b72906f2a99e2")
                .addQ0("x", "0xaf129727a4207a8cb9e9dce656d88f79fce25edbcea350499d65e9bf1204537bdde73c7cefb752a6ed5ebcd44e183302")
                .addQ0("y", "0xce68a3d5e161b2e6a968e4ddaa9e51504ad1516ec170c7eef3ca6b5327943eca95d90b23b009ba45f58b72906f2a99e2")
                .addU("0x7b01ce9b8c5a60d9fbc202d6dde92822e46915d8c17e03fcb92ece1ed6074d01e149fc9236def40d673de903c1d4c166")
                .build()
        )
        .build();

    P521_HTC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x62")
        .Z("0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb")
        .ciphersuite("P521_XMD:SHA-512_SSWU_RO_")
        .curve("NIST P-521")
        .dst("QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_")
        .expand("XMD")
        .field("0x1",
            "0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .hash("sha512")
        .k("0x100")
        .addMap("name", "SSWU")
        .randomOracle(true)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x00fd767cebb2452030358d0e9cf907f525f50920c8f607889a6a35680727f64f4d66b161fafeb2654bea0d35086bec0a10b30b14adef3556ed9f7f1bc23cecc9c088")
                .addP("y", "0x0169ba78d8d851e930680322596e39c78f4fe31b97e57629ef6460ddd68f8763fd7bd767a4e94a80d3d21a3c2ee98347e024fc73ee1c27166dc3fe5eeef782be411d")
                .addQ0("x", "0x00b70ae99b6339fffac19cb9bfde2098b84f75e50ac1e80d6acb954e4534af5f0e9c4a5b8a9c10317b8e6421574bae2b133b4f2b8c6ce4b3063da1d91d34fa2b3a3c")
                .addQ0("y", "0x007f368d98a4ddbf381fb354de40e44b19e43bb11a1278759f4ea7b485e1b6db33e750507c071250e3e443c1aaed61f2c28541bb54b1b456843eda1eb15ec2a9b36e")
                .addQ1("x", "0x01143d0e9cddcdacd6a9aafe1bcf8d218c0afc45d4451239e821f5d2a56df92be942660b532b2aa59a9c635ae6b30e803c45a6ac871432452e685d661cd41cf67214")
                .addQ1("y", "0x00ff75515df265e996d702a5380defffab1a6d2bc232234c7bcffa433cd8aa791fbc8dcf667f08818bffa739ae25773b32073213cae9a0f2a917a0b1301a242dda0c")
                .addU("0x01e5f09974e5724f25286763f00ce76238c7a6e03dc396600350ee2c4135fb17dc555be99a4a4bae0fd303d4f66d984ed7b6a3ba386093752a855d26d559d69e7e9e")
                .addU("0x00ae593b42ca2ef93ac488e9e09a5fe5a2f6fb330d18913734ff602f2a761fcaaf5f596e790bcc572c9140ec03f6cccc38f767f1c1975a0b4d70b392d95a0c7278aa")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x002f89a1677b28054b50d15e1f81ed6669b5a2158211118ebdef8a6efc77f8ccaa528f698214e4340155abc1fa08f8f613ef14a043717503d57e267d57155cf784a4")
                .addP("y", "0x010e0be5dc8e753da8ce51091908b72396d3deed14ae166f66d8ebf0a4e7059ead169ea4bead0232e9b700dd380b316e9361cfdba55a08c73545563a80966ecbb86d")
                .addQ0("x", "0x01b254e1c99c835836f0aceebba7d77750c48366ecb07fb658e4f5b76e229ae6ca5d271bb0006ffcc42324e15a6d3daae587f9049de2dbb0494378ffb60279406f56")
                .addQ0("y", "0x01845f4af72fc2b1a5a2fe966f6a97298614288b456cfc385a425b686048b25c952fbb5674057e1eb055d04568c0679a8e2dda3158dc16ac598dbb1d006f5ad915b0")
                .addQ1("x", "0x007f08e813c620e527c961b717ffc74aac7afccb9158cebc347d5715d5c2214f952c97e194f11d114d80d3481ed766ac0a3dba3eb73f6ff9ccb9304ad10bbd7b4a36")
                .addQ1("y", "0x0022468f92041f9970a7cc025d71d5b647f822784d29ca7b3bc3b0829d6bb8581e745f8d0cc9dc6279d0450e779ac2275c4c3608064ad6779108a7828ebd9954caeb")
                .addU("0x003d00c37e95f19f358adeeaa47288ec39998039c3256e13c2a4c00a7cb61a34c8969472960150a27276f2390eb5e53e47ab193351c2d2d9f164a85c6a5696d94fe8")
                .addU("0x01f3cbd3df3893a45a2f1fecdac4d525eb16f345b03e2820d69bc580f5cbe9cb89196fdf720ef933c4c0361fcfe29940fd0db0a5da6bafb0bee8876b589c41365f15")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x006e200e276a4a81760099677814d7f8794a4a5f3658442de63c18d2244dcc957c645e94cb0754f95fcf103b2aeaf94411847c24187b89fb7462ad3679066337cbc4")
                .addP("y", "0x001dd8dfa9775b60b1614f6f169089d8140d4b3e4012949b52f98db2deff3e1d97bf73a1fa4d437d1dcdf39b6360cc518d8ebcc0f899018206fded7617b654f6b168")
                .addQ0("x", "0x0021482e8622aac14da60e656043f79a6a110cbae5012268a62dd6a152c41594549f373910ebed170ade892dd5a19f5d687fae7095a461d583f8c4295f7aaf8cd7da")
                .addQ0("y", "0x0177e2d8c6356b7de06e0b5712d8387d529b848748e54a8bc0ef5f1475aa569f8f492fa85c3ad1c5edc51faf7911f11359bfa2a12d2ef0bd73df9cb5abd1b101c8b1")
                .addQ1("x", "0x00abeafb16fdbb5eb95095678d5a65c1f293291dfd20a3751dbe05d0a9bfe2d2eef19449fe59ec32cdd4a4adc3411177c0f2dffd0159438706159a1bbd0567d9b3d0")
                .addQ1("y", "0x007cc657f847db9db651d91c801741060d63dab4056d0a1d3524e2eb0e819954d8f677aa353bd056244a88f00017e00c3ce8beeedb4382d83d74418bd48930c6c182")
                .addU("0x00183ee1a9bbdc37181b09ec336bcaa34095f91ef14b66b1485c166720523dfb81d5c470d44afcb52a87b704dbc5c9bc9d0ef524dec29884a4795f55c1359945baf3")
                .addU("0x00504064fd137f06c81a7cf0f84aa7e92b6b3d56c2368f0a08f44776aa8930480da1582d01d7f52df31dca35ee0a7876500ece3d8fe0293cd285f790c9881c998d5e")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x01b264a630bd6555be537b000b99a06761a9325c53322b65bdc41bf196711f9708d58d34b3b90faf12640c27b91c70a507998e55940648caa8e71098bf2bc8d24664")
                .addP("y", "0x01ea9f445bee198b3ee4c812dcf7b0f91e0881f0251aab272a12201fd89b1a95733fd2a699c162b639e9acdcc54fdc2f6536129b6beb0432be01aa8da02df5e59aaa")
                .addQ0("x", "0x0005eac7b0b81e38727efcab1e375f6779aea949c3e409b53a1d37aa2acbac87a7e6ad24aafbf3c52f82f7f0e21b872e88c55e17b7fa21ce08a94ea2121c42c2eb73")
                .addQ0("y", "0x00a173b6a53a7420dbd61d4a21a7c0a52de7a5c6ce05f31403bef747d16cc8604a039a73bdd6e114340e55dacd6bea8e217ffbadfb8c292afa3e1b2afc839a6ce7bb")
                .addQ1("x", "0x01881e3c193a69e4d88d8180a6879b74782a0bc7e529233e9f84bf7f17d2f319c36920ffba26f9e57a1e045cc7822c834c239593b6e142a694aa00c757b0db79e5e8")
                .addQ1("y", "0x01558b16d396d866e476e001f2dd0758927655450b84e12f154032c7c2a6db837942cd9f44b814f79b4d729996ced61eec61d85c675139cbffe3fbf071d2c21cfecb")
                .addU("0x0159871e222689aad7694dc4c3480a49807b1eedd9c8cb4ae1b219d5ba51655ea5b38e2e4f56b36bf3e3da44a7b139849d28f598c816fe1bc7ed15893b22f63363c3")
                .addU("0x004ef0cffd475152f3858c0a8ccbdf7902d8261da92744e98df9b7fadb0a5502f29c5086e76e2cf498f47321434a40b1504911552ce44ad7356a04e08729ad9411f5")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x00c12bc3e28db07b6b4d2a2b1167ab9e26fc2fa85c7b0498a17b0347edf52392856d7e28b8fa7a2dd004611159505835b687ecf1a764857e27e9745848c436ef3925")
                .addP("y", "0x01cd287df9a50c22a9231beb452346720bb163344a41c5f5a24e8335b6ccc595fd436aea89737b1281aecb411eb835f0b939073fdd1dd4d5a2492e91ef4a3c55bcbd")
                .addQ0("x", "0x00041f6eb92af8777260718e4c22328a7d74203350c6c8f5794d99d5789766698f459b83d5068276716f01429934e40af3d1111a22780b1e07e72238d2207e5386be")
                .addQ0("y", "0x001c712f0182813942b87cab8e72337db017126f52ed797dd234584ac9ae7e80dfe7abea11db02cf1855312eae1447dbaecc9d7e8c880a5e76a39f6258074e1bc2e0")
                .addQ1("x", "0x0125c0b69bcf55eab49280b14f707883405028e05c927cd7625d4e04115bd0e0e6323b12f5d43d0d6d2eff16dbcf244542f84ec058911260dc3bb6512ab5db285fbd")
                .addQ1("y", "0x008bddfb803b3f4c761458eb5f8a0aee3e1f7f68e9d7424405fa69172919899317fb6ac1d6903a432d967d14e0f80af63e7035aaae0c123e56862ce969456f99f102")
                .addU("0x0033d06d17bc3b9a3efc081a05d65805a14a3050a0dd4dfb4884618eb5c73980a59c5a246b18f58ad022dd3630faa22889fbb8ba1593466515e6ab4aeb7381c26334")
                .addU("0x0092290ab99c3fea1a5b8fb2ca49f859994a04faee3301cefab312d34227f6a2d0c3322cf76861c6a3683bdaa2dd2a6daa5d6906c663e065338b2344d20e313f1114")
                .build()
        )
        .build();

    P521_ETC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x62")
        .Z("0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb")
        .ciphersuite("P521_XMD:SHA-512_SSWU_NU_")
        .curve("NIST P-521")
        .dst("QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_")
        .expand("XMD")
        .field("0x1",
            "0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .hash("sha512")
        .k("0x100")
        .addMap("name", "SSWU")
        .randomOracle(false)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x01ec604b4e1e3e4c7449b7a41e366e876655538acf51fd40d08b97be066f7d020634e906b1b6942f9174b417027c953d75fb6ec64b8cee2a3672d4f1987d13974705")
                .addP("y", "0x00944fc439b4aad2463e5c9cfa0b0707af3c9a42e37c5a57bb4ecd12fef9fb21508568aedcdd8d2490472df4bbafd79081c81e99f4da3286eddf19be47e9c4cf0e91")
                .addQ0("x", "0x01ec604b4e1e3e4c7449b7a41e366e876655538acf51fd40d08b97be066f7d020634e906b1b6942f9174b417027c953d75fb6ec64b8cee2a3672d4f1987d13974705")
                .addQ0("y", "0x00944fc439b4aad2463e5c9cfa0b0707af3c9a42e37c5a57bb4ecd12fef9fb21508568aedcdd8d2490472df4bbafd79081c81e99f4da3286eddf19be47e9c4cf0e91")
                .addU("0x01e4947fe62a4e47792cee2798912f672fff820b2556282d9843b4b465940d7683a986f93ccb0e9a191fbc09a6e770a564490d2a4ae51b287ca39f69c3d910ba6a4f")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x00c720ab56aa5a7a4c07a7732a0a4e1b909e32d063ae1b58db5f0eb5e09f08a9884bff55a2bef4668f715788e692c18c1915cd034a6b998311fcf46924ce66a2be9a")
                .addP("y", "0x003570e87f91a4f3c7a56be2cb2a078ffc153862a53d5e03e5dad5bccc6c529b8bab0b7dbb157499e1949e4edab21cf5d10b782bc1e945e13d7421ad8121dbc72b1d")
                .addQ0("x", "0x00c720ab56aa5a7a4c07a7732a0a4e1b909e32d063ae1b58db5f0eb5e09f08a9884bff55a2bef4668f715788e692c18c1915cd034a6b998311fcf46924ce66a2be9a")
                .addQ0("y", "0x003570e87f91a4f3c7a56be2cb2a078ffc153862a53d5e03e5dad5bccc6c529b8bab0b7dbb157499e1949e4edab21cf5d10b782bc1e945e13d7421ad8121dbc72b1d")
                .addU("0x0019b85ef78596efc84783d42799e80d787591fe7432dee1d9fa2b7651891321be732ddf653fa8fefa34d86fb728db569d36b5b6ed3983945854b2fc2dc6a75aa25b")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x00bcaf32a968ff7971b3bbd9ce8edfbee1309e2019d7ff373c38387a782b005dce6ceffccfeda5c6511c8f7f312f343f3a891029c5858f45ee0bf370aba25fc990cc")
                .addP("y", "0x00923517e767532d82cb8a0b59705eec2b7779ce05f9181c7d5d5e25694ef8ebd4696343f0bc27006834d2517215ecf79482a84111f50c1bae25044fe1dd77744bbd")
                .addQ0("x", "0x00bcaf32a968ff7971b3bbd9ce8edfbee1309e2019d7ff373c38387a782b005dce6ceffccfeda5c6511c8f7f312f343f3a891029c5858f45ee0bf370aba25fc990cc")
                .addQ0("y", "0x00923517e767532d82cb8a0b59705eec2b7779ce05f9181c7d5d5e25694ef8ebd4696343f0bc27006834d2517215ecf79482a84111f50c1bae25044fe1dd77744bbd")
                .addU("0x01dba0d7fa26a562ee8a9014ebc2cca4d66fd9de036176aca8fc11ef254cd1bc208847ab7701dbca7af328b3f601b11a1737a899575a5c14f4dca5aaca45e9935e07")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x001ac69014869b6c4ad7aa8c443c255439d36b0e48a0f57b03d6fe9c40a66b4e2eaed2a93390679a5cc44b3a91862b34b673f0e92c83187da02bf3db967d867ce748")
                .addP("y", "0x00d5603d530e4d62b30fccfa1d90c2206654d74291c1db1c25b86a051ee3fffc294e5d56f2e776853406bd09206c63d40f37ad8829524cf89ad70b5d6e0b4a3b7341")
                .addQ0("x", "0x001ac69014869b6c4ad7aa8c443c255439d36b0e48a0f57b03d6fe9c40a66b4e2eaed2a93390679a5cc44b3a91862b34b673f0e92c83187da02bf3db967d867ce748")
                .addQ0("y", "0x00d5603d530e4d62b30fccfa1d90c2206654d74291c1db1c25b86a051ee3fffc294e5d56f2e776853406bd09206c63d40f37ad8829524cf89ad70b5d6e0b4a3b7341")
                .addU("0x00844da980675e1244cb209dcf3ea0aabec23bd54b2cda69fff86eb3acc318bf3d01bae96e9cd6f4c5ceb5539df9a7ad7fcc5e9d54696081ba9782f3a0f6d14987e3")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x01801de044c517a80443d2bd4f503a9e6866750d2f94a22970f62d721f96e4310e4a828206d9cdeaa8f2d476705cc3bbc490a6165c687668f15ec178a17e3d27349b")
                .addP("y", "0x0068889ea2e1442245fe42bfda9e58266828c0263119f35a61631a3358330f3bb84443fcb54fcd53a1d097fccbe310489b74ee143fc2938959a83a1f7dd4a6fd395b")
                .addQ0("x", "0x01801de044c517a80443d2bd4f503a9e6866750d2f94a22970f62d721f96e4310e4a828206d9cdeaa8f2d476705cc3bbc490a6165c687668f15ec178a17e3d27349b")
                .addQ0("y", "0x0068889ea2e1442245fe42bfda9e58266828c0263119f35a61631a3358330f3bb84443fcb54fcd53a1d097fccbe310489b74ee143fc2938959a83a1f7dd4a6fd395b")
                .addU("0x01aab1fb7e5cd44ba4d9f32353a383cb1bb9eb763ed40b32bdd5f666988970205998c0e44af6e2b5f6f8e48e969b3f649cae3c6ab463e1b274d968d91c02f00cce91")
                .build()
        )
        .build();

    curve25519_HTC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x30")
        .Z("0x2")
        .ciphersuite("curve25519_XMD:SHA-512_ELL2_RO_")
        .curve("curve25519")
        .dst("QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_")
        .expand("XMD")
        .field("0x1", "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
        .hash("sha512")
        .k("0x80")
        .addMap("name", "ELL2")
        .randomOracle(true)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x2de3780abb67e861289f5749d16d3e217ffa722192d16bbd9d1bfb9d112b98c0")
                .addP("y", "0x3b5dc2a498941a1033d176567d457845637554a2fe7a3507d21abd1c1bd6e878")
                .addQ0("x", "0x36b4df0c864c64707cbf6cf36e9ee2c09a6cb93b28313c169be29561bb904f98")
                .addQ0("y", "0x6cd59d664fb58c66c892883cd0eb792e52055284dac3907dd756b45d15c3983d")
                .addQ1("x", "0x3fa114783a505c0b2b2fbeef0102853c0b494e7757f2a089d0daae7ed9a0db2b")
                .addQ1("y", "0x76c0fe7fec932aaafb8eefb42d9cbb32eb931158f469ff3050af15cfdbbeff94")
                .addU("0x005fe8a7b8fef0a16c105e6cadf5a6740b3365e18692a9c05bfbb4d97f645a6a")
                .addU("0x1347edbec6a2b5d8c02e058819819bee177077c9d10a4ce165aab0fd0252261a")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x2b4419f1f2d48f5872de692b0aca72cc7b0a60915dd70bde432e826b6abc526d")
                .addP("y", "0x1b8235f255a268f0a6fa8763e97eb3d22d149343d495da1160eff9703f2d07dd")
                .addQ0("x", "0x16b3d86e056b7970fa00165f6f48d90b619ad618791661b7b5e1ec78be10eac1")
                .addQ0("y", "0x4ab256422d84c5120b278cbdfc4e1facc5baadffeccecf8ee9bf3946106d50ca")
                .addQ1("x", "0x7ec29ddbf34539c40adfa98fcb39ec36368f47f30e8f888cc7e86f4d46e0c264")
                .addQ1("y", "0x10d1abc1cae2d34c06e247f2141ba897657fb39f1080d54f09ce0af128067c74")
                .addU("0x49bed021c7a3748f09fa8cdfcac044089f7829d3531066ac9e74e0994e05bc7d")
                .addU("0x5c36525b663e63389d886105cee7ed712325d5a97e60e140aba7e2ce5ae851b6")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x68ca1ea5a6acf4e9956daa101709b1eee6c1bb0df1de3b90d4602382a104c036")
                .addP("y", "0x2a375b656207123d10766e68b938b1812a4a6625ff83cb8d5e86f58a4be08353")
                .addQ0("x", "0x71de3dadfe268872326c35ac512164850860567aea0e7325e6b91a98f86533ad")
                .addQ0("y", "0x26a08b6e9a18084c56f2147bf515414b9b63f1522e1b6c5649f7d4b0324296ec")
                .addQ1("x", "0x5704069021f61e41779e2ba6b932268316d6d2a6f064f997a22fef16d1eaeaca")
                .addQ1("y", "0x50483c7540f64fb4497619c050f2c7fe55454ec0f0e79870bb44302e34232210")
                .addU("0x6412b7485ba26d3d1b6c290a8e1435b2959f03721874939b21782df17323d160")
                .addU("0x24c7b46c1c6d9a21d32f5707be1380ab82db1054fde82865d5c9e3d968f287b2")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x096e9c8bae6c06b554c1ee69383bb0e82267e064236b3a30608d4ed20b73ac5a")
                .addP("y", "0x1eb5a62612cafb32b16c3329794645b5b948d9f8ffe501d4e26b073fef6de355")
                .addQ0("x", "0x7a94d45a198fb5daa381f45f2619ab279744efdd8bd8ed587fc5b65d6cea1df0")
                .addQ0("y", "0x67d44f85d376e64bb7d713585230cdbfafc8e2676f7568e0b6ee59361116a6e1")
                .addQ1("x", "0x30506fb7a32136694abd61b6113770270debe593027a968a01f271e146e60c18")
                .addQ1("y", "0x7eeee0e706b40c6b5174e551426a67f975ad5a977ee2f01e8e20a6d612458c3b")
                .addU("0x5e123990f11bbb5586613ffabdb58d47f64bb5f2fa115f8ea8df0188e0c9e1b5")
                .addU("0x5e8553eb00438a0bb1e7faa59dec6d8087f9c8011e5fb8ed9df31cb6c0d4ac19")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg(
                    "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x1bc61845a138e912f047b5e70ba9606ba2a447a4dade024c8ef3dd42b7bbc5fe")
                .addP("y", "0x623d05e47b70e25f7f1d51dda6d7c23c9a18ce015fe3548df596ea9e38c69bf1")
                .addQ0("x", "0x02d606e2699b918ee36f2818f2bc5013e437e673c9f9b9cdc15fd0c5ee913970")
                .addQ0("y", "0x29e9dc92297231ef211245db9e31767996c5625dfbf92e1c8107ef887365de1e")
                .addQ1("x", "0x38920e9b988d1ab7449c0fa9a6058192c0c797bb3d42ac345724341a1aa98745")
                .addQ1("y", "0x24dcc1be7c4d591d307e89049fd2ed30aae8911245a9d8554bf6032e5aa40d3d")
                .addU("0x20f481e85da7a3bf60ac0fb11ed1d0558fc6f941b3ac5469aa8b56ec883d6d7d")
                .addU("0x017d57fd257e9a78913999a23b52ca988157a81b09c5442501d07fed20869465")
                .build()
        )

        .build();

    curve25519_ETC_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x30")
        .Z("0x2")
        .ciphersuite("curve25519_XMD:SHA-512_ELL2_NU_")
        .curve("curve25519")
        .dst("QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_NU_")
        .expand("XMD")
        .field("0x1",
            "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
        .hash("sha512")
        .k("0x80")
        .addMap("name", "ELL2")
        .randomOracle(false)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x1bb913f0c9daefa0b3375378ffa534bda5526c97391952a7789eb976edfe4d08")
                .addP("y", "0x4548368f4f983243e747b62a600840ae7c1dab5c723991f85d3a9768479f3ec4")
                .addQ0("x", "0x51125222da5e763d97f3c10fcc92ea6860b9ccbbd2eb1285728f566721c1e65b")
                .addQ0("y", "0x343d2204f812d3dfc5304a5808c6c0d81a903a5d228b342442aa3c9ba5520a3d")
                .addU("0x608d892b641f0328523802a6603427c26e55e6f27e71a91a478148d45b5093cd")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x7c22950b7d900fa866334262fcaea47a441a578df43b894b4625c9b450f9a026")
                .addP("y", "0x5547bc00e4c09685dcbc6cb6765288b386d8bdcb595fa5a6e3969e08097f0541")
                .addQ0("x", "0x7d56d1e08cb0ccb92baf069c18c49bb5a0dcd927eff8dcf75ca921ef7f3e6eeb")
                .addQ0("y", "0x404d9a7dc25c9c05c44ab9a94590e7c3fe2dcec74533a0b24b188a5d5dacf429")
                .addU("0x46f5b22494bfeaa7f232cc8d054be68561af50230234d7d1d63d1d9abeca8da5")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x31ad08a8b0deeb2a4d8b0206ca25f567ab4e042746f792f4b7973f3ae2096c52")
                .addP("y", "0x405070c28e78b4fa269427c82827261991b9718bd6c6e95d627d701a53c30db1")
                .addQ0("x", "0x3fbe66b9c9883d79e8407150e7c2a1c8680bee496c62fabe4619a72b3cabe90f")
                .addQ0("y", "0x08ec476147c9a0a3ff312d303dbbd076abb7551e5fce82b48ab14b433f8d0a7b")
                .addU("0x235fe40c443766ce7e18111c33862d66c3b33267efa50d50f9e8e5d252a40aaa")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x027877759d155b1997d0d84683a313eb78bdb493271d935b622900459d52ceaa")
                .addP("y", "0x54d691731a53baa30707f4a87121d5169fb5d587d70fb0292b5830dedbec4c18")
                .addQ0("x", "0x227e0bb89de700385d19ec40e857db6e6a3e634b1c32962f370d26f84ff19683")
                .addQ0("y", "0x5f86ff3851d262727326a32c1bf7655a03665830fa7f1b8b1e5a09d85bc66e4a")
                .addU("0x001e92a544463bda9bd04ddbe3d6eed248f82de32f522669efc5ddce95f46f5b")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x5fd892c0958d1a75f54c3182a18d286efab784e774d1e017ba2fb252998b5dc1")
                .addP("y", "0x750af3c66101737423a4519ac792fb93337bd74ee751f19da4cf1e94f4d6d0b8")
                .addQ0("x", "0x3bcd651ee54d5f7b6013898aab251ee8ecc0688166fce6e9548d38472f6bd196")
                .addQ0("y", "0x1bb36ad9197299f111b4ef21271c41f4b7ecf5543db8bb5931307ebdb2eaa465")
                .addU("0x1a68a1af9f663592291af987203393f707305c7bac9c8d63d6a729bdc553dc19")
                .build()
        )
        .build();

    curve448_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x54")
        .Z("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffe")
        .ciphersuite("curve448_XOF:SHAKE256_ELL2_RO_")
        .curve("curve448")
        .dst("QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_RO_")
        .expand("XOF")
        .field("0x1",
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .hash("shake_256")
        .k("0xe0")
        .addMap("name", "ELL2")
        .randomOracle(true)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x5ea5ff623d27c75e73717514134e73e419f831a875ca9e82915fdfc7069d0a9f8b532cfb32b1d8dd04ddeedbe3fa1d0d681c01e825d6a9ea")
                .addP("y", "0xafadd8de789f8f8e3516efbbe313a7eba364c939ecba00dabf4ced5c563b18e70a284c17d8f46b564c4e6ce11784a3825d941116622128c1")
                .addQ0("x", "0x3ba318806f89c19cc019f51e33eb6b8c038dab892e858ce7c7f2c2ac58618d06146a5fef31e49af49588d4d3db1bcf02bd4e4a733e37065d")
                .addQ0("y", "0xb30b4cfc2fd14d9d4b70456c0f5c6f6070be551788893d570e7955675a20f6c286d01d6e90d2fb500d2efb8f4e18db7f8268bb9b7fbc5975")
                .addQ1("x", "0xf03a48cf003f63be61ca055fec87c750434da07a15f8aa6210389ff85943b5166484339c8bea1af9fc571313d35ed2fbb779408b760c4cbd")
                .addQ1("y", "0x23943a33b2954dc54b76a8222faf5b7e18405a41f5ecc61bf1b8df1f9cbfad057307ed0c7b721f19c0390b8ee3a2dec223671f9ff905fda7")
                .addU("0xc704c7b3d3b36614cf3eedd0324fe6fe7d1402c50efd16cff89ff63f50938506280d3843478c08e24f7842f4e3ef45f6e3c4897f9d976148")
                .addU("0xc25427dc97fff7a5ad0a78654e2c6c27b1c1127b5b53c7950cd1fd6edd2703646b25f341e73deedfebf022d1d3cecd02b93b4d585ead3ed7")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x9b2f7ce34878d7cebf34c582db14958308ea09366d1ec71f646411d3de0ae564d082b06f40cd30dfc08d9fb7cb21df390cf207806ad9d0e4")
                .addP("y", "0x138a0eef0a4993ea696152ed7db61f7ddb4e8100573591e7466d61c0c568ecaec939e36a84d276f34c402526d8989a96e99760c4869ed633")
                .addQ0("x", "0x26714783887ec444fbade9ae350dc13e8d5a64150679232560726a73d36e28bd56766d7d0b0899d79c8d1c889ae333f601c57532ff3c4f09")
                .addQ0("y", "0x080e486f8f5740dbbe82305160cab9fac247b0b22a54d961de675037c3036fa68464c8756478c322ae0aeb9ba386fe626cebb0bcca46840c")
                .addQ1("x", "0x0d9741d10421691a8ebc7778b5f623260fdf8b28ae28d776efcb8e0d5fbb65139a2f828617835f527cb2ca24a8f5fc8e84378343c43d096d")
                .addQ1("y", "0x54f4c499bf3d5b154511913f9615bd914969b65cfb74508d7ae5a169e9595b7cbcab9a1485e07b2ce426e4fbed052f03842c4313b7dbe39a")
                .addU("0x2dd95593dfee26fe0d218d3d9a0a23d9e1a262fd1d0b602483d08415213e75e2db3c69b0a5bc89e71bcefc8c723d2b6a0cf263f02ad2aa70")
                .addU("0x272e4c79a1290cc6d2bc4f4f9d31bf7fbe956ca303c04518f117d77c0e9d850796fc3e1e2bcb9c75e8eaaded5e150333cae9931868047c9d")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0xf54ecd14b85a50eeeee0618452df3a75be7bfba11da5118774ae4ea55ac204e153f77285d780c4acee6c96abe3577a0c0b00be6e790cf194")
                .addP("y", "0x935247a64bf78c107069943c7e3ecc52acb27ce4a3230407c8357341685ea2152e8c3da93f8cd77da1bddb5bb759c6e7ae7d516dced42850")
                .addQ0("x", "0x946d91bd50c90ef70743e0dd194bddd68bb630f4e67e5b93e15a9b94e62cb85134467993501759525c1f4fdbf06f10ddaf817847d735e062")
                .addQ0("y", "0x185cf511262ec1e9b3c3cbdc015ab93df4e71cbe87766917d81c9f3419d480407c1462385122c84982d4dae60c3ae4acce0089e37ad65934")
                .addQ1("x", "0x01778f4797b717cd6f83c193b2dfb92a1606a36ede941b0f6ab0ac71ad0eac756d17604bf054398887da907e41065d3595f178ae802f2087")
                .addQ1("y", "0xb4ca727d0bda895e0eee7eb3cbc28710fa2e90a73b568cae26bd7c2e73b70a9fa0affe1096f0810198890ed65d8935886b6e60dc4c569dc6")
                .addU("0x6aab71a38391639f27e49eae8b1cb6b7172a1f478190ece293957e7cdb2391e7cc1c4261970d9c1bbf9c3915438f74fbd7eb5cd4d4d17ace")
                .addU("0xc80b8380ca47a3bcbf76caa75cef0e09f3d270d5ee8f676cde11aedf41aaca6741bd81a86232bd336ccb42efad39f06542bc06a67b65909e")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x5bd67c4f88adf6beb10f7e0d0054659776a55c97b809ec8b3101729e104fd0f684e103792f267fd87cc4afc25a073956ef4f268fb02824d5")
                .addP("y", "0xda1f5cb16a352719e4cb064cf47ba72aeba7752d03e8ca2c56229f419b4ef378785a5af1a53dd7ab4d467c1f92f7b139b3752faf29c96432")
                .addQ0("x", "0xc2d275826d6ad55e41a22318f6b6240f1f862a2e231120ff41eadbec319756032e8cef2a7ac6c10214fa0608c17fcaf61ec2694a8a2b358b")
                .addQ0("y", "0x93d2e092762b135509840e609d413200df800d99da91d8b82840666cac30e7a3520adbaa4b089bfdc86132e42729f651d022f4782502f12c")
                .addQ1("x", "0x3c0880ece7244036e9a45944a85599f9809d772f770cc237ac41b21aa71615e4f3bb08f64fca618896e4f6cf5bd92e16b89d2cf6e1956bfb")
                .addQ1("y", "0x45cce4beb96505cac5976b3d2673641e9bcd18d3462bbb453d293e5282740a6389cfeae610adc7bd425c728541ceec83fcc999164af43fb5")
                .addU("0xcb5c27e51f9c18ee8ffdb6be230f4eb4f2c2481963b2293484f08da2241c1ff59f80978e6defe9d70e34abba2fcbe12dc3a1eb2c5d3d2e4a")
                .addU("0xc895e8afecec5466e126fa70fc4aa784b8009063afb10e3ee06a9b22318256aa8693b0c85b955cf2d6540b8ed71e729af1b8d5ca3b116cd7")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0xea441c10b3636ecedd5c0dfcae96384cc40de8390a0ab648765b4508da12c586d55dc981275776507ebca0e4d1bcaa302bb69dcfa31b3451")
                .addP("y", "0xfee0192d49bcc0c28d954763c2cbe739b9265c4bebe3883803c64971220cfda60b9ac99ad986cd908c0534b260b5cfca46f6c2b0f3f21bda")
                .addQ0("x", "0x4321ab02a9849128691e9b80a5c5576793a218de14885fddccb91f17ceb1646ea00a28b69ad211e1f14f17739612dbde3782319bdf009689")
                .addQ0("y", "0x1b8a7b539519eec0ea9f7a46a43822e16cba39a439733d6847ac44a806b8adb3e1a75ea48a1228b8937ba85c6cb6ee01046e10cad8953b1e")
                .addQ1("x", "0x126d744da6a14fddec0f78a9cee4571c1320ac7645b600187812e4d7021f98fc4703732c54daec787206e1f34d9dbbf4b292c68160b8bfbd")
                .addQ1("y", "0x136eebe6020f2389d448923899a1a38a4c8ad74254e0686e91c4f93c1f8f8e1bd619ffb7c1281467882a9c957d22d50f65c5b72b2aee11af")
                .addU("0x8cba93a007bb2c801b1769e026b1fa1640b14a34cf3029db3c7fd6392745d6fec0f7870b5071d6da4402cedbbde28ae4e50ab30e1049a238")
                .addU("0x4223746145069e4b8a981acc3404259d1a2c3ecfed5d864798a89d45f81a2c59e2d40eb1d5f0fe11478cbb2bb30246dd388cb932ad7bb330")
                .build()
        )
        .build();

    edwards25519_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x30")
        .Z("0x2")
        .ciphersuite("edwards25519_XMD:SHA-512_ELL2_RO_")
        .curve("edwards25519")
        .dst("QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_")
        .expand("XMD")
        .field("0x1", "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
        .hash("sha512")
        .k("0x80")
        .addMap("name", "ELL2")
        .randomOracle(true)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x3c3da6925a3c3c268448dcabb47ccde5439559d9599646a8260e47b1e4822fc6")
                .addP("y", "0x09a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21")
                .addQ0("x", "0x6549118f65bb617b9e8b438decedc73c496eaed496806d3b2eb9ee60b88e09a7")
                .addQ0("y", "0x7315bcc8cf47ed68048d22bad602c6680b3382a08c7c5d3f439a973fb4cf9feb")
                .addQ1("x", "0x31dcfc5c58aa1bee6e760bf78cbe71c2bead8cebb2e397ece0f37a3da19c9ed2")
                .addQ1("y", "0x7876d81474828d8a5928b50c82420b2bd0898d819e9550c5c82c39fc9bafa196")
                .addU("0x03fef4813c8cb5f98c6eef88fae174e6e7d5380de2b007799ac7ee712d203f3a")
                .addU("0x780bdddd137290c8f589dc687795aafae35f6b674668d92bf92ae793e6a60c75")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x608040b42285cc0d72cbb3985c6b04c935370c7361f4b7fbdb1ae7f8c1a8ecad")
                .addP("y", "0x1a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531")
                .addQ0("x", "0x5c1525bd5d4b4e034512949d187c39d48e8cd84242aa4758956e4adc7d445573")
                .addQ0("y", "0x2bf426cf7122d1a90abc7f2d108befc2ef415ce8c2d09695a7407240faa01f29")
                .addQ1("x", "0x37b03bba828860c6b459ddad476c83e0f9285787a269df2156219b7e5c86210c")
                .addQ1("y", "0x285ebf5412f84d0ad7bb4e136729a9ffd2195d5b8e73c0dc85110ce06958f432")
                .addU("0x5081955c4141e4e7d02ec0e36becffaa1934df4d7a270f70679c78f9bd57c227")
                .addU("0x005bdc17a9b378b6272573a31b04361f21c371b256252ae5463119aa0b925b76")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x6d7fabf47a2dc03fe7d47f7dddd21082c5fb8f86743cd020f3fb147d57161472")
                .addP("y", "0x53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6")
                .addQ0("x", "0x3ac463dd7fddb773b069c5b2b01c0f6b340638f54ee3bd92d452fcec3015b52d")
                .addQ0("y", "0x7b03ba1e8db9ec0b390d5c90168a6a0b7107156c994c674b61fe696cbeb46baf")
                .addQ1("x", "0x0757e7e904f5e86d2d2f4acf7e01c63827fde2d363985aa7432106f1b3a444ec")
                .addQ1("y", "0x50026c96930a24961e9d86aa91ea1465398ff8e42015e2ec1fa397d416f6a1c0")
                .addU("0x285ebaa3be701b79871bcb6e225ecc9b0b32dff2d60424b4c50642636a78d5b3")
                .addU("0x2e253e6a0ef658fedb8e4bd6a62d1544fd6547922acb3598ec6b369760b81b31")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0x5fb0b92acedd16f3bcb0ef83f5c7b7a9466b5f1e0d8d217421878ea3686f8524")
                .addP("y", "0x2eca15e355fcfa39d2982f67ddb0eea138e2994f5956ed37b7f72eea5e89d2f7")
                .addQ0("x", "0x703e69787ea7524541933edf41f94010a201cc841c1cce60205ec38513458872")
                .addQ0("y", "0x32bb192c4f89106466f0874f5fd56a0d6b6f101cb714777983336c159a9bec75")
                .addQ1("x", "0x0c9077c5c31720ed9413abe59bf49ce768506128d810cb882435aa90f713ef6b")
                .addQ1("y", "0x7d5aec5210db638c53f050597964b74d6dda4be5b54fa73041bf909ccb3826cb")
                .addU("0x4fedd25431c41f2a606952e2945ef5e3ac905a42cf64b8b4d4a83c533bf321af")
                .addU("0x02f20716a5801b843987097a8276b6d869295b2e11253751ca72c109d37485a9")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x0efcfde5898a839b00997fbe40d2ebe950bc81181afbd5cd6b9618aa336c1e8c")
                .addP("y", "0x6dc2fc04f266c5c27f236a80b14f92ccd051ef1ff027f26a07f8c0f327d8f995")
                .addQ0("x", "0x21091b2e3f9258c7dfa075e7ae513325a94a3d8a28e1b1cb3b5b6f5d65675592")
                .addQ0("y", "0x41a33d324c89f570e0682cdf7bdb78852295daf8084c669f2cc9692896ab5026")
                .addQ1("x", "0x4c07ec48c373e39a23bd7954f9e9b66eeab9e5ee1279b867b3d5315aa815454f")
                .addQ1("y", "0x67ccac7c3cb8d1381242d8d6585c57eabaddbb5dca5243a68a8aeb5477d94b3a")
                .addU("0x6e34e04a5106e9bd59f64aba49601bf09d23b27f7b594e56d5de06df4a4ea33b")
                .addU("0x1c1c2cb59fc053f44b86c5d5eb8c1954b64976d0302d3729ff66e84068f5fd96")
                .build()
        )
        .build();

    edwards448_TEST_VECTOR_DATA = TestVectorData.builder()
        .L("0x54")
        .Z("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffe")
        .ciphersuite("edwards448_XOF:SHAKE256_ELL2_RO_")
        .curve("edwards448")
        .dst("QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_")
        .expand("XOF")
        .field("0x1",
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .hash("shake_256")
        .k("0xe0")
        .addMap("name", "ELL2")
        .randomOracle(true)

        // ---- Vector 1 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("")
                .addP("x", "0x73036d4a88949c032f01507005c133884e2f0d81f9a950826245dda9e844fc78186c39daaa7147ead3e462cff60e9c6340b58134480b4d17")
                .addP("y", "0x94c1d61b43728e5d784ef4fcb1f38e1075f3aef5e99866911de5a234f1aafdc26b554344742e6ba0420b71b298671bbeb2b7736618634610")
                .addQ0("x", "0xc08177330869db17fb81a5e6e53b36d29086d806269760f2e4cabaa4015f5dbadb7ca2ba594d96a89d0ca4f0944489e1ef393d53db85096f")
                .addQ0("y", "0x02e894598c050eeb7195f5791f1a5f65da3776b7534be37640bcbf95d4b915bd22333c50387583507169708fbd7bea0d7aa385dcc614be9c")
                .addQ1("x", "0x770877fd3b6c5503398157b68a9d3609f585f40e1ebebdd69bb0e4d3d9aa811995ce75333fdadfa50db886a35959cc59cffd5c9710daca25")
                .addQ1("y", "0xb27fef77aa6231fbbc27538fa90eaca8abd03eb1e62fdae4ec5e828117c3b8b3ff8c34d0a6e6d79fff16d339b94ae8ede33331d5b464c792")
                .addU("0x0847c5ebf957d3370b1f98fde499fb3e659996d9fc9b5707176ade785ba72cd84b8a5597c12b1024be5f510fa5ba99642c4cec7f3f69d3e7")
                .addU("0xf8cbd8a7ae8c8deed071f3ac4b93e7cfcb8f1eac1645d699fd6d3881cb295a5d3006d9449ed7cad412a77a1fe61e84a9e41d59ef384d6f9a")
                .build()
        )

        // ---- Vector 2 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abc")
                .addP("x", "0x4e0158acacffa545adb818a6ed8e0b870e6abc24dfc1dc45cf9a052e98469275d9ff0c168d6a5ac7ec05b742412ee090581f12aa398f9f8c")
                .addP("y", "0x894d3fa437b2d2e28cdc3bfaade035430f350ec5239b6b406b5501da6f6d6210ff26719cad83b63e97ab26a12df6dec851d6bf38e294af9a")
                .addQ0("x", "0x7544612a97f4419c94ab0f621a1ee8ccf46c6657b8e0778ec9718bf4b41bc774487ad87d9b1e617aa49d3a4dd35a3cf57cd390ebf0429952")
                .addQ0("y", "0xd3ab703e60267d796b485bb58a28f934bd0133a6d1bbdfeda5277fa293310be262d7f653a5adffa608c37ed45c0e6008e54a16e1a342e4df")
                .addQ1("x", "0x6262f18d064bc131ade1b8bbcf1cbdf984f4f88153fcc9f94c888af35d5e41aae84c12f169a55d8abf06e6de6c5b23079e587a58cf73303e")
                .addQ1("y", "0x6d57589e901abe7d947c93ab02c307ad9093ed9a83eb0b6e829fb7318d590381ca25f3cc628a36a924a9ddfcf3cbedf94edf3b338ea77403")
                .addU("0x04d975cd938ab49be3e81703d6a57cca84ed80d2ff6d4756d3f22947fb5b70ab0231f0087cbfb4b7cae73b41b0c9396b356a4831d9a14322")
                .addU("0x2547ca887ac3db7b5fad3a098aa476e90078afe1358af6c63d677d6edfd2100bc004e0f5db94dd2560fc5b308e223241d00488c9ca6b0ef2")
                .build()
        )

        // ---- Vector 3 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("abcdef0123456789")
                .addP("x", "0x2c25b4503fadc94b27391933b557abdecc601c13ed51c5de68389484f93dbd6c22e5f962d9babf7a39f39f994312f8ca23344847e1fbf176")
                .addP("y", "0xd5e6f5350f430e53a110f5ac7fcc82a96cb865aeca982029522d32601e41c042a9dfbdfbefa2b0bdcdc3bc58cca8a7cd546803083d3a8548")
                .addQ0("x", "0x1457b60c12e00e47ceb3ce64b57e7c3c61636475443d704a8e2b2ab0a5ac7e4b3909435416784e16e19929c653b1bdcd9478a8e5331ca9ae")
                .addQ0("y", "0x935d9f75f7a0babbc39c0a1c3b412518ed8a24bc2c4886722fb4b7d4a747af98e4e2528c75221e2dffd3424abb436e10539a74caaafa3ea3")
                .addQ1("x", "0xb44d9e34211b4028f24117e856585ed81448f3c8b934987a1c5939c86048737a08d85934fec6b3c2ef9f09cbd365cf22744f2e4ce69762a4")
                .addQ1("y", "0xdc996c1736f4319868f897d9a27c45b02dd3bc6b7ca356a039606e5406e131a0bbe8238208b327b00853e8af84b58b13443e705425563323")
                .addU("0x10659ce25588db4e4be6f7c791a79eb21a7f24aaaca76a6ca3b83b80aaf95aa328fe7d569a1ac99f9cd216edf3915d72632f1a8b990e250c")
                .addU("0x9243e5b6c480683fd533e81f4a778349a309ce00bd163a29eb9fa8dbc8f549242bef33e030db21cffacd408d2c4264b93e476c6a8590e7aa")
                .build()
        )

        // ---- Vector 4 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
                .addP("x", "0xa1861a9464ae31249a0e60bf38791f3663049a3f5378998499a83292e159a2fecff838eb9bc6939e5c6ae76eb074ad4aae39b55b72ca0b9a")
                .addP("y", "0x580a2798c5b904f8adfec5bd29fb49b4633cd9f8c2935eb4a0f12e5dfa0285680880296bb729c6405337525fb5ed3dff930c137314f60401")
                .addQ0("x", "0x9d355251e245e4b13ed4ea3e5a3c55bf9b7211f1704771f2e1d8f1a65610c468b1cf70c6c2ce30dcaad54ad9e5439471ec554b862ec8875a")
                .addQ0("y", "0x6689ba36a242af69ac2aadb955d15e982d9b04f5d77f7609ebf7429587feb7e5ce27490b9c72114509f89565122074e46a614d7fd7c800bd")
                .addQ1("x", "0xc4b3d3ad4d2d62739a62989532992c1081e9474a201085b4616da5706cab824693b9fb428a201bcd1639a4588cc43b9eb841dbca74219b1f")
                .addQ1("y", "0x265286f5dee8f3d894b5649da8565b58e96b4cfd44b462a2883ea64dbcda21a00706ea3fea53fc2d769084b0b74589e91d0384d7118909fb")
                .addU("0xc80390020e578f009ead417029eff6cd0926110922db63ab98395e3bdfdd5d8a65b1a2b8d495dc8c5e59b7f3518731f7dfc0f93ace5dee4b")
                .addU("0x1c4dc6653a445bbef2add81d8e90a6c8591a788deb91d0d3f1519a2e4a460313041b77c1b0817f2e80b388e5c3e49f37d787dc1f85e4324a")
                .build()
        )

        // ---- Vector 5 ----
        .addVector(
            TestVectorData.Vector.builder()
                .msg("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .addP("x", "0x987c5ac19dd4b47835466a50b2d9feba7c8491b8885a04edf577e15a9f2c98b203ec2cd3e5390b3d20bba0fa6fc3eecefb5029a317234401")
                .addP("y", "0x5e273fcfff6b007bb6771e90509275a71ff1480c459ded26fc7b10664db0a68aaa98bc7ecb07e49cf05b80ae5ac653fbdd14276bbd35ccbc")
                .addQ0("x", "0xd1a5eba4a332514b69760948af09ceaeddbbb9fd4cb1f19b78349c2ee4cf9ee86dbcf9064659a4a0566fe9c34d90aec86f0801edc131ad9b")
                .addQ0("y", "0x5d0a75a3014c3269c33b1b5da80706a4f097893461df286353484d8031cd607c98edc2a846c77a841f057c7251eb45077853c7b205957e52")
                .addQ1("x", "0x69583b00dc6b2aced6ffa44630cc8c8cd0dd0649f57588dd0fb1daad2ce132e281d01e3f25ccd3f405be759975c6484268bfe8f5e5f23c30")
                .addQ1("y", "0x8418484035f60bdccf48cb488634c2dfb40272123435f7e654fb6f254c6c42e7e38f1fa79a637a168a28de6c275232b704f9ded0ff76dd94")
                .addU("0x163c79ab0210a4b5e4f44fb19437ea965bf5431ab233ef16606f0b03c5f16a3feb7d46a5a675ce8f606e9c2bf74ee5336c54a1e54919f13f")
                .addU("0xf99666bde4995c4088333d6c2734687e815f80a99c6da02c47df4b51f6c9d9ed466b4fecf7d9884990a8e0d0be6907fa437e0b1a27f49265")
                .build()
        )
        .build();
  }

}


