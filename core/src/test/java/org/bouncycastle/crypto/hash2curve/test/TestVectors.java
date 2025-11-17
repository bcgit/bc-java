package org.bouncycastle.crypto.hash2curve.test;

/**
 * Functions to obtain test vector data
 */
public class TestVectors {

  public static final TestVectorData P256_TEST_VECTOR_DATA;
  public static final TestVectorData P384_TEST_VECTOR_DATA;
  public static final TestVectorData P521_TEST_VECTOR_DATA;
  public static final TestVectorData curve25519_TEST_VECTOR_DATA;

  static {
    P256_TEST_VECTOR_DATA = TestVectorData.builder()
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

    P384_TEST_VECTOR_DATA = TestVectorData.builder()
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

    P521_TEST_VECTOR_DATA = TestVectorData.builder()
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

    curve25519_TEST_VECTOR_DATA = TestVectorData.builder()
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
  }

}


