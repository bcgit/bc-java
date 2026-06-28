package org.bouncycastle.pqc.crypto.aimer;

/**
 * Parameter set for the AIMer PQC signature scheme (KpqC Round 2 submission).
 * The six NIST submission variants are exposed as the {@link #aimer128f},
 * {@link #aimer128s}, {@link #aimer192f}, {@link #aimer192s}, {@link #aimer256f}
 * and {@link #aimer256s} constants, covering NIST security categories 1/3/5 in
 * fast and short trade-off flavours.
 */
public class AIMerParameters
{
    private static final long[][] aim2_constants_128 = {
        {0x13198a2e03707344L, 0x243f6a8885a308d3L},
        {0x082efa98ec4e6c89L, 0xa4093822299f31d0L}
    };

    private static final long[][] aim2_e1_power_matrix_128 =
        {
            {0x0000000000000001L, 0x0000000000000000L},
            {0xb87c1159421de6c0L, 0xfbcf8c1e442c8cf5L},
            {0x687634c0bd8f66a6L, 0x4d328e5ae8b1bde5L},
            {0x742a6036d93c2057L, 0x08974511b147a2feL},
            {0xc8b21bf16608e4dbL, 0x4d758c29eeb484f7L},
            {0x0b5c6d5c43980a3cL, 0x82739c986dfbdb20L},
            {0x0ace7f98da3711b9L, 0x34f149a76cf782b0L},
            {0x321995ec53ea9914L, 0xc2ff5007f8a98c83L},
            {0x939b53119c4b7496L, 0x097da6d2e8f7686dL},
            {0x5fb6dd3ca90cff95L, 0x10f77bb9e7748ed3L},
            {0x55194932141d0937L, 0xc253f8ea7ac0779aL},
            {0xb2a4b4591251916bL, 0xdfef8e3e1b142c07L},
            {0x14df24dfc33e1f4fL, 0x931f7bdb443197a1L},
            {0xbd4cbe8b919dbb07L, 0x24128da6bf057bc8L},
            {0x1be6a922a8d0d7d4L, 0xb7330162b6115e90L},
            {0xb6d9e6635ec916aaL, 0x930f20cea1c668e0L},
            {0xccbb31a458da0423L, 0x60488351c7403436L},
            {0xef86b4dbc4263e4dL, 0x9237f55823767eaeL},
            {0xe2a0e301bed0748aL, 0x967e64f599297f3cL},
            {0x2fde9314f05105e5L, 0x58f5315e0e29e358L},
            {0xc9e5b15be18b7596L, 0xa305f4f11aaa8ad2L},
            {0xa592cb3563071925L, 0x31b050cca997ed24L},
            {0xa55f9e7374b10af1L, 0x5904c31aaebea1edL},
            {0xcf6921d88d12bbf2L, 0xea5142776b77d368L},
            {0x28779ef24c9ddcb5L, 0x448bfd74cc624506L},
            {0x0d2caf1924759d9aL, 0xc66ef14828e98e80L},
            {0x312a49ac8d3790dbL, 0x5121956dac40960aL},
            {0x311230a0f0166f37L, 0x41cdda4642d1e45aL},
            {0x152cd68f8d980779L, 0x50accd8f44cc6a3bL},
            {0x0e6342e6e178a202L, 0xaf2e59b6e13fec01L},
            {0xcdfaea274cfff823L, 0x008f7a68483d8f8aL},
            {0x80183f4571309485L, 0xdece92499f9521baL},
            {0xaba321469362905fL, 0x3c5814a4c792b3beL},
            {0x7e8680766e1d3ffcL, 0x7585a167f0b843b8L},
            {0x4e81e572c5dbf79aL, 0x114bd1d466ef8787L},
            {0x3a7e0a403a1da600L, 0x014747267c0b38f9L},
            {0x23116c4dd539e293L, 0x196284a6305e23d7L},
            {0xf0a02f00d5a45c0fL, 0xae9980fc3aa3cd2eL},
            {0x7eae2c6dae8286e9L, 0xd2be72a1da8addbcL},
            {0xbb8689cb630a9e23L, 0x2d1eb9e86163e7f4L},
            {0xf0febfb8f6e46561L, 0x8eda5ccd665a3ac2L},
            {0x370a6880719f8be9L, 0x83fe14fe68c33df0L},
            {0xe9634dd58474116fL, 0xdfb51a0ca76c9c82L},
            {0x9c40da32ca69fe52L, 0xcecdf64c8559eef4L},
            {0xe29f358edce8d40eL, 0x9256190cf3cfb1faL},
            {0xb5431f672597e9cdL, 0xc69025ae5a99210aL},
            {0x0f00e0c670d40d95L, 0xdf81e3ce7617b0a1L},
            {0x699332d099ea38d7L, 0xc24d5671c235f28eL},
            {0x89ea2f4529a74b45L, 0x7c11f6654369b65dL},
            {0xeaa8470e44915e89L, 0x049b62170967135bL},
            {0x39fb9877aadc951bL, 0xba3743d76fda5083L},
            {0xe2da8722532e6fbbL, 0xdef2a5ff6e028abaL},
            {0xb5e975340c6c76a1L, 0xf28418e25fbc0144L},
            {0x035ab9363f6882beL, 0xab56f227d4a26a26L},
            {0x273536b8b02dd5f1L, 0x75af981a11d43e64L},
            {0x846e480a8bc44fa9L, 0x507a048207335fa1L},
            {0x3808d8fa4fcba922L, 0xf632f1c9c802ab76L},
            {0x34ecb7872eda1962L, 0x2dcfedd3c12f73beL},
            {0xf884a540c1b411eaL, 0xf77d23a1c6600553L},
            {0x0e106a0239843e3cL, 0x7d5ef83763344eedL},
            {0x4192e743be4ae7d9L, 0x5070be659c9249ddL},
            {0x6588c07b62dd03baL, 0x09d7b6469e953856L},
            {0x790b4af55db42c92L, 0x5c859acd40414177L},
            {0xedda860c739ca8f7L, 0xd728f7e92e3e7940L},
            {0xfbcf513b18b860f7L, 0xf6fd92c58b52c44dL},
            {0x4f1571762119854eL, 0x04286d00eb347197L},
            {0x3f777b9977ed2aa6L, 0xf68288c09c8d73d4L},
            {0x538b16a3bd887a20L, 0x86437c4cb491c94bL},
            {0x3656d64f9fdf8bafL, 0x97db137363bf2a7eL},
            {0x0582fbdad31a1e6cL, 0x213b4a759760ffe0L},
            {0xc7f42208feff0a47L, 0x05cb6fb77aad0666L},
            {0x8f59c644fd5259d4L, 0xd3740dabc91a5ecdL},
            {0xca19d9ef4ab67ceeL, 0xa2486f3cdc03c63fL},
            {0x8a1f14a7c3d2f88fL, 0x71b6e4a0b3d4a2a0L},
            {0xe9ee9aa288652690L, 0xa28d2266c47e02b2L},
            {0x759c7eee1a3eead3L, 0x689aa81596670031L},
            {0x50a9a3f15e0032aeL, 0x206b34f2ed6fc8ffL},
            {0x630774b85c40302eL, 0xf7f5952347d531a6L},
            {0x78886ef4e794267bL, 0x7072ec9b3a2ddd8fL},
            {0x754c7bf46deec1a2L, 0xb360d5ec03ebf053L},
            {0x337080ceace4b67aL, 0xbe8541809bccdc7dL},
            {0x8c243c5d486009a0L, 0x87fc6f3fbe554f61L},
            {0x58e8f3ccf2596f26L, 0xc7a500e89b1b40a6L},
            {0x516a6cbee9e76420L, 0xe719cb9a5a49f8edL},
            {0x96f150816f90c216L, 0x484947f2b48d7882L},
            {0xdefb92978dfa0053L, 0x58823337d6c0a641L},
            {0x98bbc22dd2d3262bL, 0xdad5891c70205c95L},
            {0xbf1d06e5edc7d9baL, 0xea3e0a86c4241c1eL},
            {0x78e2cf480abc18efL, 0x1110bc39a35669cfL},
            {0xc188299c1375e7b2L, 0x8eb4cf8cb0851480L},
            {0xd0ec275048c667d2L, 0xff5c57071581e3b1L},
            {0x955c8d54a50fdd52L, 0xcf79008ac79991d3L},
            {0xf46cdcd85b7289c9L, 0x1c5fc0acfab2cbb2L},
            {0x676f48ac3ed3c825L, 0x862183d1a9042f4dL},
            {0xf35fc7982c7daee6L, 0xa655183af862baaeL},
            {0x5335bbcaf8b9f37bL, 0x963ed04a2a0b3eaaL},
            {0x76d009714121cb10L, 0x82f1d3e8253374eeL},
            {0x50198339f3198270L, 0xee023bd013e359f5L},
            {0x315d27ea94c7941aL, 0x5c1520117e098dbfL},
            {0x96ccc513ba987df7L, 0x7d84bbe2e504ff94L},
            {0x03464584b630d2b7L, 0x7d9fc4a633f228f4L},
            {0x7e39cbb756cac943L, 0x45a5498048f1a474L},
            {0x56a90669f7aa29c6L, 0x4883787b94c90425L},
            {0x9a262b27cb8de6e9L, 0x6495beb53f905401L},
            {0xdc5866e0159b2920L, 0x6c2c9c31b3faab04L},
            {0x82f93c693fec7b5fL, 0x1926807fb1c2bdd5L},
            {0x3a06ca560fda4251L, 0xff56ec036c5f13d6L},
            {0xcf96fe4ae095a1c3L, 0xaea98fd960fd6b9dL},
            {0xc2ae3b23e1b73447L, 0xe7c1f21b63d4e19cL},
            {0x660f92196e62044cL, 0xa61e4689ac8893c0L},
            {0x4aacc983cc5d9cfeL, 0xb71adc881811c258L},
            {0xb01938e5f92ea2e0L, 0x3d4b38fea83810f8L},
            {0x8195527abb10f039L, 0x242e99777aeec42aL},
            {0x077a36f6536baf7fL, 0x928620c22f148a6dL},
            {0xb4d16665e8f965a6L, 0x300ecf50c00b75a7L},
            {0x53d4fbf144350d5cL, 0x50967628985e6eafL},
            {0xea67291009feb48eL, 0x74a182255aa9ccaeL},
            {0xe67c52e63c97fb3aL, 0xbe1b4991d245fa61L},
            {0x6bd8d3685ed38551L, 0xc26bdd871e8691e5L},
            {0x267c4e3df39e0a7eL, 0x2408058c7b3e3c09L},
            {0x2bc55550057b4b4eL, 0xe70baa2724b374d3L},
            {0x0e2984947284c4ddL, 0x4f4e64ba26bfee68L},
            {0x78891ea4bacdb828L, 0x357f7d8801646f08L},
            {0x220a9cb569d1ee6bL, 0x8e6c9653552802faL},
            {0x6159359f74dda4d7L, 0xcbd0c89374b1cc2eL},
            {0x8dd5a4c4fe55c89fL, 0xeeca37f94d3f69bdL},
            {0x22abf1f68e0f314aL, 0x69b86caf61d48d15L},
            {0xab26c59f1090455dL, 0x1a49957d9798f177L},
        };

    private static final long[][] aim2_e2_power_matrix_128 =
        {
            {0x0000000000000001L, 0x0000000000000000L},
            {0xf50e0632f2a35f5bL, 0x386db41096f62a8aL},
            {0x1843656b2ea8f397L, 0xefdb454053648225L},
            {0xfc670d9cf3feeb63L, 0x7582326d84c7a1deL},
            {0xf1c52011971b40b3L, 0x864204566cee644dL},
            {0x5d8e354c13ae648bL, 0x192b28f22b444709L},
            {0x9d5cef9c88eb0d9fL, 0xb686d60b99470446L},
            {0xc91fa3a9b726fd99L, 0xcf7a6d254a105b09L},
            {0x048e86e374780c55L, 0x9f65220d0c78fc67L},
            {0xafa9c90017000accL, 0x83a4540ded360993L},
            {0x3e563c2c6efb6102L, 0xb7147f0d38fa394eL},
            {0x858e694ad98264cbL, 0x184d72cdc205efdbL},
            {0x260f2eae08292a50L, 0x101cdb156939622aL},
            {0x4a9a43781e99484dL, 0x8b9b7c41b6c639f6L},
            {0x16c9831c810a7459L, 0xcb60c983013050beL},
            {0x96d02af1b8d2cba8L, 0xb37b4c2c6ea27c34L},
            {0x3caadfab02ea679dL, 0x6c3124a15e087d32L},
            {0xf0892e59955b87aeL, 0xaab1aa69ba6853d8L},
            {0x8420916c212205acL, 0x86ed9039af31291cL},
            {0x0610fd444421f178L, 0xa6b004a839e31b64L},
            {0xaebf5d9bae4e4ac1L, 0x54bf9e6ec57b2d65L},
            {0x28bce750ebcba70eL, 0x4ce04f578ca77d4dL},
            {0xe35d48d89312441eL, 0xe6d91969fd74895aL},
            {0xcca901ef7fabb1c5L, 0x117d2c0c4032a05bL},
            {0x4d05be0c6a5a2edcL, 0x8314aecc100fcba9L},
            {0x7c685f4133a51825L, 0x9acd72f51105c28bL},
            {0x5011fb2faa2c215aL, 0xf33e2515d2bd65e4L},
            {0xcec542879e66d1d0L, 0xb35dca22a0c3ce97L},
            {0x40849b4ce23375b2L, 0x92453c68d163c3cbL},
            {0x807af8ab827e3617L, 0x9aa0b258c13e1db7L},
            {0x02cf8f1292f7c659L, 0x188599535df660bbL},
            {0x675c7dfe865c4b21L, 0x60e7e01162356b69L},
            {0xdca8758ed620dd7bL, 0x40e2dfc1450698caL},
            {0xd4785af596fd0c85L, 0x194dcdf10572a8d6L},
            {0x39c75c8db5a743fdL, 0xaaff1be5fb825c25L},
            {0x76f287eaaf80a26eL, 0x6d5c3d924e633b50L},
            {0xf3289f813d56fa87L, 0x8a5781160603ae34L},
            {0x023097d7bf57b560L, 0x5c09da41ceda1dabL},
            {0xaa7caa9af1506059L, 0xd65b5a005d02edd2L},
            {0x837d13e5bec17d5cL, 0x96732ad7e569d594L},
            {0xfca9d80d257930ceL, 0xbb07355f7df706c0L},
            {0x7e719f925352363eL, 0x61f17c3d17da7386L},
            {0xbdd686a4862a5d5bL, 0x5ddbe9580f36eccaL},
            {0xcd8440580a8cb347L, 0x8b395b802547e6d8L},
            {0x4338e255f15fc0d9L, 0xf2400716b60d1c2cL},
            {0xc0a4a5181cf7a401L, 0x208e7b27a3d4e578L},
            {0x6557dd7a9909844aL, 0xd7dd867435b17dedL},
            {0xe7214501f52038cdL, 0xf73bfe485cf7fdd0L},
            {0x93443a46972cbc70L, 0xd2ca8f42b2d199e0L},
            {0xbea25cda0a9de799L, 0x51886f07950aef32L},
            {0x82824ccfb37df72dL, 0x71a58d7df86233f6L},
            {0x0ab442c2423ac6e3L, 0x5d989eeb2df819bbL},
            {0x717b766d60dda065L, 0x3899b1af41b28b8bL},
            {0x2fffad98c8e94310L, 0x9ff893980c381280L},
            {0x9d7da6a6ca8c0d82L, 0x09c78e0f83da5e2aL},
            {0x26b7e85d55753566L, 0x48b0fee439062128L},
            {0x63896bb7a7a3c638L, 0x551438e5f3ff5db9L},
            {0x080d9af5ef2e5865L, 0x048eccc1b914ae50L},
            {0xf081a5f8ab004099L, 0x24ffc9670c5492acL},
            {0x7e4178c2bf375b5aL, 0xa641e4982d1c8638L},
            {0x9f1874733c37691aL, 0xa6e59883261af497L},
            {0x90068f05a814992dL, 0x8f340c2ecb9a2bd2L},
            {0x2e0a82ad5f144c70L, 0x783eb790b951d2d9L},
            {0xbf58c52a82e24af6L, 0x190f49c97cd133afL},
            {0x29e30e4d37b882a1L, 0x217bea750913f0dbL},
            {0xfe2287c403984038L, 0x870bd9dd397e696eL},
            {0x49e9bc6efdb97d7dL, 0xf75f4c5e88587e96L},
            {0xa6223b70299d2836L, 0xf27661ea227ab61bL},
            {0x4d6b8601ceb750cfL, 0xfab6503eb520e48dL},
            {0xcaf2dd4a73f67c6cL, 0x93f3baaf44fed4e0L},
            {0x1ff32e99fc57e662L, 0x502b8bb6f2031150L},
            {0x1d8b5656e3d694dcL, 0xb31de0d77f80372bL},
            {0x0f3d13aca2eac302L, 0xb6d1f98a81d2cd6dL},
            {0x840d8615c90887b8L, 0x1d44fc5efe63c574L},
            {0xded005c9eb05ef63L, 0xdeb4246e55c121bbL},
            {0x3409b8d1c43c2415L, 0x700c0d1dc307fe8dL},
            {0x8b361337911e3002L, 0x7920c1039098414cL},
            {0xa5dddabdd1beecf5L, 0x146aaf12b0d6da5eL},
            {0xe1a91d6f2a874e47L, 0x0d63fcc83ef069d1L},
            {0x0ffd9177c1f3ebb2L, 0x9a0cadce706c0cc0L},
            {0xc60d34aa0f45f13dL, 0x2d0b4ea8c2bfdc70L},
            {0x83e36503d6399610L, 0x6014c0c7cba2d2f2L},
            {0x9cc705d2ecaeca0eL, 0x79f83e8c83e7f333L},
            {0x58c7035772444cccL, 0x789c6687005b995eL},
            {0x6b3d950394c886a1L, 0x9b4f4564cd5b92d0L},
            {0x872c7f29b6dae6caL, 0xd2a320a97a0d0be9L},
            {0x14bb3a90e34016b2L, 0xb308fa5fc47ad142L},
            {0xc6b31a14ce574546L, 0xd7f758f96323f56eL},
            {0x046d3862feb271a0L, 0x391175405eef9c5eL},
            {0xf7654c3e98aff433L, 0x92b8d607c0180e5eL},
            {0xdfe26a4ee0edcbcfL, 0x4c21afb68c481788L},
            {0xb9175aa38699a7faL, 0xa26d3569fb705b0aL},
            {0xd2955bcc820c812cL, 0x29d30f039b37f636L},
            {0x37d8c59743ebdc8dL, 0x19289d7baab847bcL},
            {0x8b8a25c0075e7200L, 0x75fcbc7110b551c9L},
            {0x8ab2318dd48eb686L, 0xca8ee9edf4a5a1e0L},
            {0x182033f6233cad5fL, 0x743083edee67622bL},
            {0xc82b0364e7db3d93L, 0x3cec89a9bc59587dL},
            {0x4fb362a6d33cdc65L, 0xb2f2a5ce567b5b8eL},
            {0x90df4043911d6152L, 0xfe9e1ef68cc145b2L},
            {0x4fcf7b4fcca5200bL, 0xaba094d2f96d9249L},
            {0x5ac887c31fc3fd76L, 0x1845172174cf2944L},
            {0x25180f84f6702866L, 0xde5223f17c83df5dL},
            {0x2863a5b3ae30cdeaL, 0x610fc2ae8f7cfc74L},
            {0x64a4086ca77af644L, 0xafe073214eb0e372L},
            {0xbdc97dadac10ab50L, 0x97cf31c3dfa3a7adL},
            {0x79f2ee819538d167L, 0x68555fb401eb2780L},
            {0x72e2b904d5c7a7edL, 0x482326aa3e165b1cL},
            {0x92f65484dcff7fd8L, 0x603faf9bafb86f1eL},
            {0x210e7817fff07876L, 0xabdf6d8a0dd6d8a5L},
            {0xab561f7f19942decL, 0x55f71e3e54c7b523L},
            {0x8e7140a742fb2245L, 0x34a49c54b5ad70ecL},
            {0x6da544268e007b3fL, 0xebf2cf33aeaee1c9L},
            {0x010679622fe3753eL, 0x40228d2a0d402ed0L},
            {0x2e128b07e6e4e311L, 0x0811ebd4d8dde5b5L},
            {0x126cb02cee9ad020L, 0x398e5321decfb79cL},
            {0x6dfdff51553fb5ffL, 0x415b4003d55c33abL},
            {0xd3b7fedc1cd8ab6eL, 0x49dc7b6033f0ae60L},
            {0x7062ab84db2bbaedL, 0xc33060adb11136c6L},
            {0xae149ced6b9cc3d3L, 0xef2f29a2ebe433ceL},
            {0x133ca1e237105dc6L, 0x9712a59673f1d79cL},
            {0xfcf98569ab4ec844L, 0x6a40dd9e8d49194eL},
            {0xd73a65ce7e33212aL, 0xaa29936469e73794L},
            {0x961009e50707fe21L, 0x657c63ec063d9f23L},
            {0x6b1af6be25650671L, 0xce96b0cb11ce0372L},
            {0xc7312488beda3b54L, 0x9ee42f2347f50335L},
            {0x829d638189fca23fL, 0xe3123a63017f9509L},
            {0xbb40cef8e0e85ceaL, 0xd8b3a76799622f49L},
        };

    private static final long[][] aim2_constants_192 =
        {
            {0xc0ac29b7c97c50ddL, 0xbe5466cf34e90c6cL, 0x452821e638d01377L},
            {0xd1310ba698dfb5acL, 0x9216d5d98979fb1bL, 0x3f84d5b5b5470917L}
        };

    private static final long[][] aim2_e1_power_matrix_192 =
        {
            {0x0000000000000001L, 0x0000000000000000L, 0x0000000000000000L},
            {0x24187d60404121f6L, 0x994d0c36800d12c1L, 0x00911dd52a0924f1L},
            {0x764f49362db3c478L, 0x3bcc2005010a3fa6L, 0x402147d6af1a6ff4L},
            {0x1c0878591079091dL, 0x9b08ffde1c878f59L, 0x8ff70000000021c2L},
            {0xbc23dcb74c10198fL, 0xe23fb48357412666L, 0x70031ccb7f97795bL},
            {0xffa72d9a27550570L, 0xc7dab56f7d5ade7cL, 0x78cd4c6283845a4bL},
            {0x655b34aa00430d9aL, 0x0150004209eea37cL, 0xea5061fe40551141L},
            {0x291b4f90d5814c36L, 0xcda4bfb158be9a9bL, 0x0d4558cc51c4127cL},
            {0xbe4eb108521087f8L, 0x855a49e49b1f9165L, 0xfa15129aaa8d8745L},
            {0xef60386cb35ccf9aL, 0x5115765ff710f9f9L, 0x205677891921e135L},
            {0xbed705ee53ec571dL, 0x97ef8c6dd0851236L, 0xdfb8887b08ee7b6dL},
            {0x6731ce99be825c5aL, 0x78665e68455482e1L, 0x8b867f2046054b3eL},
            {0x008fe70500592609L, 0x6419eeb2829f34c3L, 0x8f95a35e28a915f4L},
            {0x4dd556b654d54730L, 0x07e8d738dc4b2c41L, 0x6de823272f319c70L},
            {0xc805945260585e93L, 0xf3efb93595438399L, 0x387f3dab97add8fdL},
            {0x8825784a2bb54db6L, 0x8d1d21f68a9fed14L, 0xd72c5de2e4375500L},
            {0xd9fbd5d41179e461L, 0xbaa9f9428fe27896L, 0x49998ea2c43c70eeL},
            {0xba1e061ac9218b6bL, 0x93a1c1ea0a23984aL, 0x145015f4bca9f514L},
            {0xb2829eadb1319c61L, 0xf21008aca9c587afL, 0x491dfc66b48bb406L},
            {0xdc192cc5729969e6L, 0x19aeec2c6a3facb8L, 0xeaf05f73c034e88fL},
            {0x5cc5d35af8af5039L, 0x64bfd6b3c8401142L, 0x4d083af0e0cecd4fL},
            {0xbcb663181c16e418L, 0x9d73d6e08b40b1cfL, 0xe6a19d2ea608b779L},
            {0x8f9e2660cdf64ce3L, 0x6e790dfe030df1e7L, 0xf36bdb76802d4809L},
            {0x24e27b21fdd534ebL, 0x9b2abc8327bb58a6L, 0xa60607784f3d2a8aL},
            {0x6470b72d839b493aL, 0x3de3bd12dbc9236bL, 0xab0e0e81db838cabL},
            {0x9fa25765dfa0dc0cL, 0xa4866af77f3c1d39L, 0xa22985fd177fb75eL},
            {0x1bd0dcf82dfcbaf6L, 0x2778cab77faeae14L, 0x144c9d871ac906e8L},
            {0xab206aa0299e585aL, 0x1f2a1c115b2b24e7L, 0xd683dc1df4f0e8e4L},
            {0x3db096486b11d3fcL, 0x1d88f50f57fb1318L, 0xfbdbd02cf211be3bL},
            {0x83c0ed680040dbebL, 0x01d5321e9c73822aL, 0x5c78f9da86ddc253L},
            {0xed72eb240cfd7027L, 0xe43295f2eab71065L, 0x7dad74ed8a4daf27L},
            {0x593448e3f55865bcL, 0x3dbc22ef1d415b62L, 0xff617d36a6e04fd7L},
            {0x79fee82d5e5f6225L, 0xe933e7ffba3ad69fL, 0x11333262fecf9f21L},
            {0xaccf982f89364968L, 0x961868954276eacdL, 0x3903286905b4951aL},
            {0x15f9d8aff0e99b99L, 0x37d7fc3823e38e15L, 0x8f3cf305ce9c3317L},
            {0x5f1db90ec8ff178cL, 0xef61eb5b69c0cf16L, 0xd6d4428841ba2406L},
            {0x6c1d820160b3e589L, 0x1655a37c12244e16L, 0x1506fe0d42af221aL},
            {0x776220241d5f52f8L, 0xbbd873a1a32d77fcL, 0x2967ed932de2646dL},
            {0xb360b6c691f374f5L, 0xe152921a89b1bb3aL, 0x9bb32e5d9871acf2L},
            {0xbbae8029d2f0211dL, 0xdfa58ed49cdc469aL, 0x298aa1fd3b5fee94L},
            {0x311334572c4f58e2L, 0xbd79cb94c83a4a65L, 0x097731c2b9f63b2fL},
            {0x202f161d6f618d78L, 0xb30f00f7d63d2b1cL, 0xba3ba40cb586c147L},
            {0x6f6de8a66957b811L, 0x933c64f745e4cb26L, 0xe60acca62b3467daL},
            {0x2d52d8e03eadc408L, 0x020b8ada8b0cbcfbL, 0x97e520c15d31d866L},
            {0x17f79f53394c41f8L, 0x8057746b55d4354dL, 0x29944f234150b558L},
            {0xd48d6f8d466f4fb7L, 0xe62aa6c05e099abfL, 0xe72196d812cdf8ffL},
            {0x31086eee778187b7L, 0x5f39e6312ab8e7fcL, 0xd2794f291ba18edcL},
            {0x8bb7a2d05d52dd01L, 0x898fee2a72a51691L, 0xaf83c32d4f112cdfL},
            {0xf219effd62769131L, 0x006ad7baac86fb08L, 0xae1e7bed2f88d4ebL},
            {0x085e604007b4850eL, 0x74969c7dc17959a0L, 0x70af70f460fd6854L},
            {0x85048e661ea730d2L, 0xccb4840c40f6c89eL, 0xcb4b3836c98d0776L},
            {0xac7fadd0308807deL, 0x93e5399425e1f409L, 0x6cebcde031477957L},
            {0x12b09fb9d6bb04ffL, 0xa5b0c0475b17d882L, 0x9a2d1dc52a42cbfbL},
            {0x2a89655cb1fec3dbL, 0xb8a64412d508abdfL, 0x3998b588ed04feabL},
            {0xa8687e88bff0829cL, 0x671e2f2b99afe070L, 0x2c08c6f71aa0fa09L},
            {0xe1ce5c820d6be145L, 0x7c9485f929d3a113L, 0x35a20e96293d131aL},
            {0xba53e0ea72f26b2aL, 0x2c4dc2a431baa81bL, 0x19674137360734dbL},
            {0xde4269315e846bfbL, 0x9ed583db0c4ca349L, 0x315852fa0660ab68L},
            {0x00ae2ff5c859fcd1L, 0x8a404e1ee645e1dbL, 0x9feadfee4a6a10b9L},
            {0x098454c0f608253bL, 0xbf09d16ec3b96f79L, 0xe63451db95697bafL},
            {0xa422cc6c5adc283fL, 0xb7854c10a36c12d0L, 0x9650b028e25b9107L},
            {0x8da1b75903dd2aa8L, 0xef8f3a20c77f4c10L, 0x11e6a8d176631e6fL},
            {0xe70563f20a26d72aL, 0xc706a9184b4269ecL, 0x01707c8cd370854bL},
            {0x4c497f712f722710L, 0x40d97c17a9f96a81L, 0x61ac088c7242b19bL},
            {0x9c1188e5b2c4043aL, 0x15c4ce5e386918fdL, 0xc2c19cddc8022f62L},
            {0x334dd52624b37647L, 0x0ecfeb52b8db6b3aL, 0x7cb0cc6a541d915fL},
            {0x0d2da3de5da05ab9L, 0x4c8403040eb7a0a8L, 0xaa43178d698e1d16L},
            {0x94dd24ac7d70454eL, 0x19c81eacd2305f1dL, 0xab7995a48e6230a2L},
            {0xc4c2698143f7ebe6L, 0x9a9c3bf3c8dbc9bcL, 0xef2ce69e69cf09cfL},
            {0xe4d55e8362bd6084L, 0x4bd67382e024dfd0L, 0x821aed870355bf63L},
            {0xd76139f98e468054L, 0x61f1798f51310a13L, 0x29046f782268e0dcL},
            {0xd415fc0d991dd093L, 0x40c961038916982cL, 0x50c6b0ef248e059bL},
            {0x9964bad18a8082f1L, 0x666ff6785e18a4ddL, 0x8ef30e5710f8282bL},
            {0xb414e2f6230594feL, 0x1bc6a73e670570f9L, 0x58556965657d0723L},
            {0x7923079ff8bc88c9L, 0x2009ba12607a4104L, 0x79486291900310c9L},
            {0xbee4fd3a8ba864efL, 0x5df270cc7b675b45L, 0x8fe410ae3a6416b4L},
            {0xed8ea038500ce1aaL, 0x23cfffa4b08f7923L, 0x24391c9872e1db52L},
            {0xea11414bd1ee6f54L, 0x57a5ebe50ea4869bL, 0x18f580aebbed4614L},
            {0x4d0c81d6ef843f2fL, 0xfd169854c78d4b18L, 0x7c36b2afccb84371L},
            {0x0c639f2dc76998e0L, 0xdc8e28abec0a421fL, 0xfba0c0a5251cd144L},
            {0x766dda3b823a1b74L, 0x7f6d206bbd49261dL, 0x710de4ad8beaa62eL},
            {0x7abd0b3c484d3910L, 0x58abd14b6ee2e49bL, 0x78652fe31e4d6d19L},
            {0x4dce3f2a407a25c2L, 0x57d6ce10b19b7b99L, 0x29cabd29d03528c3L},
            {0xf03c709f8b55bbc2L, 0x10f449ee0641e483L, 0xf60bd442dfd1a803L},
            {0x51d8a3af211b35bbL, 0x2b0c872b328250e9L, 0xb67d77e5c9d6d27aL},
            {0x9a731c8f091b2c24L, 0x04cf41a716e1e225L, 0x9b354a2d84899ec9L},
            {0x0748672bb3e504fbL, 0xda648aaa478a326cL, 0x0d85a4a55979e5caL},
            {0xbb732bb90d147586L, 0x446c43c25a19dc66L, 0x18523f7f708eff36L},
            {0xc549edb1f37b1b15L, 0x719aa23612aac7e4L, 0x2c771e685e380ec2L},
            {0xe2b6b4207ad6a4b6L, 0xf7cc2a116c9527baL, 0xdf6e5d55b2406221L},
            {0xb67a2baac610e044L, 0xd425d94d1ebe4051L, 0xb7bd1ce70c015395L},
            {0x64ff5ff72d64a1b1L, 0xdaca2b8812d90ae6L, 0x79a022efcc594eafL},
            {0xc93cfa6de67bcacdL, 0xa179dce6ffd14aecL, 0x31528f0f0f3c6817L},
            {0x3ec18f7af7342039L, 0xf8d7aa856a662ed9L, 0x097b848460df8308L},
            {0xf037fa04d6ff2eb4L, 0x1b6ec290719d4d0aL, 0xe20e86a3b38d743eL},
            {0x8aea64bccc94d424L, 0x2cc260f4f6b65badL, 0x355d31f6d901a260L},
            {0x140e5ae17cc96cb4L, 0x620ee0a86b0eda0aL, 0xb3fcecb29d358575L},
            {0x5ec85d1f29af07e2L, 0xd6c8834f22331d6aL, 0xcef37a820396e162L},
            {0xe344085d2eabc755L, 0x6c6b136959c8ef7aL, 0xbb22e260fa6a677aL},
            {0x7a64bfaa585ae30aL, 0xe317efc967bbe220L, 0x9a9780dfb02d4b7eL},
            {0x98c71744cd706cebL, 0xd177e9274ab5f551L, 0x8353064dea82d011L},
            {0xff04c178eec23d3eL, 0x2f460919349f2d47L, 0x78fe5c7e69a969f2L},
            {0x40b0e4b5ba731b12L, 0xdfdf6fb48e1eaccaL, 0x418adb73cc0cac43L},
            {0x07e5547b971dc85aL, 0x9bb127d9e57350efL, 0xdb9801dd4d74063cL},
            {0x85c01e6cb0183fd9L, 0x3ed03735d2254d39L, 0x759b3422ff5ef8f1L},
            {0x6d72fa4b71c48c98L, 0x3a991af37f04f9e1L, 0xb32059432a68082fL},
            {0x3fe283302875d557L, 0x8173481a149eee28L, 0xeb7766a31793b0beL},
            {0x7acae2d67f591873L, 0xb326c3aa2ed4173aL, 0x1946cb0d5f62d04dL},
            {0x23bef9ae772d7f05L, 0xe0bfc86b1d88610dL, 0x74f165bcee4734ebL},
            {0x1d4726ce666680c3L, 0x2ce0e6d607113532L, 0xffc5de80c34f2df4L},
            {0xc2c05b149cdd1b58L, 0x6944e26394cbe4d2L, 0x97958f196f8c4c6bL},
            {0x270456c0b2e40aa0L, 0x55d5c764d7670e84L, 0x717d55b1ebf4aac6L},
            {0x20bc0c1aa67ad034L, 0xd4281becc759401dL, 0xa34c23a734c590acL},
            {0x5847ae572b03bf5cL, 0xfcac4377aa016371L, 0xc37160769e1a862dL},
            {0x7dd17fc6d6f74010L, 0x5b327c27eb1048e0L, 0x9bdfc698b132189dL},
            {0xab7a432b47cdddcbL, 0xa929bbd83ccbd1f9L, 0x4d454da5089a34f2L},
            {0xb39461490efcedcaL, 0x53d60b8883762f77L, 0x38149fe44801d6e1L},
            {0x7c94c03395823033L, 0xdeeb603aad8b99f6L, 0x6135272e4190f922L},
            {0x253f212e339c57b8L, 0x4fbc0d5dd968a708L, 0xf66bd639e3fb013bL},
            {0x6607bb8d9f1426d8L, 0x0b9156b2a938e184L, 0x1d6f7d7b46319a77L},
            {0x408e99af5df09232L, 0xea04d07e17d71e98L, 0x0961e3735a066cebL},
            {0x0ac48cb89fc1d495L, 0xe5ed5004fadbdcb6L, 0xb371ec4e641dbdfdL},
            {0x870fba78bc9a5840L, 0xa1372a9ae9b35641L, 0xd7b9b31aedb9368dL},
            {0x9ec8171425817f91L, 0x46d3a766e6d0c217L, 0x6d410a83cdfd91e4L},
            {0xbaaf0e5bac52a284L, 0x6184eb30dcfa0676L, 0x10c8fb0ed6d0bdc9L},
            {0xac8814d3e0fe8707L, 0x86d0ff1167e53b8aL, 0x10e6600f84bbd4e6L},
            {0x747c0349c6a589ddL, 0xf944627e4ef37152L, 0x28e5a0f135a5a9bbL},
            {0x382e5c28e3026945L, 0xee877613758af703L, 0x2d922be5a1610e7fL},
            {0xcadae8499bb4cdb7L, 0xd090031f77613a0dL, 0xb775a4e76fd94b4fL},
            {0xd09a761e6898ecedL, 0x5669242c2f84d5daL, 0x3d97c6bded80996eL},
            {0x2f95de059a47e03fL, 0xfa75be47169ed83fL, 0x87d30a6c8dff4a90L},
            {0xf8588b0cb7a0c692L, 0xd246208d9f6dc4fbL, 0xe36d575d6c2485c0L},
            {0x48c08c7013df5c58L, 0x4d37effdea32dc30L, 0xff80378ec9caad7dL},
            {0xf9e43db917658f34L, 0xb76c0ff79e41f707L, 0x8e4935c0b5c08083L},
            {0xb33f84c0bc9ef48dL, 0xaab63f4f9f339a4cL, 0xae55cf665e81d500L},
            {0x15e234561c4632f1L, 0xe084e7a57d035829L, 0xbaa1511cb0ed12a0L},
            {0x74f83ba7ec3568deL, 0x1d7ecb2f352fdb0bL, 0xd76964def60c29f6L},
            {0xd1c2b81f2e13a757L, 0xf84d5af929439b5dL, 0xc34a2d0878b81e8dL},
            {0x47767837fdba926bL, 0x5683aec561752e96L, 0x961ca0e7d4439bebL},
            {0x7d73c95d078b625fL, 0x6e621c6b3817a9f1L, 0xd300b482fda5d226L},
            {0x2cf83b998a66fb35L, 0x4f0359eaa9684bfbL, 0x2c460d7b4765cbc7L},
            {0xa5c0e6cf67395406L, 0xb659d3e82276235dL, 0x2c5c851229561369L},
            {0x3168901c3d8747a6L, 0x4541eabd5d866402L, 0xb768bb5b1a6b8379L},
            {0xb5fa4b6cdc308417L, 0x8100841dbbeb59e8L, 0x4db5eb632adc8553L},
            {0x2622070061628fa6L, 0xc66a1ed278866e50L, 0xfad328db6fb4acbaL},
            {0x6734cb1adfc5db87L, 0xd7f8cfed34d7e713L, 0x259e5c52bef9b101L},
            {0xa077ba5e97f9e1c0L, 0x21edc3275eed4b8fL, 0xc2ddffec584d31bcL},
            {0xe8074b1519eb9faaL, 0xa35f39294a8283edL, 0xffbfa9f0fdcce212L},
            {0x49406434389cd06bL, 0x5241069e873cd010L, 0xde4f448e7e3c47b6L},
            {0x8cb6dafda57a1b04L, 0xb80b06fb012be0f6L, 0x6c1f61ef626c5ee2L},
            {0x9e596d56ff39dd82L, 0xfd823060d81e563cL, 0xfe45b0659666e7bfL},
            {0x713e642578abac3bL, 0x1e13b3773dddffd6L, 0xf7ebe45d0b4ed62eL},
            {0x0fb29b505409913aL, 0xbd66ecfa5053f05eL, 0x5172fa12bbd062cfL},
            {0x7a8cd2f2af8db5c7L, 0xf1c96d88f03f2f0cL, 0xfaa8376f49a0abd5L},
            {0xacc980889b25b5e7L, 0x2c34843e6a6d9f3dL, 0xa6bf67c68037b6caL},
            {0xaff8095311a13c10L, 0x1d4a259b84ca7804L, 0x3cbb9d0b61f7ff43L},
            {0x5662cd5d639dfe13L, 0x89c27a983290bab8L, 0x92a7d11e497af642L},
            {0x4157aad5c3c645caL, 0xf51297f3f77a30f2L, 0x83c9dda7804ac4d8L},
            {0x4e84ffef7ca3be0aL, 0x14a7ba9c76da7c08L, 0x5c28dc6da027d5a0L},
            {0xb0964b96303be4e5L, 0x4615a98b7f22a76dL, 0xf222f844d2b37df9L},
            {0x802540711d4f5f7dL, 0xf6649bae872a32e3L, 0xaed6395da047f447L},
            {0x2f0953d8ce80f600L, 0xdcf66d5eaf05752fL, 0x209193bacdf14ef8L},
            {0xc6a3ef2332ce576dL, 0xb9e01c6c4572a31fL, 0xde9e30f16310efdeL},
            {0xba02b8398971d6e6L, 0xd1bab81c9c5221d6L, 0x1c9c2d1f1b7f3f2bL},
            {0xedc228019fbdd60aL, 0x2753c3a138bcb6d7L, 0x786fd2ba67707c2fL},
            {0x448e2cb6c1407cbfL, 0xf7b738377f0cfb97L, 0x4c9212bdc0657e9cL},
            {0xc76e32691429c2f9L, 0x490232f4e8c043ceL, 0x217833736b683230L},
            {0xd1499dc75ffd2a9cL, 0xd4b5f702de32b776L, 0xd6dfbb898f67a374L},
            {0x3b5a28d4cff86b77L, 0x806f6c0571138c8bL, 0x54628239f0c0f09fL},
            {0xb8d45dd4a900ea0aL, 0x2a9169078690c168L, 0xb3657df1647fbd66L},
            {0x08189a6674f4c29cL, 0x8915f4636dd5d112L, 0x654dc7fe07da3107L},
            {0x5250e18c883794b0L, 0x8828b68987cd0d9aL, 0x300a18a7c772270dL},
            {0x51d33040e3efaa99L, 0xd658da2cb0cb97b0L, 0x39038890d157c0afL},
            {0x68f5a5cd07a32b53L, 0x46b4f5ec1368cf94L, 0xf2e0d23f40742f45L},
            {0x782b44a867a3f208L, 0xae64fe82046cd425L, 0xb78cf45fe171d435L},
            {0xde012b438c92c4d6L, 0x4733810dca874273L, 0x206a03d102c15302L},
            {0xbea371badf5b9173L, 0x8cbfaa817fd4f717L, 0x34bea5affcb319d8L},
            {0x1a26c2090378d01aL, 0xf3d15fc5c66a7f39L, 0x4de762da9a07d052L},
            {0x3486c8a67bccd6ccL, 0x0d10351e2b0e18acL, 0x087106b5da2aba90L},
            {0xbd5c398105759654L, 0x932e7ce0d2415118L, 0xff7a9395dd694851L},
            {0x6f6615de424f584eL, 0x6ca415cbf1ff0b9aL, 0x509c3763be9bb7eaL},
            {0xe45a5c178e450e25L, 0x48cc200c65039546L, 0x2c2d872741a6e8d2L},
            {0x10a487ce7b7ba1f7L, 0x8da8831a4adaa217L, 0xcb608d431e73d316L},
            {0x480667a3a33a0923L, 0x3a6fc63a03c45c96L, 0xebed952f29ad80c0L},
            {0x8899df2b4edff733L, 0x7b68b7ea18849999L, 0xcedaa43cfb6f7f7bL},
            {0x356eff5782ed987fL, 0xca6aab13ed43b0ceL, 0x9dd8a4a5288bc18aL},
            {0x5ffc38d8fbfdcdb6L, 0x697d4c0b82ce34afL, 0x3509dc6ecc05993bL},
            {0x83905969be9090ddL, 0x2125eb5bbd23d5daL, 0x64224c3dfae48ffeL},
            {0xf54512d0b6691741L, 0x0cbaec28b636b0bcL, 0xbb1d6adcda1edefcL},
            {0x89ea6a9a58cddfdbL, 0x845d179babdb73f7L, 0xcf74a641c412cff5L},
            {0x65c9f3063d3b266eL, 0x560354e0ca062952L, 0xc6eb9b218ae96514L},
            {0x8e8c7412b3689e52L, 0x99b2ec666a8a4e48L, 0x5b4477de15147c03L},
        };

    private static final long[][] aim2_e2_power_matrix_192 =
        {
            {0x0000000000000001L, 0x0000000000000000L, 0x0000000000000000L},
            {0x75575b2a01927c2bL, 0xe38f9eab8f685827L, 0x782b0bd5192bca87L},
            {0xaebbaa0e79dffe28L, 0xb3542e6782b8ce84L, 0x8a972b1b32323be2L},
            {0x62cbd1af5c77da14L, 0x3bbc6119877bbc1dL, 0x8b6d73bce65ed541L},
            {0x4cd2ae2762f272ccL, 0xdd4adc5bfc34ae6bL, 0xa3f908a96f0fe449L},
            {0x60cfbdb9b6447e24L, 0x721af8263082c01cL, 0x68cb54e6fc7104afL},
            {0xa92867af3dc3b730L, 0xb2608cc06efe34d0L, 0xa3445078ace873caL},
            {0xeedad86c96afe677L, 0x52afb525bd42562fL, 0x38cf8ddb97dc96e5L},
            {0x0a3b06f10bbc9562L, 0x577b7a04e02c557bL, 0x8be00f5765b7e908L},
            {0xaa72b3916d207e20L, 0x50f0cce86025ffacL, 0x09f7f935bbde0a04L},
            {0xac08b4e71f96174aL, 0x16babbd24d02b260L, 0x48e9d357af5ba717L},
            {0xe122c9c16beaa8beL, 0x07043902949cfad6L, 0xf78fd47b58608577L},
            {0x5c473c24ac8ca469L, 0xb1da898afda7d7aaL, 0xcac72d2cf21a9be3L},
            {0x7da00b91479d06e3L, 0xc4c76d79d51eb15aL, 0xb6c2e5796630269dL},
            {0xb42bb35d07e100ecL, 0x19964fd51c07b0afL, 0xffb88b0ef80a102fL},
            {0x60e6beb41a673a07L, 0x75bec86a6c06b470L, 0x61bb7f05fc39be82L},
            {0xfda48d0189cd0c13L, 0x649054858d5374c9L, 0xb770a8503a32e8a4L},
            {0x4a376d825f3006c4L, 0x8896eb44124e97aaL, 0x70e626bebfff29b5L},
            {0xe37a2f298ccf89c0L, 0x3c3609a866d94979L, 0x356c25d15f10d784L},
            {0x458ca204a347e41aL, 0x59568e0a4da4e181L, 0xab475a7c61d9014cL},
            {0x8c1a39eb79672160L, 0xb373d43893fbd9feL, 0x41ba8d6a7097e9c8L},
            {0x7c01434b5f8e1448L, 0x662bd055a2512d4fL, 0x652c31c38e992dbcL},
            {0x1eae5c36fe075219L, 0x82cb682598bcb1eaL, 0x60daaa526a3e9947L},
            {0xf7ab17ab10f03bdfL, 0x1e124b56f71a4c37L, 0x75df607068cfdcffL},
            {0x1ffe54ada576e3c2L, 0x384cb4e86120aaa8L, 0xc6a4fefc642071dfL},
            {0x1ae57be1013b7efbL, 0x28d36534e13a369dL, 0x75612cd220210f77L},
            {0xa84cfbb045298f2bL, 0x733fdf0216082f1fL, 0x0054b363e1fcdb09L},
            {0x8745e66041e62570L, 0x980a16636c09d9b2L, 0x51695306d0539b47L},
            {0xa67319655b027ef6L, 0x4fd02799c207267aL, 0x01587af4a65b6fd2L},
            {0x8d991698735bcc88L, 0xf14dbd2b19f99a78L, 0x6947a3b95199d2f4L},
            {0xe2906490948e4affL, 0x16b2ee7035d98706L, 0x78f47845853b1ddcL},
            {0x58d9cdc2dd693cd9L, 0x7e9c240b1b252019L, 0x5cbd3d458a53ca24L},
            {0x24101759ff01d89bL, 0xed8fdd27cdb2d47bL, 0x11b0fa26e8d8a743L},
            {0x9da3e8ee96db2f59L, 0x68285801543b4ac8L, 0x618cc8ad53d51b65L},
            {0xf0b448478f472d56L, 0x6044053c293513d2L, 0xea2fb63a575a34cbL},
            {0x56bd7f9b430ca7deL, 0xf883dbb4c18d2e0bL, 0x6c8030ef1a38c730L},
            {0xf2e2c1396125acceL, 0x882e926d399fcc33L, 0x87e914f3049f22ceL},
            {0x7ec0b0443f81915dL, 0x4573c52a818a44f3L, 0xafc01f5cc8120f6bL},
            {0x924aed58bfbc33f1L, 0x7cbf5617448b59a8L, 0xef023ef380d782bbL},
            {0xed78ebbcc2543624L, 0x4fbdf96f5a481d8aL, 0x7dea022c85973850L},
            {0x4cd0fda73b73aaf8L, 0xab714c84882fc5a6L, 0x31a12db8b87c1a82L},
            {0x4f55b122e52b04afL, 0x2b6abc206fcdea22L, 0xeecc6a28e10f3cd9L},
            {0x773b7f263618ea81L, 0xfedd6644251162ffL, 0x20f124b39fffa2efL},
            {0xc86672d34c7f9c99L, 0xa1a9bedd91ba54abL, 0xe3164453cdbc1680L},
            {0x976193445cc61080L, 0x4e8af4d9771f7fdeL, 0x2d6951afbad5a152L},
            {0xac8104ed45afc3e0L, 0x2daa407aee0854a8L, 0x93bf8a5f6332934bL},
            {0xadacd0145616a90fL, 0x18fcdf471f8e446eL, 0xb6cb1d657c5aee1fL},
            {0x39f4888a9f625046L, 0x714ced776be006aaL, 0x301aab64f4c07bacL},
            {0xfed94c87075ec99bL, 0x6527495efabe5878L, 0xae4ed05b44c346faL},
            {0xe8089970ab84a9adL, 0xfa8ef420f612f142L, 0x3033e1b424799c03L},
            {0x3de830d471a1c303L, 0x1d4648963e64b5e8L, 0xb7fc69c1308d744fL},
            {0xf917cc81a21178a2L, 0xf51c71d20d3dde0fL, 0xc755e70d903eca43L},
            {0xf988b4435c7e0659L, 0xe8ec12c9411e644dL, 0x011cff135dc46fe5L},
            {0x45eb42b4bc82e615L, 0xbb1ea1d87fa2dcc8L, 0xbbf258cddfcc5a4eL},
            {0x76c177c889777fa3L, 0x771de5ab30476ecaL, 0xe3dd4d0ea4da4f41L},
            {0x62d43190a74afaabL, 0x8c72e6cc25a0906dL, 0x6560641e35c269c1L},
            {0x4a473706039e3353L, 0x9270c15446432105L, 0x508bd6dfcce33617L},
            {0x58e979ef836cb200L, 0x64a108a5f68530dcL, 0xeeb5a210610292b9L},
            {0x3e8a485122657a2dL, 0xb7f7272f3423621bL, 0x4c0e2f899ffc6f0fL},
            {0xb03f26ebad2101f3L, 0x2bf27f00ccb827adL, 0xf2c32d1c9db42e29L},
            {0xcc5f196397e2bb63L, 0x9cf1f95bba0e5fb0L, 0xcffa723b8add78c2L},
            {0x5198cabd81774aa6L, 0x79e142bd7c3981f1L, 0xcfb65a6d42815d8aL},
            {0x91dc7af311207622L, 0xf294a4f3c38f447eL, 0xdfd67624b63f7997L},
            {0xfb2f51ed0b5b44c1L, 0x6eeb2b229427682cL, 0xfad555a3f1680200L},
            {0xd043eb034f7557aeL, 0x89f917e3d7f663f1L, 0xd7f51e2f59ce0302L},
            {0xd1738764ddee76f4L, 0x28a966bea5ec647eL, 0xa322c656d7bc27d1L},
            {0x0cd66c8dd29514f0L, 0xb4e37bf2f01130a9L, 0x7db6ecdc81a7a57fL},
            {0xc8cb28a44796dc78L, 0x88eb0048501b3765L, 0x8ff3fbd6d703c26dL},
            {0x2c5d68650ca4b6f5L, 0xa8e391ce83198344L, 0x8b9f3219506be9d0L},
            {0x911906127a1ba855L, 0x30d5215961ac95e7L, 0x71827dfac7504342L},
            {0x1ae4c2e2506d0712L, 0xb5caffb8afbcda6eL, 0x159080539f7f876eL},
            {0x86571676f6228cdbL, 0x3a51f0bfed40380fL, 0x5dec5a0cee962a54L},
            {0xf5c3339c01460504L, 0x5d55382d4e349eccL, 0xcf81cc12df0b2c9eL},
            {0x89a775997037437aL, 0xc86002223b57f27fL, 0xfe795feb841f08efL},
            {0x7da8a9b3f9f43fe4L, 0x8494d51c6e215f43L, 0xb703f044bc338b9cL},
            {0xf73c2c9d450a092fL, 0xce0ae97084884a01L, 0x9a647f6d5f970839L},
            {0x87c63573f869cdbbL, 0x812d2d8e966e6911L, 0x973b425ba1c66dfaL},
            {0x7de5a1e78d630e85L, 0x765d7d5a4a6e3cb7L, 0x28170eef2a846d99L},
            {0x0b0c630c0f59460dL, 0x9c8758a9ee8db258L, 0xd3589f9c034f75d5L},
            {0xe1a6d8e757067309L, 0xd18498099be244d9L, 0x9b10a894502fc4e1L},
            {0xfa14fe8a1dd59c3eL, 0x6a9a93b0f1ac862aL, 0xdbe4d8d065053ef7L},
            {0x5c94965ff0a8e28eL, 0xc2a32a0d57f1faa2L, 0x24dc5effe1fa9e37L},
            {0x6b404bba72a24d04L, 0xbcd23a38f7981241L, 0x93d0c9eb1b9a39efL},
            {0xa53a198b9e74e59cL, 0x17cb3bc05f9608d1L, 0x21bcc23eb5e75655L},
            {0x05911f7d3220397fL, 0x7915054dcb628314L, 0x183a2a8400570cefL},
            {0x2a420bf34788186cL, 0x8c83a2945ee3027bL, 0x606a65c37a8f2fe3L},
            {0xccf4e83131d54a27L, 0xc95466a498499126L, 0xef9ac8206968b1f7L},
            {0xe457b2ff12256f1eL, 0x57fd60a454e5f68dL, 0xf3388bb1de5dd1c2L},
            {0x4addb3e322595749L, 0x39e02bd59d8ae504L, 0x20284c1ae2f1a65cL},
            {0x9fbb5574795cac4dL, 0x9fedac975974c8bbL, 0xd307ecf05fd4fd22L},
            {0x2505bb81200f8cbbL, 0x2ac9d93c45830708L, 0x11ec704af2c49861L},
            {0xfa1702dd351d3b22L, 0xbe0dfc13d607f962L, 0x82c611b8ccd1e9f2L},
            {0xb7ff038d58626bd7L, 0x86e990a7d6acad3bL, 0x5010d30fbe2d70a9L},
            {0xc42bda459ef1afcaL, 0x83c5891e3eff20a0L, 0xdefbb485c364fd5aL},
            {0xaada4d9f943df0f1L, 0x2618e51a8838b5feL, 0x8f45f0ffff45201fL},
            {0xb55e3891213f972cL, 0xdb4f56b16dc4e905L, 0x30fd462a4cf268fcL},
            {0x64e007b7010e8c80L, 0x2d0de3d26a1748c3L, 0xa2e01ed12648c113L},
            {0x5128d2b5c4bac674L, 0xb80b46283a340508L, 0x1c1f01fe24b17a66L},
            {0x4cb8ab976733595fL, 0x403aca262ff117b0L, 0xce1698b4f9a54376L},
            {0x7781e71d8805fdc4L, 0x40c3c2110800e7a0L, 0xe72e9e63999cc311L},
            {0xbb3e3e6501e45c00L, 0x9e70bd7de6780a3bL, 0x549416aa087fe4c5L},
            {0xae1da809d7eed055L, 0x06ba5804e029b01cL, 0x490555c99e76bd05L},
            {0x67f3afbbfeee6547L, 0x1243b190c38432b1L, 0xbab2fa8df7bf2943L},
            {0x6d7197464f15c83cL, 0x9283ced1147a6a85L, 0x96ba1a0e47d9dd96L},
            {0x9cbb90e485218006L, 0x8b5ff83a0210b4d9L, 0x1086afcf143b95c2L},
            {0xa07d026b378f963bL, 0x2debd80b456cd3e3L, 0xc7792b9bc7f54c4aL},
            {0x3d0bec8b88ba06b8L, 0x0c13cdfdc4d01e9fL, 0x6d256d1087b9c95eL},
            {0x9216a33ea47259ffL, 0x2bde0cfcb54abe8dL, 0xaaef421825f1b47bL},
            {0xa1aabb09b181ae0fL, 0xc14d44d54e3620cdL, 0xabb20e2a4d637bcbL},
            {0x2544eba1038d1b04L, 0xda1f84aa9bc120c2L, 0x41fd7f657a18c45dL},
            {0xadaff973f301d8c3L, 0x87dae306486ff1a6L, 0x60ec280a2570b8ffL},
            {0x624994b2704d4c20L, 0x532232f1cf209482L, 0x861b9c2a5a7d0a43L},
            {0x4513aa7db58aea4dL, 0x89dfbe8c94798ddeL, 0xe735f37739441c13L},
            {0x2f534ce65fbe5d87L, 0xf8fcb2432339f543L, 0x8ea957572a77e395L},
            {0x2456c8d764e7c1a6L, 0x7dc7567c507e2e18L, 0xd29b13c5db1cd65aL},
            {0x885705a845bb1199L, 0xebc702d7e1680421L, 0x9aeba22f533cbac9L},
            {0x55c435f803ad3742L, 0x695442fe576b3a09L, 0x5ca02fab230ee023L},
            {0x0d446bb06a3cbf8bL, 0x5bfc8414d84fff9aL, 0x157e3384708408a8L},
            {0x7b212d17c02a4054L, 0x2b14562733ba6900L, 0x7965f7d93122eac0L},
            {0x349446294451df24L, 0x2b91f57cdcc289f3L, 0x829cb5a03cce767dL},
            {0x2f8e7fa84f0ad401L, 0xb3a50f68cba8a638L, 0xde440882f84bfd7aL},
            {0xd1ba1db41829f412L, 0x9a2c4c23fb8538f7L, 0x86ca32d92d99ecb9L},
            {0x8a6db99a627b227cL, 0x633c81cf8e52a687L, 0x8e58542594d7103eL},
            {0x4c5a928b8610d6cdL, 0x6a38a81e5ec41b61L, 0x05ac22b201c86322L},
            {0x283c4b53c14f39c0L, 0x106fe171df2218c5L, 0x4c077d33f17e0107L},
            {0x198b4c90bd33552fL, 0x5853a4c2f74596dbL, 0x1018dd6bf21150d4L},
            {0x47c29e1c2f495b4cL, 0x7ec84995131d545bL, 0x49e53beaeb94dae0L},
            {0x2678b3f7b548fc9fL, 0x63a6b9322f3a574cL, 0xef6d85f1091f1aebL},
            {0xf1391f569cd5fe90L, 0x876e8ba956de0238L, 0x6cd576e3b8ab6222L},
            {0x827547465967b775L, 0x4197e1290368e412L, 0xee63a7ef2156fb67L},
            {0x6cb2a919735b34d5L, 0x6cc967b756d72395L, 0x9a884a65ae74e811L},
            {0xbdebcb5fbfafafc0L, 0xb7fc62a4c7947030L, 0x554c36728822d8b6L},
            {0x025fef80c960792aL, 0xc0f487dcc0ad8059L, 0x9714504680995ad0L},
            {0x19ffb11f02502666L, 0x482fc0fae8608ad2L, 0x781175f6049c62eeL},
            {0xf1fece4f515854e7L, 0x6dab52f7b6560106L, 0xfa0028f50d672954L},
            {0x844afcd287c1ddbaL, 0x47234b529fe3ca41L, 0x3ca221c08f88140aL},
            {0xfdbbeaaa02badedaL, 0xf35a5e21992e2332L, 0xa37f6d68d919b65fL},
            {0x6d218f603725748aL, 0xb6df3c61103e9c3eL, 0xbb7ac1cf4c1f4692L},
            {0x8e6d3eb058cfc260L, 0xfbe2f6497287731aL, 0xffa78646830d5ce0L},
            {0x8c07c328df449acdL, 0x500ba217a7af529fL, 0x19ab11b99a1a2a19L},
            {0x42de87a6001d7bc4L, 0x6d65941a9ae5138bL, 0xcb830271914ce1eeL},
            {0x25f950eb4e2b9669L, 0x0c9f7a2279a16278L, 0x86503e9de2e76202L},
            {0xedc0f3a86b732556L, 0xc7995c7b3ec0ea66L, 0x8a4d95b8d19c29ceL},
            {0x01b5ab0eca4d3189L, 0xed7898b982b519adL, 0x24c5f841a769f11bL},
            {0xde3eefe1bad32178L, 0x493a735c30942df4L, 0x8b5ec5bed8e4d565L},
            {0xa974a9d616b752faL, 0x09d37b2ab193ca1cL, 0x55b8aaf3af4481baL},
            {0x84ca6915121b1e09L, 0x8831e83e34fac643L, 0x05e3db5a89049a2fL},
            {0x5375a9f4aefd0f44L, 0xaf272fd031366078L, 0xbbd286c07ed80632L},
            {0x9d101a493aa2ebc9L, 0x67e3ddfaa73b2b94L, 0x45bf06b13a5d6856L},
            {0x6469dfeed8b766bcL, 0x41a958a8c84553fcL, 0xc3665b3f060a6808L},
            {0x8bbd23b38d0cff32L, 0x891f48bb2592fb3fL, 0x24c6243ad065453eL},
            {0xf3d1cc12dcb4e302L, 0x588dfaa464f518beL, 0xfe082e8b4a39cf26L},
            {0x95c521746547be8eL, 0x9cbbea72400d1df8L, 0x0cfdac076655d579L},
            {0xa6c4c57375f48495L, 0xd63f47b41907a3f7L, 0x34e17c2df60668d7L},
            {0xa135ca38c26b95c3L, 0x2aac9c6b01173258L, 0x2d8499bf2ed7c23cL},
            {0xba02892976144352L, 0x9e4d9906dc2ae94eL, 0x6535b5091d0535a4L},
            {0x6ec4dba2c6f7e949L, 0x02d65b71f7db3f86L, 0x61c796b0290e7ff0L},
            {0xac044d22d442ff2eL, 0x29d00d9db764b6ffL, 0x9ec4ff5f21f3216dL},
            {0x26b3c84573c53161L, 0xa3037316e91bf8bbL, 0x251ed327edf11e39L},
            {0x2917804d2422970cL, 0x16119362ba8934beL, 0xafa94e1359c77cceL},
            {0x4eac35ec04e84a0bL, 0x31b309e5e5d361a5L, 0x4171e00956fd334eL},
            {0xa02b9fdd9f6b8162L, 0xabd8bc110f4e1f52L, 0x75578ed77238fedcL},
            {0xe73f9ad96bd8686dL, 0xbdfc49ed2dba8097L, 0x054c4bb989c34404L},
            {0xa0d01888aa5b1042L, 0x8c33305a0dc075b1L, 0x75f81fe0369e7b86L},
            {0x679d711aa88faab7L, 0xb03f74deaa29c24cL, 0x10a7766990689f5aL},
            {0x827d13e4d6310b6bL, 0xc5a73641d06e47d1L, 0xf2f0d06e14e2ab1fL},
            {0xcc968649ec63f05eL, 0x17cda3a7fc25bfb2L, 0x0df1338db25ee18eL},
            {0x7d4acd6c3cf8c18bL, 0x4bd734fd562d48adL, 0xae50c4f72f542533L},
            {0xcf438bf70dbe4c62L, 0x0019bcea28ce9270L, 0xf687acda7ff8c960L},
            {0x5b24783c5318fd09L, 0x5623189d31422de8L, 0x862fd585eeb3e3f0L},
            {0xf98482f8df7d5e16L, 0xccb9fb2d3745fbbfL, 0x7d5e1bd364daa7d4L},
            {0x024849574a40a831L, 0x48cae56880d67329L, 0xfafa85469a93e6b3L},
            {0x944eae6b760bc534L, 0x1d1d18f30fec24c3L, 0xc64a74b4d0c3181eL},
            {0x19c52990a4e62d2dL, 0x37b473c7ed759ef9L, 0x04080c0ade3df738L},
            {0xfcc4062c7876c075L, 0x48b4cf0b72aae741L, 0x3889eef0b66c1bffL},
            {0x49c26471ae06da0bL, 0x109da4749a70108bL, 0x443b50c74915bd54L},
            {0xbe68bd432e672eb8L, 0xbe737af593618ab7L, 0x5d537d8c0da1a4e7L},
            {0xa3ca7393ce4e8d7cL, 0x0fcf46d53a057c21L, 0x7451a590ca6c1db1L},
            {0x79419444b1c149e5L, 0x9d577a1e13240b2dL, 0x24da1fd0d5db6e4dL},
            {0xe8c3caf37ad5170cL, 0x423b4593d3f4c834L, 0xff039eaad5042ae3L},
            {0x3bf5913b5615f7f5L, 0x2d24b840238f2c84L, 0x97bdc5bfeb1d53b7L},
            {0x53538b2293df4606L, 0x169029e2d8675ec6L, 0x9ab1ac25ee4982a4L},
            {0x75bd284d07f591f8L, 0xccdd36b98d68786eL, 0x9321ba79d2e56eedL},
            {0xe63236d17de7e69cL, 0x9600d5f5cca5b08aL, 0x8ff14c81e5d61843L},
            {0xdb079962536683c6L, 0x35bb6068eb26bd37L, 0xa614c37971ca2e4dL},
            {0xab78167ac83c4064L, 0xb6a1928d6f89cdd1L, 0xc97cc61d01ffe82fL},
            {0x83e6edd7a512e8b7L, 0xe281601e537bc4ecL, 0x19d35d2d57518cdeL},
            {0xf737f3ddfa7fc9b2L, 0x4a8f04a9cb4847beL, 0x2946f3355994de91L},
            {0x577ca3baf1f7e1baL, 0x446729b10c51ed7cL, 0xab637d9c6e3a5554L},
            {0x4e31798071664defL, 0xec15c968e363630dL, 0xd7ce5f867f758e48L},
            {0x10525e76bc5a5ed9L, 0x1c8a384248ab4398L, 0x8f7a522f2e2f3fc5L},
            {0xdee25133572d24bfL, 0x37203f7f6c2e0e36L, 0x89ba27d9b1233156L},
        };

    private static final long[][] aim2_constants_256 =
        {
            {0x24a19947b3916cf7L, 0xba7c9045f12c7f99L, 0xb8e1afed6a267e96L, 0x2ffd72dbd01adfb7L},
            {0x0d95748f728eb658L, 0xa458fea3f4933d7eL, 0x636920d871574e69L, 0x0801f2e2858efc16L},
            {0xc5d1b023286085f0L, 0x9c30d5392af26013L, 0x7b54a41dc25a59b5L, 0x718bcd5882154aeeL}
        };

    private static final long[][] aim2_e2_power_matrix_256 =
        {
            {0x0000000000000001L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L},
            {0x13269d7dcfc555c3L, 0x6fe13874c42fedfbL, 0xc69f003d9d5abb9cL, 0x05636fd04ebf7febL},
            {0x7a273dd9fcec7e15L, 0x42cd3eb54144ea68L, 0x5a88aaa3ebaacdffL, 0x527284e39fae2053L},
            {0x56bb9ab537abf542L, 0x768c3d772850c862L, 0x0160d91d288fd0e0L, 0x342e111e0a022022L},
            {0xcdb998ce4b3eee2eL, 0x78984c4dc99c90aaL, 0x2bb89f84c00275b6L, 0x75c6a0cc065fd4acL},
            {0x74b2cd2360cb32afL, 0xbde82f7cf42dd1bfL, 0x7ceed82d54d965c4L, 0xf4e9f207aa17f2e9L},
            {0x995d5aab614ac6c0L, 0x1563800b79242f35L, 0x1d940184c4509090L, 0xe6558fd024716b90L},
            {0x8d0b793b4375cc8aL, 0xfcf792217776a3eeL, 0x5da44008043b7450L, 0xc77adf87407cf838L},
            {0x00451596f23df45eL, 0xd8bcbc0d7ae8534fL, 0x02c26abe3748db45L, 0xb37e029dc51a4b41L},
            {0x177dbfce6cbc8c0bL, 0x62cdd72c8cbd2d2aL, 0x568802d992bd7a2cL, 0xd0082d2193b6e383L},
            {0x221e6872863f45c6L, 0xbe5a9bce6c00df76L, 0x98c076efe1cfcc67L, 0xa75bdc7ab5c142a9L},
            {0x088d4e8e27e0b74dL, 0x71046740fe7e6c5aL, 0x20123cab6052c1d6L, 0xa7135d055351c99bL},
            {0x46176449341c7657L, 0x2a7936011468475eL, 0xc347e166dca96014L, 0xd79326785eee3555L},
            {0xc6b77e5a8b6dcae9L, 0x6dc641a8e07c54d4L, 0x37055c3ed77341a8L, 0xd75eaedd0ec6f1d1L},
            {0x5240b9b6f3433443L, 0x7b7d965745400c05L, 0x4542be5aec50ec53L, 0x13e6ac8f2aac12a2L},
            {0x66c30b9da469d401L, 0xcd5dbf02dc359172L, 0xf16b3e62f8a57e1dL, 0x362c2bc9345b97edL},
            {0xb2a65d5f7da755e8L, 0x11df10d6ddd9eb84L, 0x433468d75cb64470L, 0xb4a6ffd454c82b2fL},
            {0x1c87142145f7c112L, 0xde2854fa4939dc0bL, 0x10a503b51b7c7a19L, 0x174f91701431e1b3L},
            {0x60d8fb32b890cec6L, 0x27d95c11548f693cL, 0x30fce7ce95e950b3L, 0x210559008a309578L},
            {0x5de49c870dd8fb60L, 0x1f480e246bb2c961L, 0xdc5efcb1f4ee90aeL, 0x165c3f5b62136c5eL},
            {0xc17b4bbe4b5780a8L, 0x690f1102a6decffeL, 0xa26e146710d9cd7dL, 0xc7f278fb3f02a99dL},
            {0x4fe7916de7e17f1cL, 0xe9e59586ac0a7185L, 0x092b72935bc23437L, 0xa306568e985edbfaL},
            {0xc05330df507b35c8L, 0x944475d0eb5c89f7L, 0x34a3653b083969a5L, 0x97e431e62e205633L},
            {0x19fe581ef3e9a896L, 0x720ab1851376eff0L, 0xda5ca1af445dea40L, 0xe3899fd1cdc93f2fL},
            {0x7a18d867d11567d6L, 0x14e706af946787cbL, 0x2ececbd0e726236aL, 0x66a864e0c387e806L},
            {0x0a0a9e1dc2c9d30dL, 0xa1bd85358585db7aL, 0x78f90bb68d83e25eL, 0x2275165a7e496039L},
            {0x23f2e1a2057c9892L, 0xb7f503272b51fa8fL, 0x0ecf56cbb57a6021L, 0x77f77f889ecb3e74L},
            {0x237633913a45a827L, 0x3a2c98b4d38d139bL, 0xbc1dfd5ddab4bb19L, 0xf2bcbdc105b017fdL},
            {0x9a53645fca466120L, 0x07335188ef82289aL, 0x9cdd8f1434ddc4c7L, 0x25afc28ddf0c0ea5L},
            {0x0166bda62c3c97acL, 0x4821343275a35741L, 0xa4a1f8ef377f5177L, 0x3008d4b041fc0802L},
            {0xed498663eb9138f0L, 0xb16289e1ea93949bL, 0xa2476ced73badf6eL, 0xb384ce50cdee1d75L},
            {0x25430e5e2ea409d8L, 0xf8909d2164becc11L, 0x77663884798e456bL, 0xe11b963640c6a7daL},
            {0x2a5ce7930313e789L, 0x01a1b717dd5e72f3L, 0x674b4810dda58bf3L, 0xb348d6cffeee2602L},
            {0xe4871c9932b98648L, 0x90432c7798b61577L, 0xf803346f3989e611L, 0x176c5f43490e3127L},
            {0x28b7ff52a8d039f5L, 0x2549d26014bcb371L, 0x7705b13fd068e5f0L, 0x22f60aec7063b440L},
            {0xa90087e5804b094eL, 0x17b587e9f7b1334cL, 0x7e9128a8fd49f502L, 0x10a15de60dcc1259L},
            {0x676fc8232449f7f5L, 0xa45eba0b86ee4f8dL, 0x48d0f0583763ed04L, 0x9430177369350009L},
            {0x8bb187487d0ca392L, 0x8b34c408cf71198eL, 0x4c5b9033c740f6cbL, 0x15165d415ea592e5L},
            {0xe25b8fc9315d8b10L, 0x6f067bcaaa5db46fL, 0xc0d574e6df163bcbL, 0x76d62e45eeb26cb3L},
            {0xc7bb4eaa81af7e21L, 0xc0c25e2c4da66ca9L, 0x20a5b7a6ef682683L, 0xe0c40a42bed8c878L},
            {0x340b283a1f67eb72L, 0x94c68ac57747d7b1L, 0xaab540d8883c7e78L, 0x53ffb196e81fbce0L},
            {0x03d1fe920cc5c8b6L, 0x2d058e7c02de80d0L, 0x349140f34518313dL, 0x52d8d34dce452897L},
            {0x3daf5481e615a4ecL, 0x1d21ddb2b19865a7L, 0x28572f8e3caef8c4L, 0x94f0069367dd5a9cL},
            {0xf97efd31544a2432L, 0x79cc100bcd1c95c5L, 0x630dd7dbdcda2efaL, 0xb0c94889efaeabe6L},
            {0x1855a973cd69d2acL, 0xa249d1e68760fda5L, 0x9bd185166791f0b0L, 0x73aad654a16f87d5L},
            {0xb64f4c4f69887572L, 0x0dd0ddfafeaec759L, 0x9a2b2e01a2dfdf21L, 0x23e6842e19958e74L},
            {0x47126f2ed9d35243L, 0x2dd26a5dc07d8ab7L, 0x5f7a0864bae59fefL, 0x84bd4c2d7eef707eL},
            {0xc2b75aa6809fde33L, 0x4e05ff4138a1458aL, 0x4283e814ca9b30b5L, 0x46b1bcf0f62d4313L},
            {0x83f0c7c594f6cf9aL, 0xdb8a4b8e5dfe204eL, 0x44a803aecd550290L, 0x96cc8907871fc11eL},
            {0x7ca33f7d36e71a53L, 0x609b8f2296791418L, 0xd9e9118ba8ddf5e9L, 0x813002deae63def5L},
            {0x5e3805abc5d66c85L, 0xe95aac205db8a39dL, 0xfad61d269550a976L, 0xc0c3e22037926992L},
            {0xf3ba3f8e2a564d34L, 0xfd74426f936299c0L, 0x23bb54e8112b82e3L, 0xc5afe8e8365a6000L},
            {0xb733edd6855182efL, 0x5ecb1ae3728f48e8L, 0x3b8b1ce5bf96e304L, 0xf3aba2a7bfac4c59L},
            {0x78f2ea71794eaef2L, 0x59f25ef7fe359b84L, 0xacfd3e59513654c8L, 0xd1e24fda7d0c3936L},
            {0x288da25da8b17fb3L, 0xbe107e7feb777a7aL, 0x166db15573baae6cL, 0xb5ccbf5cfe3e5135L},
            {0x4637849d0285089dL, 0x4f671ebc0437c2ceL, 0x188565bc785f8268L, 0x712dec2cd1ba005eL},
            {0xa25a6b6a471a00b1L, 0x6e1a6a380bb57611L, 0x3ef50b155eddd23dL, 0xd3788fef109d4e3bL},
            {0x4f403f37eba563c1L, 0x76a201773cddd009L, 0x58fba6bec18e06a6L, 0x11a19d4cbf2a6331L},
            {0xe3e6bbb73066a175L, 0x9748c56fec4b9fa1L, 0x406aae141855018cL, 0xa1410c0e735df446L},
            {0x5e569e71e70eb719L, 0xa673071887dd4687L, 0x07055d8d0a23d785L, 0x74d498384aee1190L},
            {0xa0e8a89b6fb6984dL, 0x908716f3ce5edf66L, 0x0a2b9e842b73e729L, 0xa1b9171e0b83204bL},
            {0xbe7532657aadaa20L, 0x1b66940116e06582L, 0x7385fd540009963dL, 0x847a9b51570e7ff8L},
            {0xe9395fd61662cbe6L, 0xb3a286d4b91d1353L, 0x455b0689d3ff2d83L, 0xd56078fc7681e787L},
            {0x8b470957a3441b8aL, 0x7df431ebbf7e447bL, 0x0e0f4fa397edd83cL, 0xd793865c1388620eL},
            {0x7b29927808bfa739L, 0x96e65ce20d51654bL, 0xaa8fcec0d3c045c3L, 0xe5f31c0e239b4feaL},
            {0x5525c2a74e77bf9eL, 0x88cf3be85881afffL, 0x7c81312941d70c3cL, 0x23d8a44e23a9c737L},
            {0xb869097f96d421f1L, 0xfc5054b0f253daf5L, 0x1c241e84b424d6aaL, 0x32b29f522eb351e7L},
            {0x6a466e2ed7c0ad0bL, 0x5590c446ea6f583bL, 0x56d2464d3ee4d099L, 0x068910c7eb32dd95L},
            {0x71139d1bc66bb641L, 0xb3a1027da065feeaL, 0xe04294fcf6174557L, 0x81dae384498adb46L},
            {0xf43ed00c527a209aL, 0xa5754026d1f22c89L, 0xc78a8d365f196923L, 0xf5154817fc84f220L},
            {0xae764c7fe7341054L, 0xffc86134dc4d880fL, 0x1b6a1e1530d66862L, 0x250c95737b7b8284L},
            {0xbfee6b3c1e46c128L, 0xa78dc08ba0e7251dL, 0x3a95f11bcef9d4c7L, 0x34f2831709c6a420L},
            {0xe3a3c1aa9e2407d8L, 0x4c1a200af1077851L, 0x8965a32110544d77L, 0x6354a05036f3f5a7L},
            {0xbd108a58fc17d8a6L, 0x61b0351824a54794L, 0x499e7fd9fdd626dfL, 0x850217a6be595511L},
            {0x53f2510fb68b5c61L, 0x5b122cfd2501b4baL, 0x7fc88679758e8262L, 0x233472936a675422L},
            {0x11965eaffc401c95L, 0x0af31e003ba1fb12L, 0x2facfdd6611b7f8bL, 0xd67eaae060c88abfL},
            {0x6fa46680edff5f3fL, 0x454b6266e25e87cbL, 0x9addf096cb1df0afL, 0xa6de67c1da83476bL},
            {0xbf6f0cb8a600033aL, 0xf520f28cc3846c4bL, 0x008f972a2108bd6aL, 0x55bbe0da272b6cb0L},
            {0x9bf38905d29c13e7L, 0xc50cd62db6acc3daL, 0xbb9b791e0d47ac11L, 0xd54b025508c245d8L},
            {0x3a2547ab532ec9ffL, 0x79495ddf670c8bc8L, 0xdf4ed2dcee44e1bcL, 0xc2e52f1fc1f7d4d5L},
            {0x4800ee52ee97ecdaL, 0xc9d9b772550e380cL, 0x98506ba8ea5ec019L, 0x21ffafa8b46c668fL},
            {0x3464a9138085b307L, 0xf67a192be113e9ccL, 0xfdd61b66e0e162dcL, 0xd612aba17d397d2cL},
            {0x16207c45e571aabfL, 0xf2583066040bf4f7L, 0x4bc24730dc4d62f5L, 0x608b3d1e61a60b2fL},
            {0xc2a6d2c707faaab1L, 0xc9cfa575f99f891aL, 0x61ea461507f40f96L, 0x67104299d7331a82L},
            {0xaf1c8fcbed1f1699L, 0x985767a5dbb95b90L, 0xd6ae3b3279c96a14L, 0x275ea501029834e7L},
            {0x4e19e32114de1e9cL, 0x165f71d116e0afb9L, 0xe968cbf378c1a2f7L, 0x912182eb2d02ef2dL},
            {0x6e4e3c81caceef19L, 0x85f15b2e37fe2cbeL, 0x8ae88fcc89bb8687L, 0xe50b4d7659484c7aL},
            {0x80353d06c9930d5cL, 0x723d1f993acaffadL, 0x89e273ac935dc5e2L, 0x51356090a9eecbf9L},
            {0xc3bd743bf118e69eL, 0x78fe213d42306293L, 0x90638ea842ff3668L, 0xb0addcda3683625dL},
            {0xe26008c6b83cc264L, 0x74bbbd5777680be8L, 0xa8892126f9cc485aL, 0x54899977a5cc34a1L},
            {0xd19b2baf7fa0c771L, 0x39d199b5dfd41569L, 0x7c3c66294bc7b31dL, 0x81bb86cd53109ac5L},
            {0xe4a790156b11f26aL, 0xb496c49018830c99L, 0xf19e574456b9d549L, 0x867aa70b9bbd4fd0L},
            {0xb8ce927c2afbcba9L, 0x3ae3f9d11d478318L, 0xebdecea6a113ffd6L, 0x071def720f45ca33L},
            {0xa18c4347c3dba5daL, 0xc231d50db69b59f6L, 0x784caea3c01900f9L, 0x21b179202d1177e0L},
            {0x48d839b0e148b37aL, 0x119910fe9c00220eL, 0xf6959f7654a471b7L, 0x138df428ee1ab05eL},
            {0x2378b25ea2d743c2L, 0x52a0660820b6ff4bL, 0xb20d6835419796a6L, 0x77d41062fb9a7654L},
            {0x1e63666141c834ddL, 0x534d884045bcdedfL, 0x07b52ebe10206e92L, 0x67cb1a5c5d2017bcL},
            {0xbd489efa4249447bL, 0x81b1f830bdd020d0L, 0xb8db0042e390a71bL, 0x90b877cf8d8200e6L},
            {0xd91a2f7fe76f986dL, 0x2c6fcd64257849b8L, 0xcec2c4be6ecbe77bL, 0x5031f045518f6b98L},
            {0x3cc9f99a10cba6b9L, 0x7df264605ea09f19L, 0xc6099006fa2f35a0L, 0xf31aa1999c65f2edL},
            {0x7322250ccd66f2d2L, 0xa8cf62816a34838cL, 0xf7bd30878c6d359bL, 0x450a14aed0d49014L},
            {0xf753996b7d7c1d54L, 0x45e2b366fb683eaeL, 0xcef4cef44af75b4aL, 0xd1e647d51db49a04L},
            {0x257099ec419b94a6L, 0xd4a8a9f3335fcd10L, 0xa286788285415010L, 0x023c9feb9c1e9901L},
            {0x229d6fd7eed1531cL, 0x04cefb6c19ff0062L, 0x9130be016eed6e29L, 0xa1a04435eb4cd39dL},
            {0xefbd279ed0b045c6L, 0xe8ec58f13b1a927dL, 0xbabddf060b172c30L, 0xa5fd98adc4c9d7f8L},
            {0x0f859d44ce18448aL, 0x07af518284a5a680L, 0xff7565589bc19136L, 0x72e50c2e9eaa580aL},
            {0x6470f3d6724b5dd7L, 0x8b0ebb24be876d22L, 0xfb604e14fd34a2ccL, 0x213fc1d31fbb7996L},
            {0x50e1d4f6f24a3685L, 0x69348d20cb64f7b6L, 0xa13da095f7678267L, 0xb63a6ac7a66c3284L},
            {0xb0edaccd9a8698dcL, 0x73d7ca79b1672272L, 0xaed4ffd76475e235L, 0xf36b5b0cbbb22a1bL},
            {0x24acd40ab0b10abaL, 0xafb39e3ea0656a92L, 0xcfe743611a51fa5aL, 0xb4f8251f0f0e0d41L},
            {0xe8036bb95086dfdfL, 0x3d5d0332c379fb16L, 0x3029edc150437ed5L, 0xf561ce7ace559b0fL},
            {0x01047fd87eb154caL, 0xce04d75cd86f0d9dL, 0x33f6d9a762e84d0bL, 0x52f77f2619632746L},
            {0x3fdf7a3e2584aaa7L, 0xafdff63009b07776L, 0x24496f671e85ade5L, 0x35b2e80c0abfdee5L},
            {0x4bb3e9185acc78b3L, 0xe5634557a7f532a4L, 0xa6a979853e645782L, 0x97e9a6c3f5ed6068L},
            {0x41685f9547d8c651L, 0x6d4bade8828daedaL, 0xabe0dcd781a5b523L, 0x3528952d2a770f19L},
            {0xe4e43b26b587ea84L, 0xf0f3f420178def6dL, 0xd48cb1f978a8bb2eL, 0x25de266fb8567a86L},
            {0x2906276141285c5cL, 0x045688d8cac52240L, 0xa1a62b2fa2474687L, 0x917244641b004f87L},
            {0x73897ebb86a40eb0L, 0x0df1bc6722ab333eL, 0xb7815fffa0c79792L, 0x322111adf2c83d06L},
            {0x4dd181aa27fc54faL, 0x47b557267a691a35L, 0x089b8ed1303c2515L, 0xe60b63596c40b943L},
            {0xe574bb3f5e1d3fe5L, 0x7e5e1dd1aaea6c56L, 0x443b9d58176d285bL, 0xa2c066cf80f1c62dL},
            {0x9df2b1fe93b4cb69L, 0x5dc5dcbd7bcd4304L, 0x4cac45f5c51659e4L, 0x9039bc7472f02b80L},
            {0x81c7d14b2ff6f3d6L, 0x76b7422e6f000e01L, 0x23e23fa520ed280bL, 0x50a4f9ded0d07978L},
            {0x154548397391fa38L, 0xb1ec123aeb772341L, 0x22f40fd3abeee812L, 0x0342edcc39a77162L},
            {0xa7ef812f5e9d9ba6L, 0x65de86bcc8071b0dL, 0x4b9bbe60fe0a1fadL, 0xf4f8322efc5e2f45L},
            {0x21fbeab48a7c1136L, 0x42736db042991d3eL, 0xf78c442fd2ed07a6L, 0x36228053a90abb56L},
            {0x6ebfcec360d88021L, 0x7deeafd7cae1b159L, 0x6f32c272246a4999L, 0xb2f984f6c2b488ddL},
            {0x76beda6b3d15abc7L, 0x1bc04ff70ef9d0a9L, 0x75ec5c46c4854ec0L, 0x77bd25a817826a51L},
            {0xf79c8d9bd7aaf4f0L, 0xae5add9fd1454f93L, 0xd9f264167923d698L, 0x273bf89c8b33a9ecL},
            {0x20ba5517532e42a7L, 0xd9991aaa0bcb040fL, 0x81ec69b31aea8c89L, 0x823ee1a07f410f90L},
            {0x3e10957041e49998L, 0x9746fdf5f3deb53dL, 0xbae6be6d5a7923ddL, 0xd4aa255a7e60b5f8L},
            {0x453e76f50e50f914L, 0xba084020e530dd32L, 0x90e9982f02a0b2e3L, 0xc1bf6d0c93565fd4L},
            {0xbb44043183434a96L, 0xb6839987e4d3fbf5L, 0x780e11ff154ba921L, 0x46deb765191c6fadL},
            {0xf254860f62ddca11L, 0x2b40c2147fcc1618L, 0x9b9df4f2213a87f5L, 0xf5d9f1982bf72085L},
            {0x9ec887ef1dac7ea8L, 0xf9b9f41cd1a90cabL, 0x5106c66727088891L, 0xa079314a8a7aa0ccL},
            {0xbaca971f705d6820L, 0x32cf35c216d31b74L, 0xcda1b48f6a782676L, 0x42dd0c61745b57afL},
            {0x774f50e70700fa3cL, 0xfe706a77d17875e0L, 0x50acd4b9e4f085bcL, 0xa70b2f3a3373b5cfL},
            {0xa3d467e6532333edL, 0x9143409c675fea0aL, 0x186d4c8b7de757dbL, 0x006e698e91bc1742L},
            {0x042690d62241c815L, 0xf8a04fddc8420797L, 0x9ff8cf1394eaada4L, 0x921b7749e0687334L},
            {0x3ba03d72cd709236L, 0x12f95d885e21e3d3L, 0xba18560bb5d4d50aL, 0xa3607627494476abL},
            {0xade31f9ca5377f89L, 0x635510178eec1003L, 0x3dca939c351bf98dL, 0x339c87aee1cf78ddL},
            {0xe45a6287cc1287d4L, 0x7cf6c8c56ed07634L, 0xadf6eda911dd0200L, 0x87211a5d3722f0f6L},
            {0x7b07d341c0de902dL, 0x69838993df5c9429L, 0xb8921642be862244L, 0x555819247b006ccaL},
            {0x4b8ebd3e261a1065L, 0xec8c767eb1653cebL, 0x482e17c892519544L, 0xb61af0cc04b533a5L},
            {0x4fb9d38c4e2f7113L, 0x50030b8523699320L, 0x5716f5c60cedd7d8L, 0x0673e662c18aadefL},
            {0x641233031f77a5fbL, 0x1932c76990a0d465L, 0xb79ab4fbf32c92e8L, 0xc0a7370dd0467550L},
            {0xdb899bf50910763aL, 0xf026477f262eb097L, 0x76b70a1b2163a0d4L, 0x93a2873f23165f6eL},
            {0xba2a66c196ce2eb8L, 0x19383fd3ffab287bL, 0xaed33c3223646076L, 0x1274559077e98698L},
            {0x035a94843c44ec7aL, 0x6de99478a3c009e3L, 0x8a7ecba43ae87e6eL, 0x458c9cbfca30c71aL},
            {0xe3695ac8419682c5L, 0xaeee4d4d0392ec66L, 0xd99792a67250c187L, 0x91e0f202f4c924b3L},
            {0x9c784cfbf5192c27L, 0xc113eee0e80c2eaeL, 0x3f7b5a6101ce5f5eL, 0x842e2d646ecd9d6eL},
            {0x957028a6befc0d73L, 0xcbb8df5afe2e23c3L, 0xc00f5c490d8dafb4L, 0x67d7ee99cddb8452L},
            {0xac8c3e869f704d2dL, 0xc928ad50bd4faf6eL, 0x114a0001a078d1a0L, 0x8375ad6cc681586bL},
            {0x59a53e3fb149cca9L, 0x69cf3f7ab419768eL, 0x79d945a746a788b8L, 0x979b7e9387ae017fL},
            {0x41f7712568f43935L, 0xf17647a51bb6cff9L, 0x593eb0f68e21db19L, 0x77bf0442e77fdbddL},
            {0xd430085cbe62c90eL, 0x445d0af933a0c884L, 0x92f5c9b29a5de145L, 0x6778e9aad04a6c94L},
            {0x4914b4bd446c5d64L, 0x21b19c795fec736dL, 0x72cf9cdf7fa1c0dbL, 0xf67226412058b23cL},
            {0x1e7346a99e1464a3L, 0xacb82da3ac217e94L, 0x4d1f4486473e6c18L, 0x23274da141c63725L},
            {0xf58a0445c9b4903bL, 0x4f196615648056a4L, 0xeaf0d8fc78e51fe3L, 0xc71e969830bec69eL},
            {0xcec3175fd17dee42L, 0x6fa60eda34cf3b0fL, 0x016ff6fe365a227bL, 0x148ed225daf52abfL},
            {0x5eb5954a6c060dcdL, 0x67ed2e3411fbde9dL, 0xdaddfd054f15c5a4L, 0x80e12ae0d1591ef3L},
            {0xc9c76eda44553b71L, 0x7c4675538cbdcd1eL, 0xa2128f16928c1efdL, 0xc13aaef8cfacc959L},
            {0x525318d3ea7544bdL, 0x6f3e0f4d85ce7b2aL, 0x397102e6892ab449L, 0xd028319bc9ef0676L},
            {0xc55bc06690da6f96L, 0xea6a73d17ce2969aL, 0xfa21bd37fa658e1eL, 0x32d421c8c9a9d437L},
            {0x4f53f0e462a9f4f0L, 0x18c65d2ba362d43bL, 0x53b8871400599e70L, 0xf291e9ac535cfe6eL},
            {0x2a420a66918ee17aL, 0x4dae04d613a5a05fL, 0xc12c868048f09ef7L, 0x900c4ca4fb306ac2L},
            {0x357f0638ee05acbcL, 0x389db47cc78620f7L, 0x3c531ff5b9fff02bL, 0x902c96f5fb2c18f9L},
            {0x57abb6151ae9319fL, 0x917bd98253c43360L, 0x36b4e4e17d9c5182L, 0xc2a4751705897c3bL},
            {0x91ee0ad214084c1bL, 0xfe17b657a9ea9054L, 0x7b304880e7a3efb6L, 0xd497c8cea46cf443L},
            {0xb97e1c63dcc46441L, 0x22898ec1ecb0f186L, 0x40dd2915e34e92aeL, 0x83e63e8886604034L},
            {0xf159f13af4545efcL, 0x6b0312cbfce549f7L, 0x1632f9e6624b3c5eL, 0xc387a21c7c20a6d6L},
            {0xe81b4468c49ba628L, 0x9962cd4b58abb1e7L, 0xda2145ce9fe59f2eL, 0x6021807944cfc8e1L},
            {0x9e98852b17310f23L, 0x3cbe1c8bceb45120L, 0x0e165b29c57ec0ebL, 0x305bf854fb1aea8dL},
            {0x1c3dbdac479d54f7L, 0x4cda9c1c1bbb1a19L, 0x7d330c571f17bc88L, 0x826548b30e26b7d7L},
            {0x446afa2ca1809535L, 0x8d3c9693ee673350L, 0x7893a83f58de1ffcL, 0xb19954f7647195ffL},
            {0x21b77a7b577e945aL, 0x0c3e91d3f1f89e09L, 0xdd7b8e8a59fae93cL, 0x6435f276c4582559L},
            {0x4d0e6426007bc199L, 0x5c13184bcf7dd24aL, 0x26f1f87322e213d0L, 0x97243e676a3eb387L},
            {0x14cbfff5b787deddL, 0x355794e80f8cd847L, 0xf2c951e3c0d77a3dL, 0xe558cf2f7b5f2991L},
            {0xf87b23ea7452e43cL, 0x92521695b010b548L, 0xb7af363918a98cf1L, 0x473e6304c6f3f9cfL},
            {0xe86f5e030902695aL, 0x884c59759075978eL, 0x862a4f44f20c857dL, 0x2348092c2d62a7edL},
            {0xbebdf27580f800b3L, 0x4c82348a99cfaf36L, 0x7fec6e2fb343c70aL, 0xd0a2b036a8d95707L},
            {0x59ef03fcb5a57f39L, 0xfb04bb079290dd73L, 0x30e0751c7c8e4263L, 0x4078bcf952cf1a62L},
            {0xa19ffba37095d58aL, 0x9d164dabb30dff6aL, 0x16de88d2bac7642aL, 0x8232b5dca704cbcdL},
            {0x329dfc2b2636492cL, 0xf0397ad762a31307L, 0x78adfe730ebe751eL, 0x5783b8d9d2f05dfdL},
            {0xf2d6e8a736f23aa1L, 0xe2102f9bd2267093L, 0xdf2af690beecc500L, 0x11398c83a817f593L},
            {0xd46565aaafab2385L, 0xddff3f9a0b99928dL, 0x5eb2072a49c5a5abL, 0x53a03f6a8eb6a094L},
            {0x57fb689ec7092868L, 0xc2040eb173de1a44L, 0x810031fb7b19e630L, 0x53960a9b3b1ef568L},
            {0x40007920454fbf71L, 0xac025a589e98d1efL, 0x9e256036a7fbd143L, 0xc13cf073bd649440L},
            {0xd06cd6829f0fea3dL, 0x2a51b1d71d1ac07bL, 0x3546a5854571bbc6L, 0xc30b6bf46c0b42feL},
            {0x62488646a13da231L, 0xe28973393fb6f682L, 0x9ed13dc9f5432f8fL, 0x31b84f2be241c94eL},
            {0x9bb19ea5428d66aeL, 0xe0080b8616f3babcL, 0x9610055711788ae5L, 0x7652d184a46c90feL},
            {0x112c63f926d9850eL, 0xe5905a268850e663L, 0xb9fd3996e6d72608L, 0xa7aa33543146d58aL},
            {0x77de728df392f575L, 0x637633946129f8e6L, 0x72a867e08e3bfce6L, 0x754f7149e15a365bL},
            {0x3511c4139b98679fL, 0x56a8a361da8cbe81L, 0x2a34d15423a9eb45L, 0x82ae1da57cd32e57L},
            {0xcb3ecb886171f719L, 0xfcbf82d884e8e020L, 0xc6d2502bd1e6f6cfL, 0x80bb7b1db5c2a777L},
            {0x81b8745892f03d2dL, 0xbc5f38b14116148bL, 0x4b6d0194055b86d8L, 0x241dbd17e3eb4ba9L},
            {0x5bbc585152fcd142L, 0x930f31c230a2050eL, 0xabf51e10a3e969e5L, 0x72a0a1c90ead638eL},
            {0xcadb18ff93f7f93eL, 0x1b8e009b5719bf82L, 0x743c0ab2c8bc284aL, 0x7144a02ff1130223L},
            {0x41b95e62522de019L, 0xcd3465a01c9b93fbL, 0x236600ff15e70ef3L, 0x3658cd0c29ea6f20L},
            {0xb9c59bf0b27dc282L, 0x47955c29304112deL, 0x3f16c72af19bcb3fL, 0xa0e568c9c5397d69L},
            {0x9251cf7a209add18L, 0x8e3a95a336fe4170L, 0xf28c14a751527126L, 0xb3d3a9a208590971L},
            {0x5b129f35a37c28ffL, 0xe3f8ba25b41817b9L, 0x200b734d2501265fL, 0x52344985724ccecaL},
            {0xa8e27fd1e60dffabL, 0xa8ea4523b64f5aa4L, 0xa475b8437f8165a1L, 0xd644c1691c3c7548L},
            {0x5ddae2f669e64957L, 0x1fcef31f0b9af756L, 0x3e6da61c7980074eL, 0x206f828242ab6764L},
            {0x33144ea9f76bb631L, 0x9f36e03e21fa3065L, 0xfe08e97dc86bceb2L, 0x640b723c98cd7479L},
            {0x1636152634146114L, 0xc18c0793a80805cdL, 0x2b106edd3834043cL, 0x4191bf5c7fbacdf8L},
            {0x429dddfd03ef7bc4L, 0x4db9b9d6da197cd3L, 0xe74baaea7f22abc0L, 0x4364ff1e20f72e64L},
            {0xca8a9a678e94da68L, 0x6535f14dbed15563L, 0x98f34f0a20bd3f3cL, 0xd12c84164701e27fL},
            {0xc02c8d4c379b7ce5L, 0x7069499c81e1f16eL, 0x9bf97727b1a05c04L, 0xf27fa10bb0a78610L},
            {0x4cf536f0cf11a349L, 0xbd9dfa2a6eb41391L, 0x565f1d6e23bbbc0dL, 0xc76bbb697c18cf7fL},
            {0xa17601bde8ac478cL, 0x8db87c51403e365dL, 0x4088a87a96d9c622L, 0x31f82a7918dd0d06L},
            {0x29ee14687120f04eL, 0xfea2e736c3636d5cL, 0x7f8c89823855588aL, 0xf0da86215a008e8cL},
            {0xdd645ec1d816c223L, 0x0aa7edbc5ba5d0cfL, 0xfced1c8e126396e5L, 0x201b07bc6f65eddbL},
            {0xfb25e20cd48f4855L, 0xa8b3d1435e85371aL, 0x3ee9acb3f939329eL, 0xd075efbe502f25a4L},
            {0x0541c9b35049c704L, 0x94986dc9cd668f39L, 0x17f4cfb2726cd68bL, 0x508c14a670636ed4L},
            {0xa2b783ac55d68039L, 0xc130ab2d841d773eL, 0xd6d29b14f588465dL, 0xb790ad979cce43f8L},
            {0x4f8ce0df03c43b98L, 0xbbda15818c06d7a2L, 0x380dd95f0f042fdbL, 0x05f429bccfb597f3L},
            {0xc742e63ad5c5f5e6L, 0xcbcb225fbbbe33e2L, 0xa8edf59089d52cedL, 0xa0e788a338b45f4dL},
            {0x20e95da4bdb0c82fL, 0x3e63b532cc85e2d9L, 0x163e3d2b90d4ddafL, 0xc71593e07530219aL},
            {0x7992357ab8d37b59L, 0x4aea96f315f3c064L, 0x1ba04f945b33146bL, 0xf65bed5593247ff4L},
            {0x2d4ad59bdce5563dL, 0x3a24253d449dc88dL, 0x41c7ffbd062c28f4L, 0x42734ae219aa9361L},
            {0x644204f2ea9b71e3L, 0xe551983ade3b5122L, 0x1bc727382db55ea1L, 0xe276d03e4bd6fc9aL},
            {0xfb20c1e51a924e81L, 0x2f795f1d4507decdL, 0x154de4d0aca02046L, 0x72ddcd99451381ddL},
            {0xc09ac8020e255c2bL, 0xa4eff29a2c29d3f3L, 0x7977c4f4c2f24381L, 0x349ff7a6efa4d791L},
            {0xea5d2cd9592cb4e6L, 0xf63dcd3ff0c8104aL, 0x66d7254c1252ca0dL, 0x822791068962c667L},
            {0x7b9c477dde2ad4a4L, 0xd3460c638eb797b0L, 0x1889eaef7acad771L, 0xb23db19bd8554e11L},
            {0x6f1c469240cd647fL, 0x31825907e279b274L, 0xb97cebbf2c37c29eL, 0x74ce50e87690b22eL},
            {0xfb92d64637ac0508L, 0x97999c37b92d0720L, 0xa23a9e76c1578849L, 0x66aa9c79979e14fbL},
            {0xcf78e912e65a8877L, 0xb7dcb878bdeec090L, 0xe678ac56695a99fcL, 0x0338870b34c11ceeL},
            {0x5529c228e771c374L, 0xd8ab910e6e0a23f9L, 0xcd86f7b11bf07839L, 0xe3358c0867358f64L},
            {0x7c0e69e5db7dc1c3L, 0x355a9bbca9523a64L, 0x86985b53d32a3f4bL, 0xc715ea89b184099bL},
            {0xac499c49b8a4cdc4L, 0x22485e1df13ea826L, 0xf91367c2ad8807daL, 0x863b3b9193879ebdL},
            {0x8086427544d93f9bL, 0xf378d24905271a4eL, 0x8a2211f2e881884bL, 0x27f11aae6fbdeb19L},
            {0xd4d702e312991728L, 0xd57d86c18df5deb9L, 0x68b550520aac07f8L, 0x6163e0c25242d715L},
            {0x0484539b5bd55737L, 0x69b34b6b4664d575L, 0xcafeeeea78048b31L, 0x25a0aca017ec768dL},
            {0x955f03fc32b86250L, 0xb3ed04233eabbafdL, 0xb4da5d10fb30568dL, 0xa1d5c520656d8e7fL},
            {0x18e6772ac0c7b0b5L, 0x1e8c41bfa134bd72L, 0x36b1b28f157526b2L, 0xf5ac9222151e43e1L},
            {0xb500af50c3647566L, 0x181d28f85aca7575L, 0x9a16455dfd6341a1L, 0xc6d058b2c1e37c22L},
            {0x01b46ff0be3c6ef8L, 0x7f5abf4a7e4a72feL, 0xe18780f7372db81bL, 0x91d1172dbd7c1d3bL},
            {0x62e68a7598567ebdL, 0x4654b8ed6f377911L, 0x051bf02a5685ca63L, 0xd08b010696df1fa9L},
            {0x656ce860674f0d36L, 0x8bcbf7bc1ef730bfL, 0x00a0260df392d280L, 0x33930145fd64eecfL},
            {0x17743293297fc288L, 0x5b59ca56522bb36aL, 0xe58ef14098fd4053L, 0x7444ed68eb16e657L},
            {0x31beae245608121fL, 0xea349f5c00e7cc25L, 0xf076aacf6db8c528L, 0x13c58f0b1e99ac1aL},
            {0x910f9e30c8455d7bL, 0xc1ebc494beb98220L, 0x201a3557ec66e851L, 0x610dd21bbd2f6b9fL},
            {0x317d8fa79aa99e03L, 0x7b670f771c4590ddL, 0x77052e1a54ac4638L, 0x17309eb8c690df96L},
            {0xddae9fdfd80030d4L, 0x84daf3404eae25e8L, 0xe93997a2e172c485L, 0x51f2159ecb7b5e41L},
            {0x9f02a3e12da8bc2cL, 0x1c746f4b943dc8e5L, 0xb31951aeeaac4e5eL, 0x0128a606643b4341L},
            {0xebd158803af98ce2L, 0x08e82db8ead7c10bL, 0xba172e80caa61667L, 0xf61ff900e1918b8aL},
            {0x8c3c570f9ffae2bcL, 0xff0827921f27e4f5L, 0x6256d4a0913919b5L, 0xc1f4fcc60f17957eL},
            {0x648ade6556f9d114L, 0xf2e85e1746058ffeL, 0xc9605989ede623cfL, 0xf3d09098541725a9L},
            {0xc57b49460d911255L, 0xc0767005f4affb44L, 0x486c21436602612aL, 0x87617ddb2a9643c0L},
            {0xc2038cd71c6d3eadL, 0x8fe1e58a5096a181L, 0x51cde6590d0f6b27L, 0xf59bf938475aa39aL},
            {0x9d8138454badbf16L, 0xaf8306904b15d8a8L, 0x83bd9fd79c159b39L, 0xb85db82acdbbf3aeL},
            {0x560807274e8b13dbL, 0xb33b8a036f1617caL, 0x72bc05868c923532L, 0xb7b8ee25c3388851L},
            {0xc042df127c4f6747L, 0x704ed715ba3ca7d4L, 0x678f93c55bc0c5d2L, 0xd2ee482f0bfe6c9aL},
            {0xbd60c5ba33d87b10L, 0x6c2ff096c60536d6L, 0x0ce4b4b8c86a8f5bL, 0x86a0bcebf81d6e4dL},
            {0xf9384ef3a44799c2L, 0x8b78ec1c676a7fcdL, 0x5f7c3edb312b00daL, 0x2390763c1712af67L},
        };

    // Fast variants (AIMER-f)
    public static final AIMerParameters aimer128f = new AIMerParameters(
        "aimer128f",
        128,    // securityBits
        2,      // aim2NumInputSbox
        33,     // aimerT
        16,     // aimerN
        4,       // aimerLogN
        5888
    );

    public static final AIMerParameters aimer192f = new AIMerParameters(
        "aimer192f",
        192,    // securityBits
        2,      // aim2NumInputSbox
        49,     // aimerT
        16,     // aimerN
        4,       // aimerLogN
        13056
    );

    public static final AIMerParameters aimer256f = new AIMerParameters(
        "aimer256f",
        256,    // securityBits
        3,      // aim2NumInputSbox
        65,     // aimerT
        16,     // aimerN
        4,       // aimerLogN
        25120
    );

    // Small variants (AIMER-s)
    public static final AIMerParameters aimer128s = new AIMerParameters(
        "aimer128s",
        128,    // securityBits
        2,      // aim2NumInputSbox
        17,     // aimerT
        256,    // aimerN
        8,       // aimerLogN
        4160
    );

    public static final AIMerParameters aimer192s = new AIMerParameters(
        "aimer192s",
        192,    // securityBits
        2,      // aim2NumInputSbox
        25,     // aimerT
        256,    // aimerN
        8,       // aimerLogN
        9120
    );

    public static final AIMerParameters aimer256s = new AIMerParameters(
        "aimer256s",
        256,    // securityBits
        3,      // aim2NumInputSbox
        33,     // aimerT
        256,    // aimerN
        8,       // aimerLogN
        17056
    );

    private final String name;
    private final int securityBits;
    private final int securityBytes;

    // AIM2 parameters (based on security level)
    private final int aim2NumBitsField;
    private final int aim2NumBytesField;
    private final int aim2NumWordsField;
    private static final int AIM2_NUM_BITS_WORD = 64;
    private final int aim2IVSize;
    private final int aim2NumInputSbox;

    // AIMER parameters
    private final int aimerSaltSize;
    private final int aimerSeedSize;
    private final int aimerCommitSize;
    private final int aimerL;
    private final int aimerT;
    private final int aimerN;
    private final int aimerLogN;

    // Key sizes (derived from parameters)
    private final int publicKeyBytes;
    private final int secretKeyBytes;
    private final int signatureBytes;

    final long[][] aim2_constants;
    final long[][] aim2_e1_power_matrix;
    final long[][] aim2_e2_power_matrix;

    // Instance of the engine (to be implemented separately)
    //private final AIMerEngine aimerEngine;

    private AIMerParameters(String name, int securityBits, int aim2NumInputSbox,
                            int aimerT, int aimerN, int aimerLogN, int cryptoBytes)
    {
        this.name = name;
        this.securityBits = securityBits;
        this.securityBytes = securityBits / 8;

        // AIM2 derived parameters
        this.aim2NumBitsField = securityBits;
        this.aim2NumBytesField = securityBytes;
        this.aim2NumWordsField = securityBits / 64;  // Since 64-bit words
        this.aim2IVSize = securityBytes;
        this.aim2NumInputSbox = aim2NumInputSbox;

        // AIMER derived parameters
        this.aimerSaltSize = securityBytes;
        this.aimerSeedSize = securityBytes;
        this.aimerCommitSize = 2 * securityBytes;
        this.aimerL = aim2NumInputSbox;
        this.aimerT = aimerT;
        this.aimerN = aimerN;
        this.aimerLogN = aimerLogN;

        // Calculate key sizes based on AIMER specifications
        // For AIMER, these would need to be calculated based on the paper/spec
        // Placeholder values - adjust based on actual AIMER specification
        this.publicKeyBytes = calculatePublicKeySize();
        this.secretKeyBytes = calculateSecretKeySize();
        this.signatureBytes = cryptoBytes;

        // Create engine instance with these parameters
        //this.aimerEngine = new AIMerEngine(this);
        switch (securityBits)
        {
        case 128:
            aim2_constants = aim2_constants_128;
            aim2_e1_power_matrix = aim2_e1_power_matrix_128;
            aim2_e2_power_matrix = aim2_e2_power_matrix_128;
            break;
        case 192:
            aim2_constants = aim2_constants_192;
            aim2_e1_power_matrix = aim2_e1_power_matrix_192;
            aim2_e2_power_matrix = aim2_e2_power_matrix_192;
            break;
        case 256:
            aim2_constants = aim2_constants_256;
            aim2_e1_power_matrix = null;
            aim2_e2_power_matrix = aim2_e2_power_matrix_256;
            break;
        default:
            throw new IllegalArgumentException("unknown security bits: " + securityBits);
        }
    }

    // Placeholder methods for calculating sizes - these need to be implemented
    // based on the actual AIMER specification
    private int calculatePublicKeySize()
    {
        // In AIMER, public key typically consists of:
        // - t matrices (each N x N over GF(2^securityBits))?
        // - plus other components
        // This is a simplified placeholder
        return aim2NumBytesField * 2; // Placeholder
    }

    private int calculateSecretKeySize()
    {
        // Secret key typically includes the public key plus additional private data
        return publicKeyBytes + aim2NumBytesField; // Placeholder
    }

    // Getters for all parameters
    public String getName()
    {
        return name;
    }

    public int getSecurityBits()
    {
        return securityBits;
    }

    public int getSecurityBytes()
    {
        return securityBytes;
    }

    // AIM2 parameters
    public int getAim2NumBitsField()
    {
        return aim2NumBitsField;
    }

    public int getAim2NumBytesField()
    {
        return aim2NumBytesField;
    }

    public int getAim2NumWordsField()
    {
        return aim2NumWordsField;
    }

    public int getAim2NumBitsWord()
    {
        return AIM2_NUM_BITS_WORD;
    }

    public int getAim2IVSize()
    {
        return aim2IVSize;
    }

    public int getAim2NumInputSbox()
    {
        return aim2NumInputSbox;
    }

    // AIMER parameters
    public int getAimerSaltSize()
    {
        return aimerSaltSize;
    }

    public int getAimerSeedSize()
    {
        return aimerSeedSize;
    }

    public int getAimerCommitSize()
    {
        return aimerCommitSize;
    }

    public int getAimerL()
    {
        return aimerL;
    }

    public int getAimerT()
    {
        return aimerT;
    }

    public int getAimerN()
    {
        return aimerN;
    }

    public int getAimerLogN()
    {
        return aimerLogN;
    }

    // Key and signature sizes
    public int getSessionKeySize()
    {
        return securityBits; // For KEM, session key size = security bits
    }

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getSecretKeyBytes()
    {
        return secretKeyBytes;
    }

    public int getSignatureBytes()
    {
        return signatureBytes;
    }

    // Helper methods for derived calculations
    public int getNumFieldElementsPerMatrix()
    {
        // Each matrix in AIMER is N x N over GF(2^securityBits)
        return aimerN * aimerN;
    }
}