package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class QTesla5
{


    private static final int PARAM_N = 2048;
    private static final int PARAM_N_LOG = 11;
    private static final double PARAM_SIGMA = 10.2;
    private static final int PARAM_Q = 16801793;
    private static final int PARAM_Q_LOG = 25;
    private static final long PARAM_QINV = 3707789311L;
    private static final int PARAM_BARR_MULT = 255;
    private static final int PARAM_BARR_DIV = 32;
    private static final int PARAM_B = 4194303;
    private static final int PARAM_B_BITS = 22;
    private static final int PARAM_S_BITS = 9;
    private static final int PARAM_K = 1;
    private static final double PARAM_SIGMA_E = PARAM_SIGMA;
    private static final int PARAM_H = 61;
    private static final int PARAM_D = 23;
    private static final int PARAM_GEN_A = 98;
    private static final int PARAM_KEYGEN_BOUND_E = 1554;
    private static final int PARAM_E = PARAM_KEYGEN_BOUND_E;
    private static final int PARAM_KEYGEN_BOUND_S = 1554;
    private static final int PARAM_S = PARAM_KEYGEN_BOUND_S;
    private static final int PARAM_R2_INVN = 6863778;
    private static final int PARAM_R = 10510081;

    static final String CRYPTO_ALGNAME = "qTesla-II";

    static final int CHUNK_SIZE = 512;

    private static final int CRYPTO_RANDOMBYTES = 32;
    private static final int CRYPTO_SEEDBYTES = 32;
    private static final int CRYPTO_C_BYTES = 32;
    private static final int HM_BYTES = 64;
    private static final int RADIX32 = 32;
    private static final int RADIX = 32;

    // Contains signature (z,c). z is a polynomial bounded by B, c is the output of a hashed string
    static final int CRYPTO_BYTES = ((PARAM_N * (PARAM_B_BITS + 1) + 7) / 8 + CRYPTO_C_BYTES);
    // Contains polynomial s and e, and seeds seed_a and seed_y
    static final int CRYPTO_SECRETKEYBYTES = (2 * PARAM_S_BITS * PARAM_N / 8 + 2 * CRYPTO_SEEDBYTES);
    // Contains seed_a and polynomial t
    static final int CRYPTO_PUBLICKEYBYTES = ((PARAM_N * PARAM_Q_LOG + 7) / 8 + CRYPTO_SEEDBYTES);


    private static final int CDT_ROWS = 177;
    private static final int CDT_COLS = 7;

    private static final long[] cdt_v = new long[]{
        0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, // 0
        0x05019F23L, 0x215AA886L, 0x266BD84AL, 0x1962528BL, 0x1B78B6C3L, 0x10702362L, 0x075CEACEL, // 1
        0x0EF8936EL, 0x23BFC791L, 0x31B19042L, 0x50351AA0L, 0x24A6BDB7L, 0x0EBAFAAAL, 0x281A6107L, // 2
        0x18CB03FCL, 0x0746C256L, 0x407022E8L, 0x334F94BAL, 0x7DF18AC4L, 0x798AFB36L, 0x7039E38CL, // 3
        0x2261C15EL, 0x4527ABF1L, 0x7CCF6441L, 0x00EF6D46L, 0x0B270487L, 0x3013B648L, 0x71EA5FC1L, // 4
        0x2BA749FEL, 0x4A371856L, 0x3A2CA997L, 0x5153CB0AL, 0x6E86FC2DL, 0x71393406L, 0x38CDCEFBL, // 5
        0x3488598AL, 0x0435B2D7L, 0x4DD990AEL, 0x0E7429C0L, 0x57C70926L, 0x77D180B7L, 0x1C885AC4L, // 6
        0x3CF45E22L, 0x01E1BF49L, 0x4CFF5AEEL, 0x26AE280CL, 0x1B580293L, 0x1BBE8EA6L, 0x64E2ACB5L, // 7
        0x44DDCECBL, 0x5BEB1ED9L, 0x2BD797BFL, 0x29192D65L, 0x01E8AAA2L, 0x5E55256FL, 0x7B92EE1FL, // 8
        0x4C3A608EL, 0x22F7BD95L, 0x7BAF5E4AL, 0x611E8A2EL, 0x24A3263DL, 0x5C654D5AL, 0x721F6EE1L, // 9
        0x530319A4L, 0x2AAB68C5L, 0x135B9B19L, 0x7D19FFA3L, 0x0F4BED85L, 0x700FDB24L, 0x33FED619L, // 10
        0x59344411L, 0x6FBA748BL, 0x4409DF71L, 0x76C2A4C2L, 0x458B7E7BL, 0x0B19F872L, 0x383591D2L, // 11
        0x5ECD42A3L, 0x12258E6CL, 0x70ABD8BFL, 0x33F8D6F8L, 0x1D4E8E7FL, 0x2EA9987CL, 0x5C71DE6AL, // 12
        0x63D04CBCL, 0x4B03A25AL, 0x17893AFDL, 0x00512D3CL, 0x4D0128C2L, 0x1DDA6A23L, 0x45DD76CEL, // 13
        0x68421661L, 0x279CDBF3L, 0x64BB398DL, 0x603BDA52L, 0x1EF54067L, 0x5CC606F2L, 0x71328EA3L, // 14
        0x6C296A64L, 0x58D40125L, 0x5D5E3204L, 0x45948D02L, 0x685E0BD9L, 0x1BA23EE0L, 0x1CE3F4BDL, // 15
        0x6F8EBCDCL, 0x2CBC9B6CL, 0x078DBD24L, 0x11153742L, 0x199011B0L, 0x48F8E372L, 0x12BA1FF2L, // 16
        0x727BBBA2L, 0x6464E481L, 0x6C03A4A4L, 0x4FBBF658L, 0x5E1F7EA0L, 0x51CCDF9DL, 0x6BFB1A05L, // 17
        0x74FAE221L, 0x32614E4BL, 0x4B399625L, 0x5284D9C8L, 0x3387DBE7L, 0x1B54382CL, 0x2C0B9401L, // 18
        0x771714BEL, 0x64DE7817L, 0x5BAFF2C0L, 0x3A75B025L, 0x7B3E1C06L, 0x187323D5L, 0x537D368BL, // 19
        0x78DB474CL, 0x64906B4AL, 0x36C15D1AL, 0x49AAA0FBL, 0x70260138L, 0x61C1FBC3L, 0x258DA96BL, // 20
        0x7A5230BFL, 0x213597F2L, 0x3ECC4E7BL, 0x5FFE21CAL, 0x0BA66FF1L, 0x66E2BEE1L, 0x4C4A36E6L, // 21
        0x7B860D68L, 0x0DD17AC2L, 0x34CE2917L, 0x13D0DE15L, 0x3DAE2C15L, 0x72433BD4L, 0x6A1E26E2L, // 22
        0x7C806FFEL, 0x7068EFBDL, 0x603BDD00L, 0x24292429L, 0x086F0A5DL, 0x52B3EB35L, 0x09480B65L, // 23
        0x7D4A20E9L, 0x2D5BC71BL, 0x470F64CEL, 0x63129FAFL, 0x04D4D45DL, 0x4AC6220BL, 0x33074061L, // 24
        0x7DEB0A96L, 0x00A6501CL, 0x4C461A13L, 0x790CAB85L, 0x74FC097EL, 0x05E7BEAFL, 0x5AA87152L, // 25
        0x7E6A3144L, 0x75C93242L, 0x16023571L, 0x06B7110BL, 0x1328C0AEL, 0x1F40DF96L, 0x6B478CC1L, // 26
        0x7ECDB456L, 0x661A7E35L, 0x162E551AL, 0x75DB9DA9L, 0x46974129L, 0x031C68B0L, 0x2B74986FL, // 27
        0x7F1AD71FL, 0x20516B1FL, 0x5FF00AE2L, 0x43DFF254L, 0x3B9EAE78L, 0x06866816L, 0x447D78BCL, // 28
        0x7F560F41L, 0x3300DE7CL, 0x4B8F0799L, 0x5C3E4574L, 0x5B305708L, 0x0B96B8DCL, 0x5736634BL, // 29
        0x7F8316C3L, 0x1226EADBL, 0x51D0E0B1L, 0x5870949AL, 0x74462F50L, 0x56567448L, 0x12F77EB5L, // 30
        0x7FA5003CL, 0x3183FE96L, 0x56A3015DL, 0x5471CE29L, 0x22B635B1L, 0x43887505L, 0x1A18922DL, // 31
        0x7FBE4BCBL, 0x237FBE88L, 0x06124F61L, 0x189877D0L, 0x48CAA53FL, 0x1265E21AL, 0x62BF19B0L, // 32
        0x7FD0FBBEL, 0x4900A57BL, 0x1231A728L, 0x21713D51L, 0x223431D3L, 0x5B78BFB2L, 0x176771CFL, // 33
        0x7FDEA82DL, 0x4264689CL, 0x090BD52BL, 0x35B3EF58L, 0x45E2BC10L, 0x1CBD0BB0L, 0x0E4BD14EL, // 34
        0x7FE890F4L, 0x7F427C59L, 0x3FEA77A7L, 0x76B5CEC4L, 0x45944DB0L, 0x6431AACAL, 0x406F6970L, // 35
        0x7FEFADC9L, 0x235461F2L, 0x76530FE7L, 0x458AFED6L, 0x1600521DL, 0x496DF752L, 0x557C7C91L, // 36
        0x7FF4BC39L, 0x47D62996L, 0x080C04AEL, 0x5578E91DL, 0x1A4B652DL, 0x1F2C5708L, 0x7FC057F8L, // 37
        0x7FF84BA5L, 0x449EAC84L, 0x43D826FAL, 0x01AFCF15L, 0x082E7148L, 0x174C9617L, 0x0EF4B981L, // 38
        0x7FFAC73EL, 0x68B27237L, 0x1032E3F9L, 0x63DED627L, 0x790A03A1L, 0x12C02669L, 0x32E13A7AL, // 39
        0x7FFC7E40L, 0x6CDCE391L, 0x74D2C6E0L, 0x56F439FAL, 0x25E1A719L, 0x2F7BA7D3L, 0x6BBB03FDL, // 40
        0x7FFDAA93L, 0x2A0A579FL, 0x4E3FD638L, 0x555547D0L, 0x3DC84165L, 0x1B63F1D7L, 0x65F61784L, // 41
        0x7FFE760EL, 0x7D0DA319L, 0x04AE9E8DL, 0x47F8B424L, 0x2790150FL, 0x1465810DL, 0x60758064L, // 42
        0x7FFEFE9CL, 0x00E6F118L, 0x5B12C69BL, 0x63045184L, 0x4D76C4FCL, 0x005448BAL, 0x6BBC8934L, // 43
        0x7FFF595EL, 0x1329625AL, 0x788CC79FL, 0x61B72C9CL, 0x288DD9B9L, 0x63482AE8L, 0x51A31E34L, // 44
        0x7FFF951CL, 0x7C94755BL, 0x7F1054DFL, 0x57D6E351L, 0x3556F636L, 0x322AA171L, 0x09AB76A4L, // 45
        0x7FFFBC11L, 0x0D63DD99L, 0x16E1DEEDL, 0x5FA47FD6L, 0x3E02C7F5L, 0x1292E768L, 0x5C9950B6L, // 46
        0x7FFFD538L, 0x56FC93F8L, 0x4BF6F51DL, 0x65D1F42EL, 0x66614419L, 0x743999F4L, 0x4775F539L, // 47
        0x7FFFE54FL, 0x26D25196L, 0x4AF51374L, 0x7A3F204DL, 0x325CBC6EL, 0x35468E0BL, 0x0E6AFF8BL, // 48
        0x7FFFEF80L, 0x25C7892BL, 0x5FC036B7L, 0x563D2EF5L, 0x272F2784L, 0x60F8917AL, 0x2B7798D4L, // 49
        0x7FFFF5E5L, 0x17797BB9L, 0x4AED0883L, 0x55F4708EL, 0x2F8E9E16L, 0x42ADBC77L, 0x2C514F20L, // 50
        0x7FFFF9DEL, 0x2C7B5848L, 0x63C7FD09L, 0x7144559BL, 0x642F3815L, 0x3BC263D4L, 0x2E151167L, // 51
        0x7FFFFC50L, 0x2F236C2DL, 0x04B38B5DL, 0x67E03136L, 0x1505949DL, 0x555E169AL, 0x2B0CDB87L, // 52
        0x7FFFFDCDL, 0x7C5C8A99L, 0x47780740L, 0x3CCCFB88L, 0x658A4A5AL, 0x62742D3FL, 0x7EE61718L, // 53
        0x7FFFFEB4L, 0x2E1E4A11L, 0x366AC9FCL, 0x2F9E887BL, 0x5CAE301EL, 0x50530164L, 0x7CFA1FA4L, // 54
        0x7FFFFF3EL, 0x0FEBD46FL, 0x6BC1CE85L, 0x72F069E6L, 0x7A679EADL, 0x4D21ABE8L, 0x30D0A287L, // 55
        0x7FFFFF8FL, 0x5B6E489EL, 0x28751892L, 0x56C780B4L, 0x62C86BA2L, 0x7679DF3EL, 0x5A88A82AL, // 56
        0x7FFFFFBFL, 0x495E9E5FL, 0x7EAA1ACBL, 0x351B085FL, 0x3C5DFCC9L, 0x7033F18AL, 0x3BAFCD90L, // 57
        0x7FFFFFDBL, 0x3057607BL, 0x28E384A2L, 0x5C5256A0L, 0x32AE45A9L, 0x34190D12L, 0x2E65E081L, // 58
        0x7FFFFFEBL, 0x3035C5A3L, 0x15A78AB7L, 0x0FC670CFL, 0x3A9031EAL, 0x1B601810L, 0x73E214C7L, // 59
        0x7FFFFFF4L, 0x3F4D8780L, 0x66D50D33L, 0x63B5CAFFL, 0x61595249L, 0x3E0FEE39L, 0x4EC7BC6CL, // 60
        0x7FFFFFF9L, 0x5212DCE2L, 0x6CD045D5L, 0x07DDE51EL, 0x0FB442F9L, 0x726ABB1BL, 0x399494D3L, // 61
        0x7FFFFFFCL, 0x425CE8A8L, 0x02F46379L, 0x69404141L, 0x0DE16EC1L, 0x01DFD140L, 0x16EDF35DL, // 62
        0x7FFFFFFEL, 0x0E49947FL, 0x0E07EA75L, 0x3B58DBEAL, 0x2C87E79EL, 0x17451064L, 0x5BB480FBL, // 63
        0x7FFFFFFEL, 0x7E1F309BL, 0x2F0778A7L, 0x2D18E896L, 0x16CBED25L, 0x35E62E74L, 0x4A06DE56L, // 64
        0x7FFFFFFFL, 0x3ADDCA91L, 0x5A24C395L, 0x56E970E7L, 0x46AD989DL, 0x29A487F6L, 0x6717F088L, // 65
        0x7FFFFFFFL, 0x5B8B8969L, 0x73D05913L, 0x5979C1D5L, 0x3E870DF4L, 0x4BF68805L, 0x3B5B26F9L, // 66
        0x7FFFFFFFL, 0x6CF50016L, 0x4970EBFFL, 0x7B2F8760L, 0x2C756F1BL, 0x37E84584L, 0x462E2ED6L, // 67
        0x7FFFFFFFL, 0x7625525CL, 0x0AF78928L, 0x125CBC7DL, 0x7A62F256L, 0x7143E720L, 0x66C80349L, // 68
        0x7FFFFFFFL, 0x7AF2D44BL, 0x4619F7B3L, 0x318AF6FCL, 0x1683F758L, 0x6B101249L, 0x3BDF8061L, // 69
        0x7FFFFFFFL, 0x7D6F51AFL, 0x18D38DD1L, 0x73C75828L, 0x585FD26AL, 0x291F5F7BL, 0x7042595CL, // 70
        0x7FFFFFFFL, 0x7EB5AA16L, 0x20B148BBL, 0x23D956F7L, 0x7BD5B5C7L, 0x72795377L, 0x5F107BB5L, // 71
        0x7FFFFFFFL, 0x7F5B63C8L, 0x7DDB2AD8L, 0x2773EA98L, 0x110B0D21L, 0x507254BFL, 0x567857BFL, // 72
        0x7FFFFFFFL, 0x7FAEBE67L, 0x62813FEFL, 0x732DBF3BL, 0x4DFFDC9DL, 0x7EDF0637L, 0x5186F8DAL, // 73
        0x7FFFFFFFL, 0x7FD8444FL, 0x2E032276L, 0x5B2AFA19L, 0x04581C6EL, 0x79E07CBFL, 0x2DAE29FEL, // 74
        0x7FFFFFFFL, 0x7FECC0FAL, 0x55F8D363L, 0x07F7A470L, 0x403014C4L, 0x412437E0L, 0x550DD47CL, // 75
        0x7FFFFFFFL, 0x7FF6C3E2L, 0x30CFCC16L, 0x21550403L, 0x0968F238L, 0x05F08F1AL, 0x6AA46C1AL, // 76
        0x7FFFFFFFL, 0x7FFB9C50L, 0x5FBBDCD2L, 0x06635365L, 0x59089E37L, 0x17D6E9BAL, 0x276CEAC0L, // 77
        0x7FFFFFFFL, 0x7FFDEEEFL, 0x0D5AA5B2L, 0x756EF80AL, 0x090472C8L, 0x525340F4L, 0x430EF28AL, // 78
        0x7FFFFFFFL, 0x7FFF093FL, 0x0AEFA9CBL, 0x71B85E69L, 0x35A7E2A7L, 0x2531F904L, 0x413AA3A6L, // 79
        0x7FFFFFFFL, 0x7FFF8E00L, 0x09F364F6L, 0x34A17AD8L, 0x76BD8136L, 0x5683F3CEL, 0x10FED6E7L, // 80
        0x7FFFFFFFL, 0x7FFFCBD4L, 0x1CD513A4L, 0x5CB1E269L, 0x5939D904L, 0x5CA9B01BL, 0x20A0DBE4L, // 81
        0x7FFFFFFFL, 0x7FFFE859L, 0x400469ACL, 0x7530AE2CL, 0x628AD0A7L, 0x141964ABL, 0x7C5DAC00L, // 82
        0x7FFFFFFFL, 0x7FFFF561L, 0x1F898BDBL, 0x04826122L, 0x418CA3EBL, 0x47670ABDL, 0x485EB10BL, // 83
        0x7FFFFFFFL, 0x7FFFFB46L, 0x5697977EL, 0x7C47A5FBL, 0x73E767F1L, 0x0F3FFBAFL, 0x5AF66E4BL, // 84
        0x7FFFFFFFL, 0x7FFFFDEBL, 0x14C7AD1BL, 0x6DFCE35AL, 0x4FBD3EDBL, 0x29519FBCL, 0x3BF06C9FL, // 85
        0x7FFFFFFFL, 0x7FFFFF17L, 0x38F29E00L, 0x15864C26L, 0x3ED1C921L, 0x2DD8365AL, 0x6FF5D263L, // 86
        0x7FFFFFFFL, 0x7FFFFF9BL, 0x3B053D45L, 0x67D04FC5L, 0x2633B08BL, 0x3C36A297L, 0x6B5049E6L, // 87
        0x7FFFFFFFL, 0x7FFFFFD4L, 0x790609C5L, 0x5E96D83FL, 0x7D309D5EL, 0x49685B8CL, 0x6525899BL, // 88
        0x7FFFFFFFL, 0x7FFFFFEDL, 0x5E4DD5C7L, 0x7D8F388AL, 0x4FA72501L, 0x759163C3L, 0x5965B99FL, // 89
        0x7FFFFFFFL, 0x7FFFFFF8L, 0x29C05963L, 0x0645E13DL, 0x57138B46L, 0x704839F7L, 0x7E47F4ABL, // 90
        0x7FFFFFFFL, 0x7FFFFFFCL, 0x672F2508L, 0x3FCB5C25L, 0x75E8C19BL, 0x79B927A6L, 0x459388BFL, // 91
        0x7FFFFFFFL, 0x7FFFFFFEL, 0x57757A13L, 0x73F0B7CEL, 0x4BA283D2L, 0x4A67664DL, 0x7958BF63L, // 92
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x3B2C73A1L, 0x6BA2B500L, 0x01AEDEAFL, 0x4CB02493L, 0x05131E4AL, // 93
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x6428E338L, 0x5026719CL, 0x0658B0CAL, 0x12B28E84L, 0x1CE29302L, // 94
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x74D85FA8L, 0x5D9E5301L, 0x2D5735E5L, 0x4DFDEDC4L, 0x302571CBL, // 95
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7B92AB00L, 0x044C95FAL, 0x0AA5A52BL, 0x7E3C7C97L, 0x10174031L, // 96
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E42777FL, 0x7055A4A5L, 0x77909EC2L, 0x0A72199CL, 0x7C047649L, // 97
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F528317L, 0x1E611B25L, 0x77B0E768L, 0x76EF5F68L, 0x5C5E0880L, // 98
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FBD15BEL, 0x591E5FD1L, 0x42A39695L, 0x5753E03DL, 0x4888BA10L, // 99
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FE66F66L, 0x4ED42CB5L, 0x25B46819L, 0x29F65AF3L, 0x480D7FB5L, // 100
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF65357L, 0x3C11F581L, 0x1EE81339L, 0x0B548369L, 0x4C176653L, // 101
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC5FA6L, 0x13A72C4CL, 0x41D2C974L, 0x4D7D4F15L, 0x137E1A5CL, // 102
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFEA751L, 0x0087E172L, 0x6450815CL, 0x06BD4974L, 0x35A068B7L, // 103
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF813CL, 0x68963485L, 0x2D62B319L, 0x7F6D36F5L, 0x053AFCFFL, // 104
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFD1D2L, 0x6710A409L, 0x035B53E9L, 0x6B754C14L, 0x67E4986EL, // 105
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFEF56L, 0x56112414L, 0x147B7548L, 0x01A3C15AL, 0x5C3AEECDL, // 106
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFA0BL, 0x4B034EF2L, 0x2FE56ACCL, 0x5AB28803L, 0x2EDA5188L, // 107
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFDE4L, 0x2CC83513L, 0x334F55FEL, 0x0629A93FL, 0x38A4E0E3L, // 108
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF42L, 0x631F9BC6L, 0x69E7B1D4L, 0x0ACC308EL, 0x1A5D01F4L, // 109
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFBEL, 0x23B1C1ECL, 0x1AD56ACDL, 0x1D531D5CL, 0x2361A1E2L, // 110
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFE9L, 0x32023A0BL, 0x2448F18BL, 0x1283D5AEL, 0x6C85EB4BL, // 111
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF8L, 0x25DDC591L, 0x10460958L, 0x160127B6L, 0x0D23122BL, // 112
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFDL, 0x332A0006L, 0x39060F98L, 0x583A2EE5L, 0x7F6F4B30L, // 113
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x10BAC302L, 0x0B63D3F3L, 0x34548417L, 0x6417CEF7L, // 114
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x5B278E34L, 0x3CFCAA9CL, 0x63C0AB49L, 0x7EF44CC5L, // 115
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x73EA444EL, 0x71B589C1L, 0x40C37AB8L, 0x05AC3C2BL, // 116
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7C12EEC8L, 0x581AE332L, 0x1F6B2998L, 0x7B3F4742L, // 117
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7EBC95AFL, 0x0FCE42E4L, 0x1A12647DL, 0x312F2344L, // 118
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F98EB42L, 0x773D755CL, 0x6BA5569EL, 0x0B59780DL, // 119
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FDF7528L, 0x257E6D28L, 0x0DD3B8AAL, 0x7A8DB84CL, // 120
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF5D2FBL, 0x06D06F83L, 0x59078672L, 0x01289F57L, // 121
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFCD92AL, 0x3D1F735FL, 0x3DD750C7L, 0x724A384AL, // 122
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF087BL, 0x157C8C2CL, 0x592F1FD5L, 0x5BCAB49DL, // 123
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFB4C9L, 0x75D8D62BL, 0x5E6F960FL, 0x6E7A0825L, // 124
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFE95DL, 0x0AB518E5L, 0x5EBFD0F1L, 0x6EF5DC28L, // 125
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF940L, 0x3E71644DL, 0x1DCD2F7FL, 0x20F92853L, // 126
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFE01L, 0x74E02F84L, 0x5CDE6F58L, 0x782A7B08L, // 127
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF6AL, 0x68B9722FL, 0x24BE2517L, 0x653EBEA0L, // 128
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFD4L, 0x6475CC5AL, 0x1C2EEA1AL, 0x0328E2D1L, // 129
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF3L, 0x4CDD3713L, 0x39FF33E5L, 0x26D4E741L, // 130
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFCL, 0x3CF1DAA4L, 0x4F9A6798L, 0x61EA76B6L, // 131
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x0108514BL, 0x67772555L, 0x64F8745AL, // 132
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x5C999EB3L, 0x08168B63L, 0x46AF07F6L, // 133
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x76395C01L, 0x6F3CFAEAL, 0x131AD6A3L, // 134
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7D5374F0L, 0x5731E351L, 0x7C6F380DL, // 135
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F468A5EL, 0x4EA7CE39L, 0x036A7B8EL, // 136
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FCE3B9BL, 0x7CED4D0CL, 0x4046A3D8L, // 137
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF2C5BAL, 0x616952F6L, 0x04D4F456L, // 138
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC8488L, 0x300FEBA6L, 0x4F2917BBL, // 139
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF178CL, 0x1CEB1D35L, 0x54FDFB4FL, // 140
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFC3F6L, 0x7CDFB395L, 0x0DE10FC7L, // 141
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF0A4L, 0x3AAF842EL, 0x4F2D7D3EL, // 142
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFC1BL, 0x6D46EB35L, 0x39A589F1L, // 143
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF06L, 0x00F9D719L, 0x7C80C709L, // 144
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFC1L, 0x6E09C112L, 0x40F91447L, // 145
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF0L, 0x59BA3B04L, 0x533C64C9L, // 146
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFCL, 0x2277000DL, 0x3FFCCF35L, // 147
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x0CA8F6AFL, 0x04FDBCC1L, // 148
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x64683B2DL, 0x4DC73C3EL, // 149
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x79763BB9L, 0x6D56EF81L, // 150
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E772DC4L, 0x19BE9910L, // 151
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FA4AFACL, 0x238F593BL, // 152
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FEAF9D0L, 0x20A7706EL, // 153
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFB349CL, 0x425A62E3L, // 154
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFEEAC4L, 0x14FBA4D6L, // 155
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFC1FAL, 0x18FE5A04L, // 156
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF241L, 0x574E3E93L, // 157
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFCFBL, 0x68B2B84CL, // 158
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF58L, 0x1212FAD2L, // 159
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFDBL, 0x6DDE1CBEL, // 160
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF8L, 0x2571DA8CL, // 161
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFEL, 0x2F9DBF36L, // 162
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x54677433L, // 163
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x76F75F40L, // 164
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E255C0FL, // 165
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F9F83B6L, // 166
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FEC92C7L, // 167
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC203AL, // 168
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF3C1BL, // 169
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFD9ADL, // 170
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF893L, // 171
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFE93L, // 172
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFBAL, // 173
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF3L, // 174
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFDL, // 175
        0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, // 176
    }; // cdt_v


    /******************************************************************************************************************************************************
     * Description:	Generates A Signature for A Given Message According to the Ring-TESLA Signature Scheme for Heuristic qTESLA Security Category-1 and
     * 				Security Category-3 (Option for Size or Speed)
     *
     * @param        message                                Message to be Signed
     * @param        messageOffset                        Starting Point of the Message to be Signed
     * @param        messageLength                        Length of the Message to be Signed
     * @param        signature                            Output Package Containing Signature
     * @param        privateKey                            Private Key
     * @param        secureRandom                        Source of Randomness
     *
     * @return 0                                    Successful Execution
     ******************************************************************************************************************************************************/
    static int generateSignature(

        byte[] signature,
        final byte[] message, int messageOffset, int messageLength,
        final byte[] privateKey, SecureRandom secureRandom
    )
    {
        byte[] c = new byte[CRYPTO_C_BYTES];
        byte[] randomness = new byte[CRYPTO_SEEDBYTES];
        byte[] randomness_input = new byte[CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + HM_BYTES];
        byte[] seeds = new byte[2 * CRYPTO_SEEDBYTES];
        int[] pos_list = new int[PARAM_H];
        short[] sign_list = new short[PARAM_H];
        int[] s = new int[PARAM_N];
        int[] e = new int[PARAM_N];
        int[] y = new int[PARAM_N];
        int[] v = new int[PARAM_N];
        int[] Sc = new int[PARAM_N];
        int[] Ec = new int[PARAM_N];
        int[] z = new int[PARAM_N];
        int[] a = new int[PARAM_N];
        int nonce = 0;


        decodePrivateKey(seeds, s, e, privateKey);
        byte[] temporaryRandomnessInput = new byte[CRYPTO_RANDOMBYTES];
        secureRandom.nextBytes(temporaryRandomnessInput);
        System.arraycopy(temporaryRandomnessInput, 0, randomness_input, CRYPTO_RANDOMBYTES, CRYPTO_RANDOMBYTES);

        System.arraycopy(seeds, CRYPTO_SEEDBYTES, randomness_input, 0, CRYPTO_SEEDBYTES);


        HashUtils.secureHashAlgorithmKECCAK256(
            randomness_input, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES, HM_BYTES, message, 0, messageLength);

        HashUtils.secureHashAlgorithmKECCAK256(
            randomness, 0, CRYPTO_SEEDBYTES, randomness_input, 0, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + HM_BYTES);


        QTesla5Polynomial.poly_uniform(a, seeds, 0);


        while (true)
        {
            sampleY(y, randomness, 0, ++nonce); //n, q, b, bBit);

            /* V = A * Y Modulo Q */
            QTesla5Polynomial.poly_mul(v, a, y);


            hashFunction(c, 0, v, randomness_input, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES); //, n, d, q);
            encodeC(pos_list, sign_list, c, 0);           // Generate c = Enc(c'), where c' is the hashing of v together with m
            QTesla5Polynomial.sparse_mul16(Sc, s, pos_list, sign_list);
            QTesla5Polynomial.poly_add(z, y, Sc);


            if (testRejection(z)) // PARAM_N, b, u))
            {
                continue;
            }

            QTesla5Polynomial.sparse_mul16(Ec, e, pos_list, sign_list);
            QTesla5Polynomial.poly_sub_correct(v, v, Ec);

            if (test_correctness(v)) // PARAM_N, b, u))
            {
                continue;
            }

            encodeSignature(signature, 0, c, 0, z);
            break;
        }

        return 0;
    }


    static int verifying(

        byte[] message,
        final byte[] signature, int signatureOffset, int signatureLength,
        final byte[] publicKey)
    {
        byte[] c = new byte[CRYPTO_C_BYTES];
        byte[] c_sig = new byte[CRYPTO_C_BYTES];
        byte[] seed = new byte[CRYPTO_SEEDBYTES];
        byte[] hm = new byte[HM_BYTES];
        int[] pos_list = new int[PARAM_H];
        short[] sign_list = new short[PARAM_H];
        int[] pk_t = new int[PARAM_N];
        int[] w = new int[PARAM_N];
        int[] z = new int[PARAM_N];
        int[] a = new int[PARAM_N];
        int[] Tc = new int[PARAM_N];

        if (signatureLength < CRYPTO_BYTES)
        {
            return -1;
        }

        decodeSignature(c, z, signature, signatureOffset);

        if (testZ(z))
        {
            return -2;
        }

        decodePublicKey(pk_t, seed, 0, publicKey);

        QTesla5Polynomial.poly_uniform(a, seed, 0);
        encodeC(pos_list, sign_list, c, 0);
        QTesla5Polynomial.sparse_mul32(Tc, pk_t, pos_list, sign_list);
        QTesla5Polynomial.poly_mul(w, a, z);
        QTesla5Polynomial.poly_sub_reduce(w, w, Tc);
        HashUtils.secureHashAlgorithmKECCAK256(
            hm, 0, HM_BYTES, message, 0, message.length
        );
        hashFunction(c_sig, 0, w, hm, 0);
        if (!memoryEqual(c, 0, c_sig, 0, CRYPTO_C_BYTES))
        {
            return -3;
        }
        return 0;
    }


    static int generateKeyPair(

        byte[] publicKey, byte[] privateKey, SecureRandom secureRandom)
    {
        byte[] randomness = new byte[CRYPTO_RANDOMBYTES];
        byte[] randomness_extended = new byte[4 * CRYPTO_SEEDBYTES];
        int[] s = new int[PARAM_N];
        int[] e = new int[PARAM_N];
        int[] a = new int[PARAM_N];
        int[] t = new int[PARAM_N];
        int nonce = 0;  // Initialize domain separator for error and secret polynomials

        secureRandom.nextBytes(randomness);


        HashUtils.secureHashAlgorithmKECCAK256(randomness_extended, 0, CRYPTO_SEEDBYTES * 4, randomness, 0, CRYPTO_RANDOMBYTES);

        do
        {
            sample_gauss_poly(++nonce, randomness_extended, 0, e);
        }
        while (checkPolynomial(e, PARAM_KEYGEN_BOUND_E));

        do
        {
            sample_gauss_poly(++nonce, randomness_extended, CRYPTO_SEEDBYTES, s);
        }
        while (checkPolynomial(s, PARAM_KEYGEN_BOUND_S));


        // Generate uniform polynomial "a"
        QTesla5Polynomial.poly_uniform(a, randomness_extended, 2 * CRYPTO_SEEDBYTES);

        // Compute the public key t = as+e
        QTesla5Polynomial.poly_mul(t, a, s);


        QTesla5Polynomial.poly_add_correct(t, t, e);

        // Pack public and private keys

        encodePrivateKey(privateKey, s, e, randomness_extended, CRYPTO_SEEDBYTES * 2);

        encodePublicKey(publicKey, t, randomness_extended, CRYPTO_SEEDBYTES * 2);


        return 0;
    }


    private static boolean testZ(int[] Z)
    {
        // Returns false if valid, otherwise outputs 1 if invalid (rejected)

        for (int i = 0; i < PARAM_N; i++)
        {

            if ((Z[i] < -(PARAM_B - PARAM_S)) || (Z[i] > PARAM_B - PARAM_S))
            {

                return true;

            }

        }

        return false;

    }


    static boolean test_correctness(int[] v)
    { // Check bounds for w = v - ec during signature verification. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
        // This function leaks the position of the coefficient that fails the test (but this is independent of the secret data).
        // It does not leak the sign of the coefficients.
        int mask, left, val;
        int t0, t1;

        for (int i = 0; i < PARAM_N; i++)
        {
            // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
            mask = (PARAM_Q / 2 - v[i]) >> (RADIX32 - 1);
            val = ((v[i] - PARAM_Q) & mask) | (v[i] & ~mask);
            // If (Abs(val) < PARAM_Q/2 - PARAM_E) then t0 = 0, else t0 = 1
            t0 = (~(absolute(val) - (PARAM_Q / 2 - PARAM_E))) >>> (RADIX32 - 1);

            left = val;
            val = (val + (1 << (PARAM_D - 1)) - 1) >> PARAM_D;
            val = left - (val << PARAM_D);
            // If (Abs(val) < (1<<(PARAM_D-1))-PARAM_E) then t1 = 0, else t1 = 1
            t1 = (~(absolute(val) - ((1 << (PARAM_D - 1)) - PARAM_E))) >>> (RADIX32 - 1);

            if ((t0 | t1) == 1)  // Returns 1 if any of the two tests failed
            {
                return true;
            }
        }
        return false;
    }

    private static boolean testRejection(int[] Z) //, int n, int b, int u)
    {

        int valid = 0;

        for (int i = 0; i < PARAM_N; i++)
        {
            valid |= (PARAM_B - PARAM_S) - absolute(Z[i]);

        }

        return (valid >>> 31) != 0;

    }

    static void encodeC(int[] positionList, short[] signList, byte[] output, int outputOffset)
    {

        int count = 0;
        int position;
        short domainSeparator = 0;
        short[] C = new short[PARAM_N];
        byte[] randomness = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE];

        /* Use the Hash Value as Key to Generate Some Randomness */
        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
            randomness, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE,
            domainSeparator++,
            output, outputOffset, CRYPTO_RANDOMBYTES
        );

        /* Use Rejection Sampling to Determine Positions to be Set in the New Vector */
        Arrays.fill(C, (short)0);

        /* Sample A Unique Position k times.
         * Use Two Bytes
         */
        for (int i = 0; i < PARAM_H; )
        {

            if (count > HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE - 3)
            {

                HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                    randomness, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE,
                    domainSeparator++,
                    output, outputOffset, CRYPTO_RANDOMBYTES
                );

                count = 0;

            }

            position = (randomness[count] << 8) | (randomness[count + 1] & 0xFF);
            position &= (PARAM_N - 1);

            /* Position is between [0, n - 1] and Has not Been Set Yet
             * Determine Signature
             */
            if (C[position] == 0)
            {

                if ((randomness[count + 2] & 1) == 1)
                {

                    C[position] = -1;

                }
                else
                {

                    C[position] = 1;

                }

                positionList[i] = position;
                signList[i] = C[position];
                i++;

            }

            count += 3;

        }

    }


    private static void hashFunction(byte[] output, int outputOffset, int[] v, final byte[] message, int messageOffset) //, int n, int d, int q)
    {

        int mask;
        int cL;

        byte[] T = new byte[PARAM_N + HM_BYTES];

        for (int i = 0; i < PARAM_N; i++)
        {
            /* If V[i] > Q / 2 Then V[i] = V[i] - Q */
            // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
            mask = (PARAM_Q / 2 - v[i]) >> (RADIX32 - 1);
            v[i] = ((v[i] - PARAM_Q) & mask) | (v[i] & ~mask);

            cL = v[i] & ((1 << PARAM_D) - 1);
            // If cL > 2^(d-1) then cL -= 2^d
            mask = ((1 << (PARAM_D - 1)) - cL) >> (RADIX32 - 1);
            cL = ((cL - (1 << PARAM_D)) & mask) | (cL & ~mask);
            T[i] = (byte)((v[i] - cL) >> PARAM_D);

        }

        System.arraycopy(message, messageOffset, T, PARAM_N, HM_BYTES);
        HashUtils.secureHashAlgorithmKECCAK256(output, outputOffset, CRYPTO_C_BYTES, T, 0, PARAM_N + HM_BYTES);

    }


    static void sampleY(int[] Y, final byte[] seed, int seedOffset, int nonce) //   int n, int b, int bBit)
    {

        int i = 0;
        int position = 0;
        int numberOfByte = (PARAM_B_BITS + 1 + 7) / 8;
        int numberOfBlock = PARAM_N;
        byte[] buffer = new byte[PARAM_N * numberOfByte];
        int[] y = new int[4];

        short dualModeSampler = (short)(nonce << 8);

        HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
            buffer, 0, PARAM_N * numberOfByte, dualModeSampler++, seed, seedOffset, CRYPTO_RANDOMBYTES
        );


        while (i < PARAM_N)
        {

            if (position >= numberOfBlock * numberOfByte * 4)
            {
                numberOfBlock =
                    SHAKE_RATE /
                        ((PARAM_B_BITS + 1 + 7) / 8);

                HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
                    buffer, 0, SHAKE_RATE,
                    dualModeSampler++,
                    seed, seedOffset, CRYPTO_RANDOMBYTES
                );

                position = 0;

            }

            y[0] = (load32(buffer, position) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;
            y[1] = (load32(buffer, position + numberOfByte) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;
            y[2] = (load32(buffer, position + numberOfByte * 2) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;
            y[3] = (load32(buffer, position + numberOfByte * 3) & ((1 << (PARAM_B_BITS + 1)) - 1)) - PARAM_B;

            if (i < PARAM_N && y[0] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[0];

            }

            if (i < PARAM_N && y[1] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[1];

            }

            if (i < PARAM_N && y[2] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[2];

            }

            if (i < PARAM_N && y[3] != (1 << PARAM_B_BITS))
            {

                Y[i++] = y[3];

            }

            position += numberOfByte * 4;

        }
    }

    private static boolean checkPolynomial(int[] polynomial, int bound)
    {

        int i, j, sum = 0, limit = PARAM_N;
        int temp, mask;
        int[] list = new int[PARAM_N];

        for (j = 0; j < PARAM_N; j++)
        {
            list[j] = absolute(polynomial[j]);
        }

        for (j = 0; j < PARAM_H; j++)
        {
            for (i = 0; i < limit - 1; i++)
            {
                // If list[i+1] > list[i] then exchange contents
                mask = (list[i + 1] - list[i]) >> (RADIX32 - 1);
                temp = (list[i + 1] & mask) | (list[i] & ~mask);
                list[i + 1] = (list[i] & mask) | (list[i + 1] & ~mask);
                list[i] = temp;
            }
            sum += list[limit - 1];
            limit -= 1;
        }

        return (sum > bound);
    }


    private static int absolute(int value)
    {

        return ((value >> 31) ^ value) - (value >> 31);

    }

    private static void sample_gauss_poly(int nonce, byte[] randomnessExtended, int randomOffset, int[] poly)
    {
        int dmsp = nonce << 8;

        for (int chunk = 0; chunk < PARAM_N; chunk += CHUNK_SIZE)
        {
            kmxGauss(poly, chunk, randomnessExtended, randomOffset, dmsp++);
        }

    }


    private static void kmxGauss(int[] z, int chunk, byte[] seed, int seedOffset, int nonce)
    {
        int[] sampk = new int[(CHUNK_SIZE + CDT_ROWS) * CDT_COLS];
        int[] sampg = new int[CHUNK_SIZE + CDT_ROWS];

        {
            // In the C Implementation they cast between uint_8 and int32 a lot, this is one of those situations.
            byte[] sampkBytes = new byte[sampk.length * 4];
            HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(
                sampkBytes, 0, CHUNK_SIZE * CDT_COLS * 4, (short)nonce, seed, seedOffset, CRYPTO_SEEDBYTES);
            int i, t;

            int offset = CHUNK_SIZE * CDT_COLS * 4;

            for (i = 0; i < cdt_v.length; i++)
            {
                sampkBytes[offset++] = (byte)(cdt_v[i]);
                sampkBytes[offset++] = (byte)(cdt_v[i] >>> 8);
                sampkBytes[offset++] = (byte)(cdt_v[i] >>> 16);
                sampkBytes[offset++] = (byte)(cdt_v[i] >>> 24);
            }

            for (i = 0, t = 0; t < sampkBytes.length; t += 4, i++)
            {
                sampk[i] = Pack.littleEndianToInt(sampkBytes, t);
            }

        }

        for (int i = 0; i < CHUNK_SIZE; i++)
        {
            sampg[i] = i << 16;
        }

        for (int i = 0; i < CDT_ROWS; i++)
        {
            sampg[CHUNK_SIZE + i] = (int)(0xFFFF0000L ^ i);
        }

        knuthMergeExchangeKG(sampk, sampg, CHUNK_SIZE + CDT_ROWS);

        int prev_inx = 0;
        for (int i = 0; i < CHUNK_SIZE + CDT_ROWS; i++)
        {
            int curr_inx = sampg[i] & 0xFFFF;
            // prev_inx < curr_inx => prev_inx - curr_inx < 0 => (prev_inx - curr_inx) >> 31 = 0xF...F else 0x0...0
            prev_inx ^= (curr_inx ^ prev_inx) & ((prev_inx - curr_inx) >> (RADIX32 - 1));
            int neg = (sampk[i * CDT_COLS] >> (RADIX - 1));  // Only the (so far unused) msb of the leading word
            sampg[i] |= ((neg & -prev_inx) ^ (~neg & prev_inx)) & 0xFFFFL;
        }

        knuthMergeExchangeG(sampg, CHUNK_SIZE + CDT_ROWS);

        for (int i = 0; i < CHUNK_SIZE; i++)
        {
            z[i + chunk] = (sampg[i] << (RADIX32 - 16)) >> (RADIX32 - 16);
        }

    }

    static void knuthMergeExchangeKG(int[] a, int g[], int n)
    {
        int t = 1;
        while (t < n - t)
        {
            t += t;
        }
        for (int p = t; p > 0; p >>= 1)
        {
            int apPtr = p * CDT_COLS;
            int a_iPtr = 0;
            int ap_iPtr = apPtr;
            int gpPtr = p;

            int neg = ~0;

            for (int i = 0; i < n - p; i++, a_iPtr += CDT_COLS, ap_iPtr += CDT_COLS)
            {
                if (!((i & p) != 0))
                {
                    {
                        int diff = 0, swapa;
                        int swapg;
                        {

                            {
                                diff = (diff + (a[ap_iPtr + 6] & ((neg >>> 1))) - (a[a_iPtr + 6] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                diff = (diff + (a[ap_iPtr + 5] & ((neg >>> 1))) - (a[a_iPtr + 5] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                diff = (diff + (a[ap_iPtr + 4] & ((neg >>> 1))) - (a[a_iPtr + 4] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                diff = (diff + (a[ap_iPtr + 3] & ((neg >>> 1))) - (a[a_iPtr + 3] & ((neg >>> 1)))) >> (32 - 1);
                            }
                            ;
                            {
                                {
                                    diff = (diff + (a[ap_iPtr + 2] & (neg >>> 1))) - (a[a_iPtr + 2] & ((neg >>> 1))) >> (32 - 1);
                                }
                                ;
                                {
                                    {
                                        diff = (diff + (a[ap_iPtr + 1] & (neg >>> 1))) - (a[a_iPtr + 1] & ((neg >>> 1))) >> (32 - 1);
                                    }
                                    ;
                                    {
                                        {
                                            diff = (diff + (a[ap_iPtr] & ((neg >>> 1))) - (a[a_iPtr] & ((neg >>> 1)))) >> (32 - 1);
                                        }
                                        ;
                                        {
                                            swapa = (a[a_iPtr] ^ a[ap_iPtr]) & diff;
                                            a[a_iPtr] ^= swapa;
                                            a[ap_iPtr] ^= swapa;
                                        }
                                        ;
                                    }
                                    ;
                                    {
                                        swapa = (a[a_iPtr + 1] ^ a[ap_iPtr + 1]) & diff;
                                        a[a_iPtr + 1] ^= swapa;
                                        a[ap_iPtr + 1] ^= swapa;
                                    }
                                    ;
                                }
                                ;
                                {
                                    swapa = (a[a_iPtr + 2] ^ a[ap_iPtr + 2]) & diff;
                                    a[a_iPtr + 2] ^= swapa;
                                    a[ap_iPtr + 2] ^= swapa;
                                }
                                ;
                            }
                            ;
                            {
                                swapa = (a[a_iPtr + 3] ^ a[ap_iPtr + 3]) & diff;
                                a[a_iPtr + 3] ^= swapa;
                                a[ap_iPtr + 3] ^= swapa;
                            }

                            {
                                swapa = (a[a_iPtr + 4] ^ a[ap_iPtr + 4]) & diff;
                                a[a_iPtr + 4] ^= swapa;
                                a[ap_iPtr + 4] ^= swapa;
                            }
                            {
                                swapa = (a[a_iPtr + 5] ^ a[ap_iPtr + 5]) & diff;
                                a[a_iPtr + 5] ^= swapa;
                                a[ap_iPtr + 5] ^= swapa;
                            }

                            {
                                swapa = (a[a_iPtr + 6] ^ a[ap_iPtr + 6]) & diff;
                                a[a_iPtr + 6] ^= swapa;
                                a[ap_iPtr + 6] ^= swapa;
                            }

                            ;
                        }
                        ;
                        {
                            swapg = (g[i] ^ g[gpPtr + i]) & diff;
                            g[i] ^= swapg;
                            g[gpPtr + i] ^= swapg;
                        }
                        ;
                    }
                    ;
                }
            }


            for (int q = t; q > p; q >>= 1)
            {
                int ap_iPtr_ = apPtr;
                int aq_iPtr = q * CDT_COLS;
                int gqPtr = q;
                for (int i = 0; i < n - q; i++, ap_iPtr_ += CDT_COLS, aq_iPtr += CDT_COLS)
                {
                    if (!((i & p) != 0))
                    {
                        {
                            int diff = 0, swapa;
                            int swapg;
                            {
                                {
                                    diff = (diff + (a[aq_iPtr + 6] & (neg >>> 1))) - (a[ap_iPtr_ + 6] & (neg >>> 1)) >> (32 - 1);
                                }

                                {
                                    diff = (diff + (a[aq_iPtr + 5] & (neg >>> 1))) - (a[ap_iPtr_ + 5] & (neg >>> 1)) >> (32 - 1);
                                }

                                {
                                    diff = (diff + (a[aq_iPtr + 4] & (neg >>> 1))) - (a[ap_iPtr_ + 4] & (neg >>> 1)) >> (32 - 1);
                                }

                                {
                                    diff = (diff + (a[aq_iPtr + 3] & (neg >>> 1))) - (a[ap_iPtr_ + 3] & (neg >>> 1)) >> (32 - 1);
                                }
                                ;
                                {
                                    {
                                        diff = (diff + (a[aq_iPtr + 2] & (neg >>> 1))) - (a[ap_iPtr_ + 2] & (neg >>> 1)) >> (32 - 1);
                                    }
                                    ;
                                    {
                                        {
                                            diff = (diff + (a[aq_iPtr + 1] & (neg >>> 1))) - (a[ap_iPtr_ + 1] & (neg >>> 1)) >> (32 - 1);
                                        }
                                        ;
                                        {
                                            {
                                                diff = (diff + (a[aq_iPtr] & (neg >>> 1))) - (a[ap_iPtr_] & (neg >>> 1)) >> (32 - 1);
                                            }
                                            ;
                                            {
                                                swapa = (a[ap_iPtr_] ^ a[aq_iPtr]) & diff;
                                                a[ap_iPtr_] ^= swapa;
                                                a[aq_iPtr] ^= swapa;
                                            }
                                            ;
                                        }
                                        ;
                                        {
                                            swapa = (a[ap_iPtr_ + 1] ^ a[aq_iPtr + 1]) & diff;
                                            a[ap_iPtr_ + 1] ^= swapa;
                                            a[aq_iPtr + 1] ^= swapa;
                                        }
                                        ;
                                    }
                                    ;
                                    {
                                        swapa = (a[ap_iPtr_ + 2] ^ a[aq_iPtr + 2]) & diff;
                                        a[ap_iPtr_ + 2] ^= swapa;
                                        a[aq_iPtr + 2] ^= swapa;
                                    }
                                    ;
                                }
                                ;
                                {
                                    swapa = (a[ap_iPtr_ + 3] ^ a[aq_iPtr + 3]) & diff;
                                    a[ap_iPtr_ + 3] ^= swapa;
                                    a[aq_iPtr + 3] ^= swapa;
                                }
                                ;
                                {
                                    swapa = (a[ap_iPtr_ + 4] ^ a[aq_iPtr + 4]) & diff;
                                    a[ap_iPtr_ + 4] ^= swapa;
                                    a[aq_iPtr + 4] ^= swapa;
                                }
                                ;

                                {
                                    swapa = (a[ap_iPtr_ + 5] ^ a[aq_iPtr + 5]) & diff;
                                    a[ap_iPtr_ + 5] ^= swapa;
                                    a[aq_iPtr + 5] ^= swapa;
                                }
                                ;
                                {
                                    swapa = (a[ap_iPtr_ + 6] ^ a[aq_iPtr + 6]) & diff;
                                    a[ap_iPtr_ + 6] ^= swapa;
                                    a[aq_iPtr + 6] ^= swapa;
                                }
                                ;
                            }
                            ;
                            {
                                swapg = (g[gpPtr + i] ^ g[gqPtr + i]) & diff;
                                g[gpPtr + i] ^= swapg;
                                g[gqPtr + i] ^= swapg;
                            }
                            ;
                        }
                        ;

                    }
                }
            }

        }
    }


    static void knuthMergeExchangeG(int a[], int n)
    {
        int t = 1;
        while (t < n - t)
        {
            t += t;
        }
        for (int p = t; p > 0; p >>= 1)
        {

            int apPtr = p;
            for (int i = 0; i < n - p; i++)
            {
                if (!((i & p) != 0))
                {
                    int diff = ((a[apPtr + i] & 0x7FFFFFFF) - (a[i] & 0x7FFFFFFF)) >> (32 - 1);
                    int swap = (a[i] ^ a[apPtr + i]) & diff;
                    a[i] ^= swap;
                    a[apPtr + i] ^= swap;
                }
            }

            for (int q = t; q > p; q >>= 1)
            {
                int aqPtr = q;
                for (int i = 0; i < n - q; i++)
                {
                    if (!((i & p) != 0))
                    {
                        int diff = ((a[aqPtr + i] & 0x7FFFFFFF) - (a[apPtr + i] & 0x7FFFFFFF)) >> (32 - 1);
                        int swap = (a[apPtr + i] ^ a[aqPtr + i]) & diff;
                        a[apPtr + i] ^= swap;
                        a[aqPtr + i] ^= swap;
                    }
                }
            }
        }
    }


    private static void at(byte[] bufer, int base, int offset, int v)
    {
        Pack.intToLittleEndian(v, bufer, base * 4 + offset * 4);
    }


    private static int at(byte[] bufer, int base, int offset)
    {
        return Pack.littleEndianToInt(bufer, base * 4 + offset * 4);
    }


    static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z)
    {
        int maskd = ((1 << (PARAM_B_BITS + 1)) - 1);
        int j = 0;
        for (int i = 0; i < (PARAM_N * (PARAM_B_BITS + 1) / 32); i += (PARAM_B_BITS + 1))
        {

            at(signature, i, 0, ((Z[j + 0] & ((1 << 23) - 1)) | (Z[j + 1] << 23)));
            at(signature, i, 1, (((Z[j + 1] >>> 9) & ((1 << 14) - 1)) | (Z[j + 2] << 14)));
            at(signature, i, 2, (((Z[j + 2] >>> 18) & ((1 << 5) - 1)) | ((Z[j + 3] & maskd) << 5) | (Z[j + 4] << 28)));
            at(signature, i, 3, (((Z[j + 4] >>> 4) & ((1 << 19) - 1)) | (Z[j + 5] << 19)));
            at(signature, i, 4, (((Z[j + 5] >>> 13) & ((1 << 10) - 1)) | (Z[j + 6] << 10)));
            at(signature, i, 5, (((Z[j + 6] >>> 22) & ((1 << 1) - 1)) | ((Z[j + 7] & maskd) << 1) | (Z[j + 8] << 24)));
            at(signature, i, 6, (((Z[j + 8] >>> 8) & ((1 << 15) - 1)) | (Z[j + 9] << 15)));
            at(signature, i, 7, (((Z[j + 9] >>> 17) & ((1 << 6) - 1)) | ((Z[j + 10] & maskd) << 6) | (Z[j + 11] << 29)));
            at(signature, i, 8, (((Z[j + 11] >>> 3) & ((1 << 20) - 1)) | (Z[j + 12] << 20)));
            at(signature, i, 9, (((Z[j + 12] >>> 12) & ((1 << 11) - 1)) | (Z[j + 13] << 11)));
            at(signature, i, 10, (((Z[j + 13] >>> 21) & ((1 << 2) - 1)) | ((Z[j + 14] & maskd) << 2) | (Z[j + 15] << 25)));
            at(signature, i, 11, (((Z[j + 15] >>> 7) & ((1 << 16) - 1)) | (Z[j + 16] << 16)));
            at(signature, i, 12, (((Z[j + 16] >>> 16) & ((1 << 7) - 1)) | ((Z[j + 17] & maskd) << 7) | (Z[j + 18] << 30)));
            at(signature, i, 13, (((Z[j + 18] >>> 2) & ((1 << 21) - 1)) | (Z[j + 19] << 21)));
            at(signature, i, 14, (((Z[j + 19] >>> 11) & ((1 << 12) - 1)) | (Z[j + 20] << 12)));
            at(signature, i, 15, (((Z[j + 20] >>> 20) & ((1 << 3) - 1)) | ((Z[j + 21] & maskd) << 3) | (Z[j + 22] << 26)));
            at(signature, i, 16, (((Z[j + 22] >>> 6) & ((1 << 17) - 1)) | (Z[j + 23] << 17)));
            at(signature, i, 17, (((Z[j + 23] >>> 15) & ((1 << 8) - 1)) | ((Z[j + 24] & maskd) << 8) | (Z[j + 25] << 31)));
            at(signature, i, 18, (((Z[j + 25] >>> 1) & ((1 << 22) - 1)) | (Z[j + 26] << 22)));
            at(signature, i, 19, (((Z[j + 26] >>> 10) & ((1 << 13) - 1)) | (Z[j + 27] << 13)));
            at(signature, i, 20, (((Z[j + 27] >>> 19) & ((1 << 4) - 1)) | ((Z[j + 28] & maskd) << 4) | (Z[j + 29] << 27)));
            at(signature, i, 21, (((Z[j + 29] >>> 5) & ((1 << 18) - 1)) | (Z[j + 30] << 18)));
            at(signature, i, 22, (((Z[j + 30] >>> 14) & ((1 << 9) - 1)) | (Z[j + 31] << 9)));
            j += 32;
        }
        System.arraycopy(C, cOffset, signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, CRYPTO_C_BYTES);

    }


    static void decodeSignature(byte[] C, int[] Z, final byte[] signature, int signatureOffset)
    {

        int j = 0;
        for (int i = 0; i < PARAM_N; i += 32)
        {
            Z[i + 0] = (at(signature, j, 0) << 9) >> 9;
            Z[i + 1] = (at(signature, j, 0) >>> 23) | ((at(signature, j, 1) << 18) >> 9);
            Z[i + 2] = (at(signature, j, 1) >>> 14) | ((at(signature, j, 2) << 27) >> 9);
            Z[i + 3] = (at(signature, j, 2) << 4) >> 9;
            Z[i + 4] = (at(signature, j, 2) >>> 28) | ((at(signature, j, 3) << 13) >> 9);
            Z[i + 5] = (at(signature, j, 3) >>> 19) | ((at(signature, j, 4) << 22) >> 9);
            Z[i + 6] = (at(signature, j, 4) >>> 10) | ((at(signature, j, 5) << 31) >> 9);
            Z[i + 7] = (at(signature, j, 5) << 8) >> 9;
            Z[i + 8] = (at(signature, j, 5) >>> 24) | ((at(signature, j, 6) << 17) >> 9);
            Z[i + 9] = (at(signature, j, 6) >>> 15) | ((at(signature, j, 7) << 26) >> 9);
            Z[i + 10] = (at(signature, j, 7) << 3) >> 9;
            Z[i + 11] = (at(signature, j, 7) >>> 29) | ((at(signature, j, 8) << 12) >> 9);
            Z[i + 12] = (at(signature, j, 8) >>> 20) | ((at(signature, j, 9) << 21) >> 9);
            Z[i + 13] = (at(signature, j, 9) >>> 11) | ((at(signature, j, 10) << 30) >> 9);
            Z[i + 14] = (at(signature, j, 10) << 7) >> 9;
            Z[i + 15] = (at(signature, j, 10) >>> 25) | ((at(signature, j, 11) << 16) >> 9);
            Z[i + 16] = (at(signature, j, 11) >>> 16) | ((at(signature, j, 12) << 25) >> 9);
            Z[i + 17] = (at(signature, j, 12) << 2) >> 9;
            Z[i + 18] = (at(signature, j, 12) >>> 30) | ((at(signature, j, 13) << 11) >> 9);
            Z[i + 19] = (at(signature, j, 13) >>> 21) | ((at(signature, j, 14) << 20) >> 9);
            Z[i + 20] = (at(signature, j, 14) >>> 12) | ((at(signature, j, 15) << 29) >> 9);
            Z[i + 21] = (at(signature, j, 15) << 6) >> 9;
            Z[i + 22] = (at(signature, j, 15) >>> 26) | ((at(signature, j, 16) << 15) >> 9);
            Z[i + 23] = (at(signature, j, 16) >>> 17) | ((at(signature, j, 17) << 24) >> 9);
            Z[i + 24] = (at(signature, j, 17) << 1) >> 9;
            Z[i + 25] = (at(signature, j, 17) >>> 31) | ((at(signature, j, 18) << 10) >> 9);
            Z[i + 26] = (at(signature, j, 18) >>> 22) | ((at(signature, j, 19) << 19) >> 9);
            Z[i + 27] = (at(signature, j, 19) >>> 13) | ((at(signature, j, 20) << 28) >> 9);
            Z[i + 28] = (at(signature, j, 20) << 5) >> 9;
            Z[i + 29] = (at(signature, j, 20) >>> 27) | ((at(signature, j, 21) << 14) >> 9);
            Z[i + 30] = (at(signature, j, 21) >>> 18) | ((at(signature, j, 22) << 23) >> 9);
            Z[i + 31] = at(signature, j, 22) >> 9;
            j += (PARAM_B_BITS + 1);
        }
        System.arraycopy(signature, signatureOffset + PARAM_N * (PARAM_B_BITS + 1) / 8, C, 0, CRYPTO_C_BYTES);


    }


    private static final int SHAKE_RATE = HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE;


    static void encodePublicKey(byte[] publicKey, final int[] T, final byte[] seedA, int seedAOffset)
    {

        int j = 0;


        for (int i = 0; i < (PARAM_N * PARAM_Q_LOG / 32); i += PARAM_Q_LOG)
        {
            {
                at(publicKey, i, 0, (T[j + 0] | (T[j + 1] << 25)));
                at(publicKey, i, 1, ((T[j + 1] >> 7) | (T[j + 2] << 18)));
                at(publicKey, i, 2, ((T[j + 2] >> 14) | (T[j + 3] << 11)));
                at(publicKey, i, 3, ((T[j + 3] >> 21) | (T[j + 4] << 4) | (T[j + 5] << 29)));
                at(publicKey, i, 4, ((T[j + 5] >> 3) | (T[j + 6] << 22)));
                at(publicKey, i, 5, ((T[j + 6] >> 10) | (T[j + 7] << 15)));
                at(publicKey, i, 6, ((T[j + 7] >> 17) | (T[j + 8] << 8)));
                at(publicKey, i, 7, ((T[j + 8] >> 24) | (T[j + 9] << 1) | (T[j + 10] << 26)));
                at(publicKey, i, 8, ((T[j + 10] >> 6) | (T[j + 11] << 19)));
                at(publicKey, i, 9, ((T[j + 11] >> 13) | (T[j + 12] << 12)));
                at(publicKey, i, 10, ((T[j + 12] >> 20) | (T[j + 13] << 5) | (T[j + 14] << 30)));
                at(publicKey, i, 11, ((T[j + 14] >> 2) | (T[j + 15] << 23)));
                at(publicKey, i, 12, ((T[j + 15] >> 9) | (T[j + 16] << 16)));
                at(publicKey, i, 13, ((T[j + 16] >> 16) | (T[j + 17] << 9)));
                at(publicKey, i, 14, ((T[j + 17] >> 23) | (T[j + 18] << 2) | (T[j + 19] << 27)));
                at(publicKey, i, 15, ((T[j + 19] >> 5) | (T[j + 20] << 20)));
                at(publicKey, i, 16, ((T[j + 20] >> 12) | (T[j + 21] << 13)));
                at(publicKey, i, 17, ((T[j + 21] >> 19) | (T[j + 22] << 6) | (T[j + 23] << 31)));
                at(publicKey, i, 18, ((T[j + 23] >> 1) | (T[j + 24] << 24)));
                at(publicKey, i, 19, ((T[j + 24] >> 8) | (T[j + 25] << 17)));
                at(publicKey, i, 20, ((T[j + 25] >> 15) | (T[j + 26] << 10)));
                at(publicKey, i, 21, ((T[j + 26] >> 22) | (T[j + 27] << 3) | (T[j + 28] << 28)));
                at(publicKey, i, 22, ((T[j + 28] >> 4) | (T[j + 29] << 21)));
                at(publicKey, i, 23, ((T[j + 29] >> 11) | (T[j + 30] << 14)));
                at(publicKey, i, 24, ((T[j + 30] >> 18) | (T[j + 31] << 7)));
                j += 32;
            }

            System.arraycopy(seedA, seedAOffset, publicKey, PARAM_N * PARAM_Q_LOG / 8, CRYPTO_SEEDBYTES);

        }
    }


    static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, final byte[] publicKeyInput)
    {

        int j = 0;

        int maskq = (1 << PARAM_Q_LOG) - 1;


        for (int i = 0; i < PARAM_N; i += 32)
        {
            publicKey[i + 0] = (at(publicKeyInput, j, 0)) & maskq;
            publicKey[i + 1] = ((at(publicKeyInput, j, 0) >>> 25) | (at(publicKeyInput, j, 1) << 7)) & maskq;
            publicKey[i + 2] = ((at(publicKeyInput, j, 1) >>> 18) | (at(publicKeyInput, j, 2) << 14)) & maskq;
            publicKey[i + 3] = ((at(publicKeyInput, j, 2) >>> 11) | (at(publicKeyInput, j, 3) << 21)) & maskq;
            publicKey[i + 4] = ((at(publicKeyInput, j, 3) >>> 4)) & maskq;
            publicKey[i + 5] = ((at(publicKeyInput, j, 3) >>> 29) | (at(publicKeyInput, j, 4) << 3)) & maskq;
            publicKey[i + 6] = ((at(publicKeyInput, j, 4) >>> 22) | (at(publicKeyInput, j, 5) << 10)) & maskq;
            publicKey[i + 7] = ((at(publicKeyInput, j, 5) >>> 15) | (at(publicKeyInput, j, 6) << 17)) & maskq;
            publicKey[i + 8] = ((at(publicKeyInput, j, 6) >>> 8) | (at(publicKeyInput, j, 7) << 24)) & maskq;
            publicKey[i + 9] = ((at(publicKeyInput, j, 7) >>> 1)) & maskq;
            publicKey[i + 10] = ((at(publicKeyInput, j, 7) >>> 26) | (at(publicKeyInput, j, 8) << 6)) & maskq;
            publicKey[i + 11] = ((at(publicKeyInput, j, 8) >>> 19) | (at(publicKeyInput, j, 9) << 13)) & maskq;
            publicKey[i + 12] = ((at(publicKeyInput, j, 9) >>> 12) | (at(publicKeyInput, j, 10) << 20)) & maskq;
            publicKey[i + 13] = ((at(publicKeyInput, j, 10) >>> 5)) & maskq;
            publicKey[i + 14] = ((at(publicKeyInput, j, 10) >>> 30) | (at(publicKeyInput, j, 11) << 2)) & maskq;
            publicKey[i + 15] = ((at(publicKeyInput, j, 11) >>> 23) | (at(publicKeyInput, j, 12) << 9)) & maskq;
            publicKey[i + 16] = ((at(publicKeyInput, j, 12) >>> 16) | (at(publicKeyInput, j, 13) << 16)) & maskq;
            publicKey[i + 17] = ((at(publicKeyInput, j, 13) >>> 9) | (at(publicKeyInput, j, 14) << 23)) & maskq;
            publicKey[i + 18] = ((at(publicKeyInput, j, 14) >>> 2)) & maskq;
            publicKey[i + 19] = ((at(publicKeyInput, j, 14) >>> 27) | (at(publicKeyInput, j, 15) << 5)) & maskq;
            publicKey[i + 20] = ((at(publicKeyInput, j, 15) >>> 20) | (at(publicKeyInput, j, 16) << 12)) & maskq;
            publicKey[i + 21] = ((at(publicKeyInput, j, 16) >>> 13) | (at(publicKeyInput, j, 17) << 19)) & maskq;
            publicKey[i + 22] = ((at(publicKeyInput, j, 17) >>> 6)) & maskq;
            publicKey[i + 23] = ((at(publicKeyInput, j, 17) >>> 31) | (at(publicKeyInput, j, 18) << 1)) & maskq;
            publicKey[i + 24] = ((at(publicKeyInput, j, 18) >>> 24) | (at(publicKeyInput, j, 19) << 8)) & maskq;
            publicKey[i + 25] = ((at(publicKeyInput, j, 19) >>> 17) | (at(publicKeyInput, j, 20) << 15)) & maskq;
            publicKey[i + 26] = ((at(publicKeyInput, j, 20) >>> 10) | (at(publicKeyInput, j, 21) << 22)) & maskq;
            publicKey[i + 27] = ((at(publicKeyInput, j, 21) >>> 3)) & maskq;
            publicKey[i + 28] = ((at(publicKeyInput, j, 21) >>> 28) | (at(publicKeyInput, j, 22) << 4)) & maskq;
            publicKey[i + 29] = ((at(publicKeyInput, j, 22) >>> 21) | (at(publicKeyInput, j, 23) << 11)) & maskq;
            publicKey[i + 30] = ((at(publicKeyInput, j, 23) >>> 14) | (at(publicKeyInput, j, 24) << 18)) & maskq;
            publicKey[i + 31] = ((at(publicKeyInput, j, 24) >>> 7)) & maskq;
            j += PARAM_Q_LOG;
        }

        System.arraycopy(publicKeyInput, PARAM_N * PARAM_Q_LOG / 8, seedA, seedAOffset, CRYPTO_SEEDBYTES);

    }


    static void encodePrivateKey(byte[] privateKey, final int[] secretPolynomial,
                                 final int[] errorPolynomial, final byte[] seed, int seedOffset)
    {
        byte[] sk = privateKey;
        int[] s = secretPolynomial;
        int[] e = errorPolynomial;

        int j = 0;

        for (int i = 0; i < PARAM_N; i += 8)
        {
            sk[j + 0] = (byte)s[i + 0];
            sk[j + 1] = (byte)(((s[i + 0] >> 8) & 0x01) | (s[i + 1] << 1));
            sk[j + 2] = (byte)(((s[i + 1] >> 7) & 0x03) | (s[i + 2] << 2));
            sk[j + 3] = (byte)(((s[i + 2] >> 6) & 0x07) | (s[i + 3] << 3));
            sk[j + 4] = (byte)(((s[i + 3] >> 5) & 0x0F) | (s[i + 4] << 4));
            sk[j + 5] = (byte)(((s[i + 4] >> 4) & 0x1F) | (s[i + 5] << 5));
            sk[j + 6] = (byte)(((s[i + 5] >> 3) & 0x3F) | (s[i + 6] << 6));
            sk[j + 7] = (byte)(((s[i + 6] >> 2) & 0x7F) | (s[i + 7] << 7));
            sk[j + 8] = (byte)(s[i + 7] >> 1);

            j += 9;
        }

        for (int i = 0; i < PARAM_N; i += 8)
        {
            sk[j + 0] = (byte)e[i + 0];
            sk[j + 1] = (byte)(((e[i + 0] >> 8) & 0x01) | (e[i + 1] << 1));
            sk[j + 2] = (byte)(((e[i + 1] >> 7) & 0x03) | (e[i + 2] << 2));
            sk[j + 3] = (byte)(((e[i + 2] >> 6) & 0x07) | (e[i + 3] << 3));
            sk[j + 4] = (byte)(((e[i + 3] >> 5) & 0x0F) | (e[i + 4] << 4));
            sk[j + 5] = (byte)(((e[i + 4] >> 4) & 0x1F) | (e[i + 5] << 5));
            sk[j + 6] = (byte)(((e[i + 5] >> 3) & 0x3F) | (e[i + 6] << 6));
            sk[j + 7] = (byte)(((e[i + 6] >> 2) & 0x7F) | (e[i + 7] << 7));
            sk[j + 8] = (byte)(e[i + 7] >> 1);
            j += 9;
        }

        System.arraycopy(seed, seedOffset, privateKey, PARAM_N * PARAM_S_BITS * 2 / 8, CRYPTO_SEEDBYTES * 2);

    }


    static void decodePrivateKey(byte[] seed, int[] secretPolynomial, int[] errorPolynomial,
                                 final byte[] privateKey)
    {

        int j = 0;
        int temporary = 0;


        for (int i = 0; i < PARAM_N; i += 8)
        {

            secretPolynomial[i + 0] = (short)((privateKey[j + 0] & 0xFF) | ((privateKey[j + 1] & 0xFF) << 31) >> 23);
            secretPolynomial[i + 1] = (short)(((privateKey[j + 1] & 0xFF) >>> 1) | ((privateKey[j + 2] & 0xFF) << 30) >> 23);
            secretPolynomial[i + 2] = (short)(((privateKey[j + 2] & 0xFF) >>> 2) | ((privateKey[j + 3] & 0xFF) << 29) >> 23);
            secretPolynomial[i + 3] = (short)(((privateKey[j + 3] & 0xFF) >>> 3) | ((privateKey[j + 4] & 0xFF) << 28) >> 23);
            secretPolynomial[i + 4] = (short)(((privateKey[j + 4] & 0xFF) >>> 4) | ((privateKey[j + 5] & 0xFF) << 27) >> 23);
            secretPolynomial[i + 5] = (short)(((privateKey[j + 5] & 0xFF) >>> 5) | ((privateKey[j + 6] & 0xFF) << 26) >> 23);
            secretPolynomial[i + 6] = (short)(((privateKey[j + 6] & 0xFF) >>> 6) | ((privateKey[j + 7] & 0xFF) << 25) >> 23);
            secretPolynomial[i + 7] = (short)(((privateKey[j + 7] & 0xFF) >>> 7) | (privateKey[j + 8] << 1)); // j+8 is to be treated as signed.

            j += 9;
        }

        for (int i = 0; i < PARAM_N; i += 8)
        {
            errorPolynomial[i + 0] = (short)((privateKey[j + 0] & 0xFF) | ((privateKey[j + 1] & 0xFF) << 31) >> 23);
            errorPolynomial[i + 1] = (short)(((privateKey[j + 1] & 0xFF) >>> 1) | ((privateKey[j + 2] & 0xFF) << 30) >> 23);
            errorPolynomial[i + 2] = (short)(((privateKey[j + 2] & 0xFF) >>> 2) | ((privateKey[j + 3] & 0xFF) << 29) >> 23);
            errorPolynomial[i + 3] = (short)(((privateKey[j + 3] & 0xFF) >>> 3) | ((privateKey[j + 4] & 0xFF) << 28) >> 23);
            errorPolynomial[i + 4] = (short)(((privateKey[j + 4] & 0xFF) >>> 4) | ((privateKey[j + 5] & 0xFF) << 27) >> 23);
            errorPolynomial[i + 5] = (short)(((privateKey[j + 5] & 0xFF) >>> 5) | ((privateKey[j + 6] & 0xFF) << 26) >> 23);
            errorPolynomial[i + 6] = (short)(((privateKey[j + 6] & 0xFF) >>> 6) | ((privateKey[j + 7] & 0xFF) << 25) >> 23);
            errorPolynomial[i + 7] = (short)(((privateKey[j + 7] & 0xFF) >>> 7) | (privateKey[j + 8] << 1)); // j+8 to be treated as signed.


            j += 9;
        }

        System.arraycopy(privateKey, PARAM_N * PARAM_S_BITS * 2 / 8, seed, 0, CRYPTO_SEEDBYTES * 2);


    }

    static int load32(final byte[] load, int loadOffset)
    {

        int number = 0;

        if (load.length - loadOffset >= 4)
        {

            for (int i = 0; i < 4; i++)
            {

                number ^= (int)(load[loadOffset + i] & 0xFF) << (8 * i);

            }

        }
        else
        {


            for (int i = 0; i < load.length - loadOffset; i++)
            {

                number ^= (int)(load[loadOffset + i] & 0xFF) << (8 * i);

            }

        }

        return number;

    }


    //TODO use Arrays lib.
    static boolean memoryEqual(byte[] left, int leftOffset, byte[] right, int rightOffset, int length)
    {

        if ((leftOffset + length <= left.length) && (rightOffset + length <= right.length))
        {

            for (int i = 0; i < length; i++)
            {

                if (left[leftOffset + i] != right[rightOffset + i])
                {

                    return false;

                }

            }

            return true;

        }
        else
        {

            return false;

        }

    }


    static class QTesla5Polynomial
    {


        private static final int[] zeta = new int[]{
            237578, 4288697, 12177210, 12251670, 2820109, 16559108, 8640185, 734734, 4877739, 9368949, 15692986, 7892196, 4260427, 15873151, 4142315, 8965173,
            11169896, 5010602, 3649184, 16378095, 5602899, 2220085, 13697693, 15129942, 2537438, 9116594, 16410343, 9557539, 15691195, 7279843, 1593404, 6707422,
            729573, 5647949, 2653234, 7997012, 9715582, 13445158, 5317239, 4737884, 5158670, 1611636, 2754732, 7654402, 9513034, 852770, 6030533, 98847,
            15896485, 9468292, 101985, 16348615, 9909869, 8710886, 13400582, 8402476, 11142365, 5039007, 6002270, 15101063, 11982941, 14572856, 5446047, 7255389,
            1598269, 8218712, 16286658, 10486886, 3039285, 12065852, 8686242, 4602074, 1074217, 15960169, 9815379, 11719092, 15439118, 15007386, 6490529, 1278232,
            4159488, 10910087, 12253311, 12465579, 6910324, 8338618, 7260714, 15844676, 10975469, 410689, 4613096, 16438782, 5576397, 7848026, 4159282, 5530317,
            15689884, 8081281, 6505968, 15456466, 13513813, 11126519, 4479257, 15469744, 1599996, 1549552, 1292615, 16617372, 7354752, 1212703, 1143200, 3034349,
            15607925, 8432537, 14598568, 3650873, 8563652, 3699157, 6433725, 12350373, 4010416, 1729562, 1541253, 11745245, 10894394, 9295277, 5984122, 11866989,
            12690929, 5041453, 4242865, 5343004, 16126341, 11364700, 15647038, 15855542, 13160962, 12290657, 11024990, 14647543, 16368775, 3380411, 16446020, 6240966,
            5751466, 7134009, 2438665, 8929213, 8968783, 10215238, 15346668, 4198060, 10982550, 6270676, 4864722, 6161680, 10301951, 14707040, 4490423, 15971195,
            7805545, 2614465, 7943973, 13761892, 7316833, 14319887, 2730887, 11524479, 16166974, 2788533, 15090677, 7948454, 14199491, 1084744, 8467481, 13478272,
            11365178, 12009889, 10439117, 3416556, 11171006, 3409286, 7525445, 6590049, 13380721, 8863580, 2798830, 15617249, 16691165, 114140, 8378876, 4187487,
            3949667, 13260130, 8320850, 26362, 1631374, 1783873, 14962126, 15292247, 7601202, 8959283, 11243898, 10280677, 13372043, 9939314, 739328, 10429343,
            10517204, 4883929, 10227043, 2540273, 16070370, 13822704, 7688124, 3592640, 5780893, 15904587, 11974241, 5651133, 4855371, 13392454, 16231644, 6178303,
            13065505, 11589059, 9308086, 2588727, 8432796, 16102143, 11471848, 3896453, 6448066, 11215807, 14687955, 8093468, 3351919, 13610159, 9417184, 4141670,
            1564317, 12787559, 9340359, 5991184, 4844747, 10736464, 13915539, 6014043, 12533406, 7870928, 6204965, 7273556, 3361131, 6133191, 2170560, 234890,
            6205675, 1064783, 6909725, 10453386, 14043312, 9513430, 7584898, 15286455, 11616261, 13617701, 10971227, 7326501, 11225193, 16421440, 13159686, 11937009,
            14407060, 16605598, 6715364, 15250230, 10588042, 14945257, 10933852, 1845223, 11937773, 10619031, 837021, 4236465, 11555490, 15280572, 10771639, 5489198,
            1641146, 14841852, 5130068, 11192924, 10148864, 10864560, 5414267, 9151778, 2834937, 13876858, 8108835, 1275721, 14448973, 9361586, 7450208, 2624020,
            14156688, 7796284, 6441054, 9632118, 7183393, 5656624, 6737558, 10418563, 13847552, 12649051, 6482189, 5674962, 2861541, 6648641, 2654778, 302113,
            5338264, 4359987, 15246631, 7144915, 16176671, 15046504, 14305811, 1530803, 8699605, 16093559, 12247205, 9194298, 1045573, 4788527, 12686522, 12448472,
            455886, 9130666, 1109076, 6640485, 14470011, 9073185, 450611, 14049726, 4716009, 4735301, 8095066, 434252, 3923392, 13020544, 13516099, 14565268,
            9928676, 15092165, 3559767, 12563322, 16470800, 5142013, 13762243, 13776061, 12889648, 10170328, 11546445, 6313833, 3489539, 15335036, 4114016, 7270536,
            13240532, 16475683, 1900749, 12271560, 13695337, 16539830, 1459938, 1979474, 2189605, 407835, 9509778, 9030685, 16417128, 5464084, 4250166, 3247084,
            5746578, 471674, 15884837, 5217747, 4897618, 3214451, 3783219, 14191827, 6507807, 16488072, 5841422, 14152181, 775849, 16268009, 2866871, 13908577,
            12405691, 15470161, 14083424, 10965747, 16660146, 2813095, 912756, 8577251, 9517010, 13916729, 1115386, 9002935, 12116047, 9368317, 14622645, 4297439,
            7468990, 14962985, 3100390, 5422880, 1356148, 7668434, 16262840, 4770510, 8040653, 1838503, 3321784, 12877311, 9062788, 14918761, 10085773, 11854269,
            1782669, 3761336, 12230595, 3960759, 1943160, 13996860, 3286412, 13505566, 8300879, 3970272, 13667619, 9354530, 9324585, 16782214, 15518792, 3480087,
            7560142, 10068427, 9991249, 10809921, 1433904, 120746, 15153520, 10457484, 13911952, 5115143, 11589553, 1391220, 12501491, 1236478, 6235898, 6638249,
            5472489, 2354635, 15116536, 7804552, 13531423, 707240, 584852, 11792981, 13472431, 15969727, 15634398, 735101, 7120974, 15055354, 12226328, 8983744,
            10320409, 10420874, 13002674, 13039919, 7966842, 7781950, 5719726, 8849645, 121313, 10809336, 10997452, 12964605, 12119406, 10698327, 11776009, 4054532,
            11639093, 6926766, 14050967, 8053573, 13494936, 8479044, 10442803, 14452557, 15640788, 11065582, 3710173, 3531730, 1468545, 12086286, 15378434, 14509362,
            4201327, 7133188, 9369379, 3542584, 5228822, 7939940, 5788608, 16487503, 13305258, 5474402, 11143623, 8551587, 294665, 9030310, 15223749, 110264,
            12980318, 15143987, 7581228, 10661169, 15574695, 2332834, 2998765, 14072862, 9656990, 4971366, 11319278, 12141807, 4422931, 13305232, 3726322, 5917120,
            12975241, 8481847, 12238953, 3788197, 15584373, 722678, 7642189, 12040759, 8539390, 7457921, 3355371, 8943316, 6401117, 1929917, 3359938, 15128666,
            1971540, 7566896, 674014, 11505895, 1920684, 10819708, 10804381, 16864, 4740228, 2310057, 1350875, 7116144, 11449118, 13523455, 12942651, 3731087,
            16644215, 3362922, 9716827, 14256395, 1223703, 10738730, 2174308, 10016323, 9373626, 14331360, 9267521, 11419058, 6098214, 6509558, 8047836, 15365365,
            6003629, 13541219, 384837, 4502089, 105404, 4425067, 9978915, 7173226, 14063772, 12692662, 12734850, 2740676, 11589919, 13111489, 7894889, 11337274,
            2430375, 15894434, 229297, 2043, 721712, 14990389, 2402364, 1420299, 10413174, 16459152, 3865644, 6115408, 419989, 14234910, 14843792, 4128203,
            4677396, 13576079, 12526806, 1535936, 7157469, 7816932, 1851391, 10532092, 1598422, 5818298, 10599749, 12246115, 9336770, 10102264, 5167417, 14051228,
            9227061, 81041, 362457, 2407097, 2356689, 768837, 15551574, 15075826, 13931704, 11495447, 12087387, 3491987, 8466091, 13934230, 6269795, 16004759,
            5204463, 1030999, 4778261, 4332326, 16067695, 7691476, 16737836, 8468475, 2884992, 3424104, 11937657, 11818091, 11388339, 14652944, 13260049, 12608810,
            11626099, 5873392, 5274931, 10630435, 16428663, 14253122, 10701214, 8990180, 5800907, 14550462, 3941680, 7689598, 11164637, 11416711, 11667444, 5990714,
            16118408, 15906702, 3247249, 10134321, 15513236, 8530232, 13656387, 2642844, 13709091, 1057322, 11527683, 2431397, 5759759, 9792404, 8375877, 15493293,
            2747540, 12900249, 6384119, 8206334, 10902433, 3419690, 3132950, 15252614, 163228, 12099566, 3202153, 16336302, 12797357, 10532244, 15254744, 9461517,
            15505549, 4271041, 10561968, 16580302, 16406815, 2541078, 11239368, 15147052, 8598180, 3930228, 9760618, 1761085, 14757788, 12510004, 7150895, 16782407,
            6992809, 1052746, 7180767, 10534352, 7446376, 10985890, 11135471, 1110325, 11780289, 11848295, 12880159, 6286001, 9949482, 16137479, 11552764, 4669868,
            9282299, 11758635, 1084386, 2482408, 15399614, 2246778, 5494861, 6146397, 16507240, 15238831, 11142033, 8222567, 14441088, 302087, 8750296, 14687710,
            4134240, 7735795, 14087206, 9106568, 4800728, 3581112, 6462019, 10845391, 731525, 1378813, 10922994, 1889488, 16373671, 10576128, 2482862, 14894554,
            11279920, 15031500, 699165, 2656082, 7044554, 10867078, 11007951, 11270921, 6738497, 15183278, 9495167, 15729011, 1103877, 10862360, 8494186, 1425639,
            15309600, 7406857, 670812, 1227182, 16439474, 8374675, 13534116, 5426799, 7913523, 2236364, 11199676, 1552469, 4930110, 2114147, 4268705, 11783436,
            5947396, 6931859, 956318, 4406867, 12546709, 123044, 16014658, 15287416, 3114860, 6120585, 9905438, 12179550, 7862490, 6289444, 11766117, 8421975,
            6122133, 884282, 3888827, 14928208, 13669751, 16032838, 16735595, 11275345, 14230884, 14920501, 165402, 9816619, 6131874, 16075854, 260538, 16052507,
            6207716, 6929970, 13628464, 5479020, 9978795, 8906467, 3252701, 15894887, 7988373, 10960077, 4664901, 7609577, 11359884, 3481107, 8117846, 3746438,
            1515150, 15238543, 15333263, 2035325, 15134714, 16121539, 3166719, 9904128, 14577198, 10562766, 8618374, 10448166, 10200839, 10810935, 2779000, 877102,
            5234179, 16468657, 16639959, 6244100, 14515203, 14627156, 3508679, 1019094, 4528472, 14263121, 9052300, 15914848, 9546129, 2152100, 13753130, 6404850,
            5221418, 1546896, 13808947, 15563228, 15618391, 8955129, 1922457, 1759118, 4062444, 9410041, 16483195, 7197040, 14038422, 11118646, 12759420, 14765496,
            11612032, 13088674, 11233815, 12949418, 5726423, 5026286, 12027035, 9217397, 10842138, 3215204, 5776281, 2997277, 8120659, 1489262, 16427185, 4194862,
            10617661, 2913417, 8061764, 15205731, 3256846, 4907311, 16488538, 4661020, 11099318, 12284189, 2942123, 14307192, 5343620, 8621583, 5160364, 6368175,
            12842220, 6752225, 1769827, 3355288, 3434335, 14325212, 9595793, 4335480, 5404999, 13892158, 16474395, 6538437, 15404126, 641952, 16347031, 3345165,
            4554224, 635100, 8251873, 5302151, 773477, 9336383, 4937083, 4108188, 10206168, 671022, 15439802, 10449884, 3167572, 8999846, 14248663, 1375699,
            16336410, 8747706, 3552933, 1004678, 14568168, 4971485, 12504463, 5288319, 1380857, 12710148, 3055946, 8061272, 11247348, 10797984, 5383539, 9701378,
            7825086, 15929060, 9475968, 10910773, 6237124, 1832421, 11790537, 2408416, 14081404, 12141080, 15819630, 15606203, 4523846, 16668150, 13968077, 14988577,
            4969646, 206490, 3196429, 15151830, 3238025, 5993510, 2031389, 7750059, 7192981, 6446817, 8796178, 6029348, 3441013, 14318322, 6487451, 7080654,
            14776137, 13557853, 1704839, 12521002, 8815557, 1305694, 12651799, 3229346, 14892360, 12637855, 13999670, 12972376, 423114, 8364393, 1916307, 4696151,
            4479208, 6046400, 311418, 8647348, 1128277, 7903539, 11055428, 1206328, 14459343, 3483594, 977929, 2432878, 13026683, 2294784, 6243844, 5655748,
            4084239, 13387981, 15169625, 9068510, 9095663, 1550086, 15223692, 6740415, 5854791, 11561221, 16555421, 4495659, 3837514, 8308636, 10238976, 15537215,
            1790635, 5619983, 9896472, 1553461, 9162310, 5215055, 5336509, 140422, 3707017, 6843105, 4678697, 1165289, 6713838, 5074305, 11070002, 6684038,
            11532335, 4636657, 15963864, 8044897, 9541844, 14691192, 832827, 2277592, 10944126, 15111259, 1283116, 10424870, 9455185, 4112797, 10222428, 9822599,
            11048785, 16070058, 4800525, 12215255, 9924177, 4962392, 12869736, 15832053, 4139498, 13864358, 1933121, 160770, 4883368, 2429068, 8966813, 15817390,
            12989912, 7933320, 851212, 6327647, 5244335, 4723593, 15596159, 3662674, 5659776, 1361317, 5112425, 4054879, 16506968, 13905636, 11917764, 6635140,
            10229745, 14248148, 8179255, 6125997, 5353160, 6211484, 10320900, 4254842, 2561425, 8025065, 7856953, 3468803, 9824246, 16800081, 6245875, 12420003,
            6501648, 13294085, 4813435, 10871209, 6545935, 4714148, 11749717, 5102236, 8419884, 12115038, 5797602, 7092234, 7270947, 4499510, 2516872, 9874182,
            12831108, 5163519, 14188075, 1765141, 3336379, 2424997, 5554909, 5632936, 7029469, 9015776, 7145235, 4766761, 12777424, 4685517, 5451477, 4693514,
            14502132, 4239532, 12309978, 12779189, 15635654, 13204440, 7850975, 8042197, 11030591, 4354244, 12831322, 10128779, 3522088, 5433734, 5116425, 14051729,
            10687001, 5508827, 13164340, 3590905, 15045104, 14613823, 5838463, 2709696, 11123373, 15726407, 6796145, 1532872, 6009285, 4201054, 4515181, 9373428,
            15967613, 13662028, 7270741, 12773639, 4694362, 10624928, 16646188, 11141393, 1542477, 1608897, 9361527, 6567316, 5958623, 11987483, 10509534, 12582614,
            5012006, 1762956, 4447818, 7387524, 708325, 335969, 14822817, 917007, 10580635, 12552643, 6546716, 9517138, 8228639, 9645403, 11152745, 4425595,
            7895591, 16389707, 10700078, 16205484, 8872687, 4713787, 8719090, 14667304, 10569345, 7497084, 5265213, 5660675, 12774102, 10022847, 10107501, 4858715,
            9157470, 1753012, 15680765, 14979415, 14389927, 12622848, 786720, 3278745, 853097, 8454150, 982576, 16075084, 498420, 13887294, 16318709, 12893686,
            10768292, 11025553, 14636485, 9911994, 7215659, 14690968, 13427002, 13285821, 13999931, 2890810, 906227, 14330453, 10682394, 4980190, 12651827, 14576168,
            7652281, 16374046, 16105684, 14038390, 13804177, 14827364, 7816675, 4271588, 5985236, 9559769, 8674316, 9132348, 15601954, 971234, 1421410, 8704636,
            10312725, 2161253, 5513937, 12430226, 9060352, 3720079, 16291873, 11621772, 772885, 3469701, 9590461, 7445288, 14633513, 14238395, 11148683, 10274737,
            3205852, 7360180, 10334224, 7600517, 7394501, 904997, 7308413, 8358556, 11836806, 3789130, 10757468, 8109301, 8977995, 2738270, 8100044, 10434532,
            1626076, 9790193, 12899348, 11313513, 12302222, 1442073, 9272416, 12677440, 10934987, 14853993, 8012691, 10545941, 15561891, 5546386, 7147001, 4891686,
            367999, 687099, 5847063, 10352910, 10302239, 305206, 2680720, 1243873, 10279252, 862313, 13818032, 10257522, 10924470, 15131539, 11383243, 10436442,
            2999851, 12373233, 11567843, 2076663, 443644, 7809821, 10943528, 9331798, 1771255, 7240149, 2160582, 8342292, 12366343, 13110502, 3006529, 10184725,
            4000157, 10807781, 13441696, 9310970, 13180885, 9069760, 13073593, 11574287, 15660995, 9977953, 4207566, 1420046, 10011284, 11806593, 8132505, 5719744,
            6657667, 10999552, 16035738, 2628885, 14181142, 36895, 13913537, 15456708, 15359255, 3888589, 13547141, 3656160, 3613581, 10673239, 10972997, 9050018,
            16379615, 3635922, 4803503, 7019554, 1794283, 13617073, 9375958, 9194909, 4871786, 11508652, 9753506, 6101334, 15983720, 8044812, 3894771, 8766356,
            9137911, 12440997, 6911092, 8728499, 3857007, 1621146, 14872887, 4848804, 16059761, 7966357, 202222, 12152229, 14470053, 3472544, 6137331, 4412072,
            1555869, 3995336, 818406, 7358777, 9632997, 14063755, 11859511, 15201753, 4442159, 1550808, 4483153, 7196737, 3396339, 1296353, 11959022, 7372124,
            5465965, 4228232, 16673794, 3840827, 14381136, 1964113, 1829197, 6143683, 3031442, 14207505, 15673050, 8416376, 1611209, 14072654, 3349660, 12712421,
            7197884, 9908795, 6982002, 3324349, 14389070, 1689232, 1563018, 5845802, 13580316, 5190612, 3897822, 11505968, 9142541, 10302659, 1736822, 4794103,
            3413989, 10345777, 5479687, 6716577, 9029709, 14686195, 1329204, 1148231, 10630825, 6900262, 14252744, 12716702, 16654654, 6285798, 2985992, 14679588,
            11487585, 3349352, 9545009, 7655989, 2869366, 11707775, 5232085, 11542850, 7960301, 4321662, 4175131, 8128545, 3818337, 2461129, 1985911, 525163,
            2764070, 14483365, 5075652, 10816757, 11628774, 12004620, 13027012, 258514, 14312612, 3368288, 11201221, 2823222, 16069732, 13289972, 6913275, 3361827,
            2199730, 7598157, 14669747, 12779404, 4222567, 11911786, 14518575, 6045181, 9067089, 3446433, 5170311, 15821933, 4865691, 12581721, 4589631, 15016706,
            9939178, 1213183, 5359012, 11861622, 11337767, 3237231, 5037413, 6912943, 13477259, 1829904, 6065621, 13310634, 486364, 16566684, 5732340, 5438271,
            14581389, 157332, 2410573, 15479696, 6118986, 13688895, 9837127, 6009520, 1231194, 1930062, 1133091, 8122764, 6389844, 2208243, 5180288, 9683077,
            6845519, 1471407, 7323525, 3618661, 1757000, 1920954, 3466844, 13493819, 4118227, 11219353, 2987694, 14966489, 13713666, 16254224, 14108140, 7578797,
            1448731, 9973168, 10486345, 13083813, 10684433, 2311135, 11098916, 13607055, 13518280, 2320971, 14039025, 12662406, 1265301, 3495043, 10664131, 16748099,
            6419741, 310531, 9545626, 4824859, 16474710, 5404674, 4711334, 8847505, 12129105, 14688747, 2461000, 11965938, 15201750, 16319070, 5945126, 4634784,
            9734505, 10758683, 4781920, 15128293, 515697, 10669127, 12941605, 13888154, 4269947, 12129597, 10595316, 14287597, 6160331, 2178347, 13674391, 15934704,
            8081452, 12730909, 438860, 6382007, 12234840, 3378460, 3650964, 3187251, 11313503, 15263546, 10489202, 13780686, 10806196, 1118726, 1416802, 9671963,
            3601976, 5618005, 644680, 363547, 8092216, 7919291, 10509503, 5374993, 1792350, 14952543, 12479701, 12817119, 11336622, 6705449, 7623414, 3429409,
            4625410, 294959, 3271584, 4919832, 3106587, 4795645, 2675761, 10626482, 14333176, 13481486, 9630355, 16017601, 102419, 2827976, 13859145, 5661807,
            15435615, 4076500, 1841120, 13458454, 7843039, 7376293, 12818926, 3305346, 4723609, 7394411, 4210363, 3372563, 4643590, 2676458, 4546409, 1708711,
            15969219, 11526810, 12697456, 9057035, 2821493, 8023436, 3210572, 8607187, 12575420, 11561312, 4613309, 1900170, 9102266, 743188, 4360749, 5007029,
            2090916, 2643218, 15033702, 7359766, 14258893, 4757188, 8926885, 9375838, 2130767, 735236, 6206447, 3142018, 16297630, 10654583, 6175411, 10913776,
            15390460, 5189869, 592440, 1494378, 314200, 13543972, 8742587, 10803444, 11333918, 11242056, 14346752, 1102388, 11657507, 16508792, 8604848, 15213669,
            3248396, 4382639, 16496728, 16337734, 9692856, 2000715, 3788331, 7721530, 4310870, 14487631, 16500902, 16356090, 3454663, 8703641, 6474221, 8987801,
            15569561, 4471692, 7139567, 15851789, 1620868, 15396164, 13421374, 14217013, 11251876, 10259922, 15201737, 2398844, 10099633, 9048488, 15543059, 15904366,
            7372927, 15862183, 15342486, 562355, 11305289, 13671850, 12048098, 12503248, 3259258, 14505847, 11833396, 12857011, 1587301, 16230882, 2597365, 2461115,
            3823159, 13123959, 1205770, 2661988, 4870840, 7242506, 12080825, 10491685, 11725051, 170701, 12158230, 6210690, 13708350, 14659538, 4807684, 8230998,
            140641, 5722187, 5291958, 416531, 10838230, 11486785, 6297047, 4239038, 9931414, 4421535, 3040135, 6268892, 3757508, 8657877, 13935368, 15489826,
            4080473, 5924403, 14914786, 12657459, 12001871, 8152642, 257917, 11050963, 6786379, 6866327, 15135519, 3701674, 12158641, 1323517, 9153090, 15432726,
            3827995, 16319311, 7921800, 614211, 10864862, 6125405, 15835332, 10435071, 14900993, 4361399, 14766770, 5276151, 2041498, 9361583, 7843904, 3500580,
            6509646, 484467, 411368, 376050, 13874234, 2220412, 4388415, 8885942, 8502621, 4828906, 6234389, 16532438, 13824681, 4138404, 10123204, 8721965,
            4435452, 12225533, 5265121, 14306713, 996576, 10172982, 16094370, 3400139, 14977246, 1615774, 14175885, 4843252, 5380933, 13916988, 729884, 206587,
            7268718, 2901639, 7947304, 7899536, 15521541, 11988700, 2016327, 8546469, 16670114, 12137140, 12018127, 7969513, 6078855, 13730300, 3155306, 11169547,
            3231209, 5200457, 5656843, 9137997, 13551278, 9754389, 7027836, 16115172, 15433006, 10746570, 15026594, 14976664, 5769713, 9782134, 11985077, 11156652,
            15288549, 2628064, 4310063, 333115, 2917706, 8724254, 6477678, 1316446, 12995947, 2859886, 9892482, 1044822, 5351969, 15013652, 7478674, 8482350,
            13436429, 9872884, 15152314, 5063644, 15585535, 2588345, 8158041, 4835087, 1575461, 16509793, 11655960, 16295263, 5051852, 12122955, 8545024, 1280942,
            1358421, 12199906, 7988985, 5957454, 12428548, 14646493, 2946238, 11801458, 9937105, 10016261, 708217, 8122056, 15293135, 14357918, 1979216, 5866400,
            15552253, 9823452, 16720440, 15606755, 16092747, 14599702, 10768305, 9222057, 4165566, 4503133, 14315333, 16791876, 7689683, 15001981, 10124183, 8274340,
            8091124, 2319820, 13870920, 2286453, 7421091, 1144258, 11159978, 3074023, 863594, 6843149, 15706282, 11911608, 4274285, 7324609, 7489242, 15311893,
            91659, 7906285, 3530009, 6933833, 10733038, 4394548, 16221589, 5410042, 5933264, 5612964, 6915265, 12128141, 47592, 14352434, 15980198, 10510081,
        };

        private static final int[] zetainv = new int[]{

            821595, 2449359, 16754201, 4673652, 9886528, 11188829, 10868529, 11391751, 580204, 12407245, 6068755, 9867960, 13271784, 8895508, 16710134, 1489900,
            9312551, 9477184, 12527508, 4890185, 1095511, 9958644, 15938199, 13727770, 5641815, 15657535, 9380702, 14515340, 2930873, 14481973, 8710669, 8527453,
            6677610, 1799812, 9112110, 9917, 2486460, 12298660, 12636227, 7579736, 6033488, 2202091, 709046, 1195038, 81353, 6978341, 1249540, 10935393,
            14822577, 2443875, 1508658, 8679737, 16093576, 6785532, 6864688, 5000335, 13855555, 2155300, 4373245, 10844339, 8812808, 4601887, 15443372, 15520851,
            8256769, 4678838, 11749941, 506530, 5145833, 292000, 15226332, 11966706, 8643752, 14213448, 1216258, 11738149, 1649479, 6928909, 3365364, 8319443,
            9323119, 1788141, 11449824, 15756971, 6909311, 13941907, 3805846, 15485347, 10324115, 8077539, 13884087, 16468678, 12491730, 14173729, 1513244, 5645141,
            4816716, 7019659, 11032080, 1825129, 1775199, 6055223, 1368787, 686621, 9773957, 7047404, 3250515, 7663796, 11144950, 11601336, 13570584, 5632246,
            13646487, 3071493, 10722938, 8832280, 4783666, 4664653, 131679, 8255324, 14785466, 4813093, 1280252, 8902257, 8854489, 13900154, 9533075, 16595206,
            16071909, 2884805, 11420860, 11958541, 2625908, 15186019, 1824547, 13401654, 707423, 6628811, 15805217, 2495080, 11536672, 4576260, 12366341, 8079828,
            6678589, 12663389, 2977112, 269355, 10567404, 11972887, 8299172, 7915851, 12413378, 14581381, 2927559, 16425743, 16390425, 16317326, 10292147, 13301213,
            8957889, 7440210, 14760295, 11525642, 2035023, 12440394, 1900800, 6366722, 966461, 10676388, 5936931, 16187582, 8879993, 482482, 12973798, 1369067,
            7648703, 15478276, 4643152, 13100119, 1666274, 9935466, 10015414, 5750830, 16543876, 8649151, 4799922, 4144334, 1887007, 10877390, 12721320, 1311967,
            2866425, 8143916, 13044285, 10532901, 13761658, 12380258, 6870379, 12562755, 10504746, 5315008, 5963563, 16385262, 11509835, 11079606, 16661152, 8570795,
            11994109, 2142255, 3093443, 10591103, 4643563, 16631092, 5076742, 6310108, 4720968, 9559287, 11930953, 14139805, 15596023, 3677834, 12978634, 14340678,
            14204428, 570911, 15214492, 3944782, 4968397, 2295946, 13542535, 4298545, 4753695, 3129943, 5496504, 16239438, 1459307, 939610, 9428866, 897427,
            1258734, 7753305, 6702160, 14402949, 1600056, 6541871, 5549917, 2584780, 3380419, 1405629, 15180925, 950004, 9662226, 12330101, 1232232, 7813992,
            10327572, 8098152, 13347130, 445703, 300891, 2314162, 12490923, 9080263, 13013462, 14801078, 7108937, 464059, 305065, 12419154, 13553397, 1588124,
            8196945, 293001, 5144286, 15699405, 2455041, 5559737, 5467875, 5998349, 8059206, 3257821, 16487593, 15307415, 16209353, 11611924, 1411333, 5888017,
            10626382, 6147210, 504163, 13659775, 10595346, 16066557, 14671026, 7425955, 7874908, 12044605, 2542900, 9442027, 1768091, 14158575, 14710877, 11794764,
            12441044, 16058605, 7699527, 14901623, 12188484, 5240481, 4226373, 8194606, 13591221, 8778357, 13980300, 7744758, 4104337, 5274983, 832574, 15093082,
            12255384, 14125335, 12158203, 13429230, 12591430, 9407382, 12078184, 13496447, 3982867, 9425500, 8958754, 3343339, 14960673, 12725293, 1366178, 11139986,
            2942648, 13973817, 16699374, 784192, 7171438, 3320307, 2468617, 6175311, 14126032, 12006148, 13695206, 11881961, 13530209, 16506834, 12176383, 13372384,
            9178379, 10096344, 5465171, 3984674, 4322092, 1849250, 15009443, 11426800, 6292290, 8882502, 8709577, 16438246, 16157113, 11183788, 13199817, 7129830,
            15384991, 15683067, 5995597, 3021107, 6312591, 1538247, 5488290, 13614542, 13150829, 13423333, 4566953, 10419786, 16362933, 4070884, 8720341, 867089,
            3127402, 14623446, 10641462, 2514196, 6206477, 4672196, 12531846, 2913639, 3860188, 6132666, 16286096, 1673500, 12019873, 6043110, 7067288, 12167009,
            10856667, 482723, 1600043, 4835855, 14340793, 2113046, 4672688, 7954288, 12090459, 11397119, 327083, 11976934, 7256167, 16491262, 10382052, 53694,
            6137662, 13306750, 15536492, 4139387, 2762768, 14480822, 3283513, 3194738, 5702877, 14490658, 6117360, 3717980, 6315448, 6828625, 15353062, 9222996,
            2693653, 547569, 3088127, 1835304, 13814099, 5582440, 12683566, 3307974, 13334949, 14880839, 15044793, 13183132, 9478268, 15330386, 9956274, 7118716,
            11621505, 14593550, 10411949, 8679029, 15668702, 14871731, 15570599, 10792273, 6964666, 3112898, 10682807, 1322097, 14391220, 16644461, 2220404, 11363522,
            11069453, 235109, 16315429, 3491159, 10736172, 14971889, 3324534, 9888850, 11764380, 13564562, 5464026, 4940171, 11442781, 15588610, 6862615, 1785087,
            12212162, 4220072, 11936102, 979860, 11631482, 13355360, 7734704, 10756612, 2283218, 4890007, 12579226, 4022389, 2132046, 9203636, 14602063, 13439966,
            9888518, 3511821, 732061, 13978571, 5600572, 13433505, 2489181, 16543279, 3774781, 4797173, 5173019, 5985036, 11726141, 2318428, 14037723, 16276630,
            14815882, 14340664, 12983456, 8673248, 12626662, 12480131, 8841492, 5258943, 11569708, 5094018, 13932427, 9145804, 7256784, 13452441, 5314208, 2122205,
            13815801, 10515995, 147139, 4085091, 2549049, 9901531, 6170968, 15653562, 15472589, 2115598, 7772084, 10085216, 11322106, 6456016, 13387804, 12007690,
            15064971, 6499134, 7659252, 5295825, 12903971, 11611181, 3221477, 10955991, 15238775, 15112561, 2412723, 13477444, 9819791, 6892998, 9603909, 4089372,
            13452133, 2729139, 15190584, 8385417, 1128743, 2594288, 13770351, 10658110, 14972596, 14837680, 2420657, 12960966, 127999, 12573561, 11335828, 9429669,
            4842771, 15505440, 13405454, 9605056, 12318640, 15250985, 12359634, 1600040, 4942282, 2738038, 7168796, 9443016, 15983387, 12806457, 15245924, 12389721,
            10664462, 13329249, 2331740, 4649564, 16599571, 8835436, 742032, 11952989, 1928906, 15180647, 12944786, 8073294, 9890701, 4360796, 7663882, 8035437,
            12907022, 8756981, 818073, 10700459, 7048287, 5293141, 11930007, 7606884, 7425835, 3184720, 15007510, 9782239, 11998290, 13165871, 422178, 7751775,
            5828796, 6128554, 13188212, 13145633, 3254652, 12913204, 1442538, 1345085, 2888256, 16764898, 2620651, 14172908, 766055, 5802241, 10144126, 11082049,
            8669288, 4995200, 6790509, 15381747, 12594227, 6823840, 1140798, 5227506, 3728200, 7732033, 3620908, 7490823, 3360097, 5994012, 12801636, 6617068,
            13795264, 3691291, 4435450, 8459501, 14641211, 9561644, 15030538, 7469995, 5858265, 8991972, 16358149, 14725130, 5233950, 4428560, 13801942, 6365351,
            5418550, 1670254, 5877323, 6544271, 2983761, 15939480, 6522541, 15557920, 14121073, 16496587, 6499554, 6448883, 10954730, 16114694, 16433794, 11910107,
            9654792, 11255407, 1239902, 6255852, 8789102, 1947800, 5866806, 4124353, 7529377, 15359720, 4499571, 5488280, 3902445, 7011600, 15175717, 6367261,
            8701749, 14063523, 7823798, 8692492, 6044325, 13012663, 4964987, 8443237, 9493380, 15896796, 9407292, 9201276, 6467569, 9441613, 13595941, 6527056,
            5653110, 2563398, 2168280, 9356505, 7211332, 13332092, 16028908, 5180021, 509920, 13081714, 7741441, 4371567, 11287856, 14640540, 6489068, 8097157,
            15380383, 15830559, 1199839, 7669445, 8127477, 7242024, 10816557, 12530205, 8985118, 1974429, 2997616, 2763403, 696109, 427747, 9149512, 2225625,
            4149966, 11821603, 6119399, 2471340, 15895566, 13910983, 2801862, 3515972, 3374791, 2110825, 9586134, 6889799, 2165308, 5776240, 6033501, 3908107,
            483084, 2914499, 16303373, 726709, 15819217, 8347643, 15948696, 13523048, 16015073, 4178945, 2411866, 1822378, 1121028, 15048781, 7644323, 11943078,
            6694292, 6778946, 4027691, 11141118, 11536580, 9304709, 6232448, 2134489, 8082703, 12088006, 7929106, 596309, 6101715, 412086, 8906202, 12376198,
            5649048, 7156390, 8573154, 7284655, 10255077, 4249150, 6221158, 15884786, 1978976, 16465824, 16093468, 9414269, 12353975, 15038837, 11789787, 4219179,
            6292259, 4814310, 10843170, 10234477, 7440266, 15192896, 15259316, 5660400, 155605, 6176865, 12107431, 4028154, 9531052, 3139765, 834180, 7428365,
            12286612, 12600739, 10792508, 15268921, 10005648, 1075386, 5678420, 14092097, 10963330, 2187970, 1756689, 13210888, 3637453, 11292966, 6114792, 2750064,
            11685368, 11368059, 13279705, 6673014, 3970471, 12447549, 5771202, 8759596, 8950818, 3597353, 1166139, 4022604, 4491815, 12562261, 2299661, 12108279,
            11350316, 12116276, 4024369, 12035032, 9656558, 7786017, 9772324, 11168857, 11246884, 14376796, 13465414, 15036652, 2613718, 11638274, 3970685, 6927611,
            14284921, 12302283, 9530846, 9709559, 11004191, 4686755, 8381909, 11699557, 5052076, 12087645, 10255858, 5930584, 11988358, 3507708, 10300145, 4381790,
            10555918, 1712, 6977547, 13332990, 8944840, 8776728, 14240368, 12546951, 6480893, 10590309, 11448633, 10675796, 8622538, 2553645, 6572048, 10166653,
            4884029, 2896157, 294825, 12746914, 11689368, 15440476, 11142017, 13139119, 1205634, 12078200, 11557458, 10474146, 15950581, 8868473, 3811881, 984403,
            7834980, 14372725, 11918425, 16641023, 14868672, 2937435, 12662295, 969740, 3932057, 11839401, 6877616, 4586538, 12001268, 731735, 5753008, 6979194,
            6579365, 12688996, 7346608, 6376923, 15518677, 1690534, 5857667, 14524201, 15968966, 2110601, 7259949, 8756896, 837929, 12165136, 5269458, 10117755,
            5731791, 11727488, 10087955, 15636504, 12123096, 9958688, 13094776, 16661371, 11465284, 11586738, 7639483, 15248332, 6905321, 11181810, 15011158, 1264578,
            6562817, 8493157, 12964279, 12306134, 246372, 5240572, 10947002, 10061378, 1578101, 15251707, 7706130, 7733283, 1632168, 3413812, 12717554, 11146045,
            10557949, 14507009, 3775110, 14368915, 15823864, 13318199, 2342450, 15595465, 5746365, 8898254, 15673516, 8154445, 16490375, 10755393, 12322585, 12105642,
            14885486, 8437400, 16378679, 3829417, 2802123, 4163938, 1909433, 13572447, 4149994, 15496099, 7986236, 4280791, 15096954, 3243940, 2025656, 9721139,
            10314342, 2483471, 13360780, 10772445, 8005615, 10354976, 9608812, 9051734, 14770404, 10808283, 13563768, 1649963, 13605364, 16595303, 11832147, 1813216,
            2833716, 133643, 12277947, 1195590, 982163, 4660713, 2720389, 14393377, 5011256, 14969372, 10564669, 5891020, 7325825, 872733, 8976707, 7100415,
            11418254, 6003809, 5554445, 8740521, 13745847, 4091645, 15420936, 11513474, 4297330, 11830308, 2233625, 15797115, 13248860, 8054087, 465383, 15426094,
            2553130, 7801947, 13634221, 6351909, 1361991, 16130771, 6595625, 12693605, 11864710, 7465410, 16028316, 11499642, 8549920, 16166693, 12247569, 13456628,
            454762, 16159841, 1397667, 10263356, 327398, 2909635, 11396794, 12466313, 7206000, 2476581, 13367458, 13446505, 15031966, 10049568, 3959573, 10433618,
            11641429, 8180210, 11458173, 2494601, 13859670, 4517604, 5702475, 12140773, 313255, 11894482, 13544947, 1596062, 8740029, 13888376, 6184132, 12606931,
            374608, 15312531, 8681134, 13804516, 11025512, 13586589, 5959655, 7584396, 4774758, 11775507, 11075370, 3852375, 5567978, 3713119, 5189761, 2036297,
            4042373, 5683147, 2763371, 9604753, 318598, 7391752, 12739349, 15042675, 14879336, 7846664, 1183402, 1238565, 2992846, 15254897, 11580375, 10396943,
            3048663, 14649693, 7255664, 886945, 7749493, 2538672, 12273321, 15782699, 13293114, 2174637, 2286590, 10557693, 161834, 333136, 11567614, 15924691,
            14022793, 5990858, 6600954, 6353627, 8183419, 6239027, 2224595, 6897665, 13635074, 680254, 1667079, 14766468, 1468530, 1563250, 15286643, 13055355,
            8683947, 13320686, 5441909, 9192216, 12136892, 5841716, 8813420, 906906, 13549092, 7895326, 6822998, 11322773, 3173329, 9871823, 10594077, 749286,
            16541255, 725939, 10669919, 6985174, 16636391, 1881292, 2570909, 5526448, 66198, 768955, 3132042, 1873585, 12912966, 15917511, 10679660, 8379818,
            5035676, 10512349, 8939303, 4622243, 6896355, 10681208, 13686933, 1514377, 787135, 16678749, 4255084, 12394926, 15845475, 9869934, 10854397, 5018357,
            12533088, 14687646, 11871683, 15249324, 5602117, 14565429, 8888270, 11374994, 3267677, 8427118, 362319, 15574611, 16130981, 9394936, 1492193, 15376154,
            8307607, 5939433, 15697916, 1072782, 7306626, 1618515, 10063296, 5530872, 5793842, 5934715, 9757239, 14145711, 16102628, 1770293, 5521873, 1907239,
            14318931, 6225665, 428122, 14912305, 5878799, 15422980, 16070268, 5956402, 10339774, 13220681, 12001065, 7695225, 2714587, 9065998, 12667553, 2114083,
            8051497, 16499706, 2360705, 8579226, 5659760, 1562962, 294553, 10655396, 11306932, 14555015, 1402179, 14319385, 15717407, 5043158, 7519494, 12131925,
            5249029, 664314, 6852311, 10515792, 3921634, 4953498, 5021504, 15691468, 5666322, 5815903, 9355417, 6267441, 9621026, 15749047, 9808984, 19386,
            9650898, 4291789, 2044005, 15040708, 7041175, 12871565, 8203613, 1654741, 5562425, 14260715, 394978, 221491, 6239825, 12530752, 1296244, 7340276,
            1547049, 6269549, 4004436, 465491, 13599640, 4702227, 16638565, 1549179, 13668843, 13382103, 5899360, 8595459, 10417674, 3901544, 14054253, 1308500,
            8425916, 7009389, 11042034, 14370396, 5274110, 15744471, 3092702, 14158949, 3145406, 8271561, 1288557, 6667472, 13554544, 895091, 683385, 10811079,
            5134349, 5385082, 5637156, 9112195, 12860113, 2251331, 11000886, 7811613, 6100579, 2548671, 373130, 6171358, 11526862, 10928401, 5175694, 4192983,
            3541744, 2148849, 5413454, 4983702, 4864136, 13377689, 13916801, 8333318, 63957, 9110317, 734098, 12469467, 12023532, 15770794, 11597330, 797034,
            10531998, 2867563, 8335702, 13309806, 4714406, 5306346, 2870089, 1725967, 1250219, 16032956, 14445104, 14394696, 16439336, 16720752, 7574732, 2750565,
            11634376, 6699529, 7465023, 4555678, 6202044, 10983495, 15203371, 6269701, 14950402, 8984861, 9644324, 15265857, 4274987, 3225714, 12124397, 12673590,
            1958001, 2566883, 16381804, 10686385, 12936149, 342641, 6388619, 15381494, 14399429, 1811404, 16080081, 16799750, 16572496, 907359, 14371418, 5464519,
            8906904, 3690304, 5211874, 14061117, 4066943, 4109131, 2738021, 9628567, 6822878, 12376726, 16696389, 12299704, 16416956, 3260574, 10798164, 1436428,
            8753957, 10292235, 10703579, 5382735, 7534272, 2470433, 7428167, 6785470, 14627485, 6063063, 15578090, 2545398, 7084966, 13438871, 157578, 13070706,
            3859142, 3278338, 5352675, 9685649, 15450918, 14491736, 12061565, 16784929, 5997412, 5982085, 14881109, 5295898, 16127779, 9234897, 14830253, 1673127,
            13441855, 14871876, 10400676, 7858477, 13446422, 9343872, 8262403, 4761034, 9159604, 16079115, 1217420, 13013596, 4562840, 8319946, 3826552, 10884673,
            13075471, 3496561, 12378862, 4659986, 5482515, 11830427, 7144803, 2728931, 13803028, 14468959, 1227098, 6140624, 9220565, 1657806, 3821475, 16691529,
            1578044, 7771483, 16507128, 8250206, 5658170, 11327391, 3496535, 314290, 11013185, 8861853, 11572971, 13259209, 7432414, 9668605, 12600466, 2292431,
            1423359, 4715507, 15333248, 13270063, 13091620, 5736211, 1161005, 2349236, 6358990, 8322749, 3306857, 8748220, 2750826, 9875027, 5162700, 12747261,
            5025784, 6103466, 4682387, 3837188, 5804341, 5992457, 16680480, 7952148, 11082067, 9019843, 8834951, 3761874, 3799119, 6380919, 6481384, 7818049,
            4575465, 1746439, 9680819, 16066692, 1167395, 832066, 3329362, 5008812, 16216941, 16094553, 3270370, 8997241, 1685257, 14447158, 11329304, 10163544,
            10565895, 15565315, 4300302, 15410573, 5212240, 11686650, 2889841, 6344309, 1648273, 16681047, 15367889, 5991872, 6810544, 6733366, 9241651, 13321706,
            1283001, 19579, 7477208, 7447263, 3134174, 12831521, 8500914, 3296227, 13515381, 2804933, 14858633, 12841034, 4571198, 13040457, 15019124, 4947524,
            6716020, 1883032, 7739005, 3924482, 13480009, 14963290, 8761140, 12031283, 538953, 9133359, 15445645, 11378913, 13701403, 1838808, 9332803, 12504354,
            2179148, 7433476, 4685746, 7798858, 15686407, 2885064, 7284783, 8224542, 15889037, 13988698, 141647, 5836046, 2718369, 1331632, 4396102, 2893216,
            13934922, 533784, 16025944, 2649612, 10960371, 313721, 10293986, 2609966, 13018574, 13587342, 11904175, 11584046, 916956, 16330119, 11055215, 13554709,
            12551627, 11337709, 384665, 7771108, 7292015, 16393958, 14612188, 14822319, 15341855, 261963, 3106456, 4530233, 14901044, 326110, 3561261, 9531257,
            12687777, 1466757, 13312254, 10487960, 5255348, 6631465, 3912145, 3025732, 3039550, 11659780, 330993, 4238471, 13242026, 1709628, 6873117, 2236525,
            3285694, 3781249, 12878401, 16367541, 8706727, 12066492, 12085784, 2752067, 16351182, 7728608, 2331782, 10161308, 15692717, 7671127, 16345907, 4353321,
            4115271, 12013266, 15756220, 7607495, 4554588, 708234, 8102188, 15270990, 2495982, 1755289, 625122, 9656878, 1555162, 12441806, 11463529, 16499680,
            14147015, 10153152, 13940252, 11126831, 10319604, 4152742, 2954241, 6383230, 10064235, 11145169, 9618400, 7169675, 10360739, 9005509, 2645105, 14177773,
            9351585, 7440207, 2352820, 15526072, 8692958, 2924935, 13966856, 7650015, 11387526, 5937233, 6652929, 5608869, 11671725, 1959941, 15160647, 11312595,
            6030154, 1521221, 5246303, 12565328, 15964772, 6182762, 4864020, 14956570, 5867941, 1856536, 6213751, 1551563, 10086429, 196195, 2394733, 4864784,
            3642107, 380353, 5576600, 9475292, 5830566, 3184092, 5185532, 1515338, 9216895, 7288363, 2758481, 6348407, 9892068, 15737010, 10596118, 16566903,
            14631233, 10668602, 13440662, 9528237, 10596828, 8930865, 4268387, 10787750, 2886254, 6065329, 11957046, 10810609, 7461434, 4014234, 15237476, 12660123,
            7384609, 3191634, 13449874, 8708325, 2113838, 5585986, 10353727, 12905340, 5329945, 699650, 8368997, 14213066, 7493707, 5212734, 3736288, 10623490,
            570149, 3409339, 11946422, 11150660, 4827552, 897206, 11020900, 13209153, 9113669, 2979089, 731423, 14261520, 6574750, 11917864, 6284589, 6372450,
            16062465, 6862479, 3429750, 6521116, 5557895, 7842510, 9200591, 1509546, 1839667, 15017920, 15170419, 16775431, 8480943, 3541663, 12852126, 12614306,
            8422917, 16687653, 110628, 1184544, 14002963, 7938213, 3421072, 10211744, 9276348, 13392507, 5630787, 13385237, 6362676, 4791904, 5436615, 3323521,
            8334312, 15717049, 2602302, 8853339, 1711116, 14013260, 634819, 5277314, 14070906, 2481906, 9484960, 3039901, 8857820, 14187328, 8996248, 830598,
            12311370, 2094753, 6499842, 10640113, 11937071, 10531117, 5819243, 12603733, 1455125, 6586555, 7833010, 7872580, 14363128, 9667784, 11050327, 10560827,
            355773, 13421382, 433018, 2154250, 5776803, 4511136, 3640831, 946251, 1154755, 5437093, 675452, 11458789, 12558928, 11760340, 4110864, 4934804,
            10817671, 7506516, 5907399, 5056548, 15260540, 15072231, 12791377, 4451420, 10368068, 13102636, 8238141, 13150920, 2203225, 8369256, 1193868, 13767444,
            15658593, 15589090, 9447041, 184421, 15509178, 15252241, 15201797, 1332049, 12322536, 5675274, 3287980, 1345327, 10295825, 8720512, 1111909, 11271476,
            12642511, 8953767, 11225396, 363011, 12188697, 16391104, 5826324, 957117, 9541079, 8463175, 9891469, 4336214, 4548482, 5891706, 12642305, 15523561,
            10311264, 1794407, 1362675, 5082701, 6986414, 841624, 15727576, 12199719, 8115551, 4735941, 13762508, 6314907, 515135, 8583081, 15203524, 9546404,
            11355746, 2228937, 4818852, 1700730, 10799523, 11762786, 5659428, 8399317, 3401211, 8090907, 6891924, 453178, 16699808, 7333501, 905308, 16702946,
            10771260, 15949023, 7288759, 9147391, 14047061, 15190157, 11643123, 12063909, 11484554, 3356635, 7086211, 8804781, 14148559, 11153844, 16072220, 10094371,
            15208389, 9521950, 1110598, 7244254, 391450, 7685199, 14264355, 1671851, 3104100, 14581708, 11198894, 423698, 13152609, 11791191, 5631897, 7836620,
            12659478, 928642, 12541366, 8909597, 1108807, 7432844, 11924054, 16067059, 8161608, 242685, 13981684, 4550123, 4624583, 12513096, 16564215, 6291712,
        };


        static void poly_uniform(int[] a, byte[] seed, int seedOffset)
        {
            int pos = 0, i = 0, nbytes = (PARAM_Q_LOG + 7) / 8;
            int nblocks = PARAM_GEN_A;
            int val1, val2, val3, val4, mask = (1 << PARAM_Q_LOG) - 1;
            byte[] buf = new byte[HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A];
            short dmsp = 0;


            HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                buf, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A,
                dmsp++,
                seed, seedOffset, CRYPTO_RANDOMBYTES
            );


            while (i < PARAM_N)
            {
                if (pos > HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * nblocks - 4 * nbytes)
                {
                    nblocks = 1;

                    HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(
                        buf, 0, HashUtils.SECURE_HASH_ALGORITHM_KECCAK_128_RATE * PARAM_GEN_A,
                        dmsp++,
                        seed, seedOffset, CRYPTO_RANDOMBYTES
                    );

                    pos = 0;
                }
                val1 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                val2 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                val3 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                val4 = Pack.littleEndianToInt(buf, pos) & mask;
                pos += nbytes;
                if (val1 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = reduce((long)val1 * PARAM_R2_INVN);
                }
                if (val2 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = reduce((long)val2 * PARAM_R2_INVN);
                }
                if (val3 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = reduce((long)val3 * PARAM_R2_INVN);
                }
                if (val4 < PARAM_Q && i < PARAM_N)
                {
                    a[i++] = reduce((long)val4 * PARAM_R2_INVN);
                }
            }
        }


        static int reduce(long a)
        { // Montgomery reduction
            long u;

            u = (a * (long)PARAM_QINV) & 0xFFFFFFFFL;
            u *= PARAM_Q;
            a += u;
            return (int)(a >> 32);
        }


        static void ntt(int[] a, int[] w)
        { // Forward NTT transform
            int NumoProblems = PARAM_N >> 1, jTwiddle = 0;

            for (; NumoProblems > 0; NumoProblems >>= 1)
            {
                int jFirst, j = 0;
                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems)
                {
                    int W = (int)w[jTwiddle++];
                    for (j = jFirst; j < jFirst + NumoProblems; j++)
                    {
                        int temp = reduce((long)W * a[j + NumoProblems]);
                        a[j + NumoProblems] = a[j] - temp;
                        a[j] = temp + a[j];
                    }
                }
            }
        }


        static int barr_reduce(int a)
        { // Barrett reduction
            long u = (((long)a * PARAM_BARR_MULT) >> PARAM_BARR_DIV); // TODO u may need to be cast back to int.
            return a - (int)u * PARAM_Q;
        }


        static void nttinv(int[] a, int[] w)
        { // Inverse NTT transform
            int NumoProblems = 1, jTwiddle = 0;
            for (NumoProblems = 1; NumoProblems < PARAM_N; NumoProblems *= 2)
            {
                int jFirst, j = 0;
                for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems)
                {
                    int W = (int)w[jTwiddle++];
                    for (j = jFirst; j < jFirst + NumoProblems; j++)
                    {
                        int temp = a[j];

                        if (NumoProblems == 16)
                        {
                            a[j] = barr_reduce(temp + a[j + NumoProblems]);
                        }
                        else
                        {
                            a[j] = temp + a[j + NumoProblems];
                        }
                        a[j + NumoProblems] = reduce((long)W * (temp - a[j + NumoProblems]));
                    }
                }
            }

            for (int i = 0; i < PARAM_N / 2; i++)
            {
                a[i] = reduce((long)PARAM_R * a[i]);
            }
        }


        static void poly_pointwise(int[] result, int[] x, int[] y)
        { // Pointwise polynomial multiplication result = x.y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = reduce((long)x[i] * y[i]);
            }
        }


        static void poly_mul(int[] result, int[] x, int[] y)
        { // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)
            // The input x is assumed to be in NTT form
            int[] y_ntt = new int[PARAM_N];

            for (int i = 0; i < PARAM_N; i++)
            {
                y_ntt[i] = y[i];
            }

            ntt(y_ntt, zeta);
            poly_pointwise(result, x, y_ntt);
            nttinv(result, zetainv);
        }


        static void poly_add(int[] result, int[] x, int[] y)
        { // Polynomial addition result = x+y

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] + y[i];
            }
        }


        static void poly_add_correct(int[] result, int[] x, int[] y)
        { // Polynomial addition result = x+y with correction

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] + y[i];
                result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;    // If result[i] < 0 then add q
                result[i] -= PARAM_Q;
                result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;    // If result[i] >= q then subtract q
            }
        }


        static void poly_sub_correct(int[] result, int[] x, int[] y)
        { // Polynomial subtraction result = x-y with correction

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = x[i] - y[i];
                result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;    // If result[i] < 0 then add q
            }
        }


        static void poly_sub_reduce(int[] result, int[] x, int[] y)
        { // Polynomial subtraction result = x-y with Montgomery reduction

            for (int i = 0; i < PARAM_N; i++)
            {
                result[i] = reduce((long)PARAM_R * (x[i] - y[i]));
            }
        }

        static void sparse_mul16(int[] prod, int s[], int pos_list[], short sign_list[])
        {
            int i, j, pos;
//            short[] t = s;

            for (i = 0; i < PARAM_N; i++)
            {
                prod[i] = 0;
            }

            for (i = 0; i < PARAM_H; i++)
            {
                pos = pos_list[i];
                for (j = 0; j < pos; j++)
                {
                    prod[j] = prod[j] - sign_list[i] * s[j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    prod[j] = prod[j] + sign_list[i] * s[j - pos];
                }
            }
        }


        static void sparse_mul32(int[] prod, int[] pk, int[] pos_list, short[] sign_list)
        {
            int i, j, pos;

            for (i = 0; i < PARAM_N; i++)
            {
                prod[i] = 0;
            }

            for (i = 0; i < PARAM_H; i++)
            {
                pos = pos_list[i];
                for (j = 0; j < pos; j++)
                {
                    prod[j] = prod[j] - sign_list[i] * pk[j + PARAM_N - pos];
                }
                for (j = pos; j < PARAM_N; j++)
                {
                    prod[j] = prod[j] + sign_list[i] * pk[j - pos];
                }
            }
        }

    }

}
