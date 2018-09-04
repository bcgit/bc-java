package org.bouncycastle.math.ec.rfc8032.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Ed448Test
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

//    @BeforeClass
//    public static void init()
    public void setUp()
    {
        Ed448.precompute();
    }

//    @Test
    public void testEd448Consistency()
    {
        byte[] sk = new byte[Ed448.SECRET_KEY_SIZE];
        byte[] pk = new byte[Ed448.PUBLIC_KEY_SIZE];
        byte[] ctx = new byte[RANDOM.nextInt() & 7];
        byte[] m = new byte[255];
        byte[] sig1 = new byte[Ed448.SIGNATURE_SIZE];
        byte[] sig2 = new byte[Ed448.SIGNATURE_SIZE];

        RANDOM.nextBytes(ctx);
        RANDOM.nextBytes(m);

        for (int i = 0; i < 10; ++i)
        {
            RANDOM.nextBytes(sk);
            Ed448.generatePublicKey(sk, 0, pk, 0);

            int mLen = RANDOM.nextInt() & 255;

            Ed448.sign(sk, 0, ctx, m, 0, mLen, sig1, 0);
            Ed448.sign(sk, 0, pk, 0, ctx, m, 0, mLen, sig2, 0);

            assertTrue("Ed448 consistent signatures #" + i, Arrays.areEqual(sig1, sig2));

            boolean shouldVerify = Ed448.verify(sig1, 0, pk, 0, ctx, m, 0, mLen);

            assertTrue("Ed448 consistent sign/verify #" + i, shouldVerify);

            sig1[Ed448.PUBLIC_KEY_SIZE - 1] ^= 0x80;
            boolean shouldNotVerify = Ed448.verify(sig1, 0, pk, 0, ctx, m, 0, mLen);

            assertFalse("Ed448 consistent verification failure #" + i, shouldNotVerify);
        }
    }

//    @Test
    public void testEd448phConsistency()
    {
        byte[] sk = new byte[Ed448.SECRET_KEY_SIZE];
        byte[] pk = new byte[Ed448.PUBLIC_KEY_SIZE];
        byte[] ctx = new byte[RANDOM.nextInt() & 7];
        byte[] m = new byte[255];
        byte[] ph = new byte[Ed448.PREHASH_SIZE];
        byte[] sig1 = new byte[Ed448.SIGNATURE_SIZE];
        byte[] sig2 = new byte[Ed448.SIGNATURE_SIZE];

        RANDOM.nextBytes(ctx);
        RANDOM.nextBytes(m);

        for (int i = 0; i < 10; ++i)
        {
            RANDOM.nextBytes(sk);
            Ed448.generatePublicKey(sk, 0, pk, 0);

            int mLen = RANDOM.nextInt() & 255;

            Xof prehash = Ed448.createPrehash();
            prehash.update(m, 0, mLen);
            prehash.doFinal(ph, 0, ph.length);

            Ed448.signPrehash(sk, 0, ctx, ph, 0, sig1, 0);
            Ed448.signPrehash(sk, 0, pk, 0, ctx, ph, 0, sig2, 0);

            assertTrue("Ed448ph consistent signatures #" + i, Arrays.areEqual(sig1, sig2));

            boolean shouldVerify = Ed448.verifyPrehash(sig1, 0, pk, 0, ctx, ph, 0);

            assertTrue("Ed448ph consistent sign/verify #" + i, shouldVerify);

            sig1[Ed448.PUBLIC_KEY_SIZE - 1] ^= 0x80;
            boolean shouldNotVerify = Ed448.verifyPrehash(sig1, 0, pk, 0, ctx, ph, 0);

            assertFalse("Ed448ph consistent verification failure #" + i, shouldNotVerify);
        }
    }

//    @Test
    public void testEd448Vector1()
    {
        checkEd448Vector(
            ( "6c82a562cb808d10d632be89c8513ebf"
            + "6c929f34ddfa8c9f63c9960ef6e348a3"
            + "528c8a3fcc2f044e39a3fc5b94492f8f"
            + "032e7549a20098f95b"),
            ( "5fd7449b59b461fd2ce787ec616ad46a"
            + "1da1342485a70e1f8a0ea75d80e96778"
            + "edf124769b46c7061bd6783df1e50f6c"
            + "d1fa1abeafe8256180"),
            "",
            "",
            ( "533a37f6bbe457251f023c0d88f976ae"
            + "2dfb504a843e34d2074fd823d41a591f"
            + "2b233f034f628281f2fd7a22ddd47d78"
            + "28c59bd0a21bfd3980ff0d2028d4b18a"
            + "9df63e006c5d1c2d345b925d8dc00b41"
            + "04852db99ac5c7cdda8530a113a0f4db"
            + "b61149f05a7363268c71d95808ff2e65"
            + "2600"),
            "Ed448 Vector #1");
    }

//    @Test
    public void testEd448Vector2()
    {
        checkEd448Vector(
            ( "c4eab05d357007c632f3dbb48489924d"
            + "552b08fe0c353a0d4a1f00acda2c463a"
            + "fbea67c5e8d2877c5e3bc397a659949e"
            + "f8021e954e0a12274e"),
            ( "43ba28f430cdff456ae531545f7ecd0a"
            + "c834a55d9358c0372bfa0c6c6798c086"
            + "6aea01eb00742802b8438ea4cb82169c"
            + "235160627b4c3a9480"),
            "03",
            "",
            ( "26b8f91727bd62897af15e41eb43c377"
            + "efb9c610d48f2335cb0bd0087810f435"
            + "2541b143c4b981b7e18f62de8ccdf633"
            + "fc1bf037ab7cd779805e0dbcc0aae1cb"
            + "cee1afb2e027df36bc04dcecbf154336"
            + "c19f0af7e0a6472905e799f1953d2a0f"
            + "f3348ab21aa4adafd1d234441cf807c0"
            + "3a00"),
            "Ed448 Vector #2");
    }

//    @Test
    public void testEd448Vector3()
    {
        checkEd448Vector(
            ( "c4eab05d357007c632f3dbb48489924d"
            + "552b08fe0c353a0d4a1f00acda2c463a"
            + "fbea67c5e8d2877c5e3bc397a659949e"
            + "f8021e954e0a12274e"),
            ( "43ba28f430cdff456ae531545f7ecd0a"
            + "c834a55d9358c0372bfa0c6c6798c086"
            + "6aea01eb00742802b8438ea4cb82169c"
            + "235160627b4c3a9480"),
            "03",
            "666f6f",
            ( "d4f8f6131770dd46f40867d6fd5d5055"
            + "de43541f8c5e35abbcd001b32a89f7d2"
            + "151f7647f11d8ca2ae279fb842d60721"
            + "7fce6e042f6815ea000c85741de5c8da"
            + "1144a6a1aba7f96de42505d7a7298524"
            + "fda538fccbbb754f578c1cad10d54d0d"
            + "5428407e85dcbc98a49155c13764e66c"
            + "3c00"),
            "Ed448 Vector #3");
    }

//    @Test
    public void testEd448Vector4()
    {
        checkEd448Vector(
            ( "cd23d24f714274e744343237b93290f5"
            + "11f6425f98e64459ff203e8985083ffd"
            + "f60500553abc0e05cd02184bdb89c4cc"
            + "d67e187951267eb328"),
            ( "dcea9e78f35a1bf3499a831b10b86c90"
            + "aac01cd84b67a0109b55a36e9328b1e3"
            + "65fce161d71ce7131a543ea4cb5f7e9f"
            + "1d8b00696447001400"),
            "0c3e544074ec63b0265e0c",
            "",
            ( "1f0a8888ce25e8d458a21130879b840a"
            + "9089d999aaba039eaf3e3afa090a09d3"
            + "89dba82c4ff2ae8ac5cdfb7c55e94d5d"
            + "961a29fe0109941e00b8dbdeea6d3b05"
            + "1068df7254c0cdc129cbe62db2dc957d"
            + "bb47b51fd3f213fb8698f064774250a5"
            + "028961c9bf8ffd973fe5d5c206492b14"
            + "0e00"),
            "Ed448 Vector #4");
    }

//    @Test
    public void testEd448Vector5()
    {
        checkEd448Vector(
            ( "258cdd4ada32ed9c9ff54e63756ae582"
            + "fb8fab2ac721f2c8e676a72768513d93"
            + "9f63dddb55609133f29adf86ec9929dc"
            + "cb52c1c5fd2ff7e21b"),
            ( "3ba16da0c6f2cc1f30187740756f5e79"
            + "8d6bc5fc015d7c63cc9510ee3fd44adc"
            + "24d8e968b6e46e6f94d19b945361726b"
            + "d75e149ef09817f580"),
            "64a65f3cdedcdd66811e2915",
            "",
            ( "7eeeab7c4e50fb799b418ee5e3197ff6"
            + "bf15d43a14c34389b59dd1a7b1b85b4a"
            + "e90438aca634bea45e3a2695f1270f07"
            + "fdcdf7c62b8efeaf00b45c2c96ba457e"
            + "b1a8bf075a3db28e5c24f6b923ed4ad7"
            + "47c3c9e03c7079efb87cb110d3a99861"
            + "e72003cbae6d6b8b827e4e6c143064ff"
            + "3c00"),
            "Ed448 Vector #5");
    }

//    @Test
    public void testEd448Vector6()
    {
        checkEd448Vector(
            ( "7ef4e84544236752fbb56b8f31a23a10"
            + "e42814f5f55ca037cdcc11c64c9a3b29"
            + "49c1bb60700314611732a6c2fea98eeb"
            + "c0266a11a93970100e"),
            ( "b3da079b0aa493a5772029f0467baebe"
            + "e5a8112d9d3a22532361da294f7bb381"
            + "5c5dc59e176b4d9f381ca0938e13c6c0"
            + "7b174be65dfa578e80"),
            "64a65f3cdedcdd66811e2915e7",
            "",
            ( "6a12066f55331b6c22acd5d5bfc5d712"
            + "28fbda80ae8dec26bdd306743c5027cb"
            + "4890810c162c027468675ecf645a8317"
            + "6c0d7323a2ccde2d80efe5a1268e8aca"
            + "1d6fbc194d3f77c44986eb4ab4177919"
            + "ad8bec33eb47bbb5fc6e28196fd1caf5"
            + "6b4e7e0ba5519234d047155ac727a105"
            + "3100"),
            "Ed448 Vector #6");
    }

//    @Test
    public void testEd448Vector64()
    {
        String m =
            "bd0f6a3747cd561bdddf4640a332461a" +
            "4a30a12a434cd0bf40d766d9c6d458e5" +
            "512204a30c17d1f50b5079631f64eb31" +
            "12182da3005835461113718d1a5ef944";

        checkEd448Vector(
            ( "d65df341ad13e008567688baedda8e9d"
            + "cdc17dc024974ea5b4227b6530e339bf"
            + "f21f99e68ca6968f3cca6dfe0fb9f4fa"
            + "b4fa135d5542ea3f01"),
            ( "df9705f58edbab802c7f8363cfe5560a"
            + "b1c6132c20a9f1dd163483a26f8ac53a"
            + "39d6808bf4a1dfbd261b099bb03b3fb5"
            + "0906cb28bd8a081f00"),
            m,
            "",
            ( "554bc2480860b49eab8532d2a533b7d5"
            + "78ef473eeb58c98bb2d0e1ce488a98b1"
            + "8dfde9b9b90775e67f47d4a1c3482058"
            + "efc9f40d2ca033a0801b63d45b3b722e"
            + "f552bad3b4ccb667da350192b61c508c"
            + "f7b6b5adadc2c8d9a446ef003fb05cba"
            + "5f30e88e36ec2703b349ca229c267083"
            + "3900"),
            "Ed448 Vector #64");
    }

//    @Test
    public void testEd448Vector256()
    {
        String m =
            "15777532b0bdd0d1389f636c5f6b9ba7" +
            "34c90af572877e2d272dd078aa1e567c" +
            "fa80e12928bb542330e8409f31745041" +
            "07ecd5efac61ae7504dabe2a602ede89" +
            "e5cca6257a7c77e27a702b3ae39fc769" +
            "fc54f2395ae6a1178cab4738e543072f" +
            "c1c177fe71e92e25bf03e4ecb72f47b6" +
            "4d0465aaea4c7fad372536c8ba516a60" +
            "39c3c2a39f0e4d832be432dfa9a706a6" +
            "e5c7e19f397964ca4258002f7c0541b5" +
            "90316dbc5622b6b2a6fe7a4abffd9610" +
            "5eca76ea7b98816af0748c10df048ce0" +
            "12d901015a51f189f3888145c03650aa" +
            "23ce894c3bd889e030d565071c59f409" +
            "a9981b51878fd6fc110624dcbcde0bf7" +
            "a69ccce38fabdf86f3bef6044819de11";

        checkEd448Vector(
            ( "2ec5fe3c17045abdb136a5e6a913e32a"
            + "b75ae68b53d2fc149b77e504132d3756"
            + "9b7e766ba74a19bd6162343a21c8590a"
            + "a9cebca9014c636df5"),
            ( "79756f014dcfe2079f5dd9e718be4171"
            + "e2ef2486a08f25186f6bff43a9936b9b"
            + "fe12402b08ae65798a3d81e22e9ec80e"
            + "7690862ef3d4ed3a00"),
            m,
            "",
            ( "c650ddbb0601c19ca11439e1640dd931"
            + "f43c518ea5bea70d3dcde5f4191fe53f"
            + "00cf966546b72bcc7d58be2b9badef28"
            + "743954e3a44a23f880e8d4f1cfce2d7a"
            + "61452d26da05896f0a50da66a239a8a1"
            + "88b6d825b3305ad77b73fbac0836ecc6"
            + "0987fd08527c1a8e80d5823e65cafe2a"
            + "3d00"),
            "Ed448 Vector #256");
    }
    
//    @Test
    public void testEd448Vector1023()
    {
        String m =
            "6ddf802e1aae4986935f7f981ba3f035" +
            "1d6273c0a0c22c9c0e8339168e675412" +
            "a3debfaf435ed651558007db4384b650" +
            "fcc07e3b586a27a4f7a00ac8a6fec2cd" +
            "86ae4bf1570c41e6a40c931db27b2faa" +
            "15a8cedd52cff7362c4e6e23daec0fbc" +
            "3a79b6806e316efcc7b68119bf46bc76" +
            "a26067a53f296dafdbdc11c77f7777e9" +
            "72660cf4b6a9b369a6665f02e0cc9b6e" +
            "dfad136b4fabe723d2813db3136cfde9" +
            "b6d044322fee2947952e031b73ab5c60" +
            "3349b307bdc27bc6cb8b8bbd7bd32321" +
            "9b8033a581b59eadebb09b3c4f3d2277" +
            "d4f0343624acc817804728b25ab79717" +
            "2b4c5c21a22f9c7839d64300232eb66e" +
            "53f31c723fa37fe387c7d3e50bdf9813" +
            "a30e5bb12cf4cd930c40cfb4e1fc6225" +
            "92a49588794494d56d24ea4b40c89fc0" +
            "596cc9ebb961c8cb10adde976a5d602b" +
            "1c3f85b9b9a001ed3c6a4d3b1437f520" +
            "96cd1956d042a597d561a596ecd3d173" +
            "5a8d570ea0ec27225a2c4aaff26306d1" +
            "526c1af3ca6d9cf5a2c98f47e1c46db9" +
            "a33234cfd4d81f2c98538a09ebe76998" +
            "d0d8fd25997c7d255c6d66ece6fa56f1" +
            "1144950f027795e653008f4bd7ca2dee" +
            "85d8e90f3dc315130ce2a00375a318c7" +
            "c3d97be2c8ce5b6db41a6254ff264fa6" +
            "155baee3b0773c0f497c573f19bb4f42" +
            "40281f0b1f4f7be857a4e59d416c06b4" +
            "c50fa09e1810ddc6b1467baeac5a3668" +
            "d11b6ecaa901440016f389f80acc4db9" +
            "77025e7f5924388c7e340a732e554440" +
            "e76570f8dd71b7d640b3450d1fd5f041" +
            "0a18f9a3494f707c717b79b4bf75c984" +
            "00b096b21653b5d217cf3565c9597456" +
            "f70703497a078763829bc01bb1cbc8fa" +
            "04eadc9a6e3f6699587a9e75c94e5bab" +
            "0036e0b2e711392cff0047d0d6b05bd2" +
            "a588bc109718954259f1d86678a579a3" +
            "120f19cfb2963f177aeb70f2d4844826" +
            "262e51b80271272068ef5b3856fa8535" +
            "aa2a88b2d41f2a0e2fda7624c2850272" +
            "ac4a2f561f8f2f7a318bfd5caf969614" +
            "9e4ac824ad3460538fdc25421beec2cc" +
            "6818162d06bbed0c40a387192349db67" +
            "a118bada6cd5ab0140ee273204f628aa" +
            "d1c135f770279a651e24d8c14d75a605" +
            "9d76b96a6fd857def5e0b354b27ab937" +
            "a5815d16b5fae407ff18222c6d1ed263" +
            "be68c95f32d908bd895cd76207ae7264" +
            "87567f9a67dad79abec316f683b17f2d" +
            "02bf07e0ac8b5bc6162cf94697b3c27c" +
            "d1fea49b27f23ba2901871962506520c" +
            "392da8b6ad0d99f7013fbc06c2c17a56" +
            "9500c8a7696481c1cd33e9b14e40b82e" +
            "79a5f5db82571ba97bae3ad3e0479515" +
            "bb0e2b0f3bfcd1fd33034efc6245eddd" +
            "7ee2086ddae2600d8ca73e214e8c2b0b" +
            "db2b047c6a464a562ed77b73d2d841c4" +
            "b34973551257713b753632efba348169" +
            "abc90a68f42611a40126d7cb21b58695" +
            "568186f7e569d2ff0f9e745d0487dd2e" +
            "b997cafc5abf9dd102e62ff66cba87";

        checkEd448Vector(
            ( "872d093780f5d3730df7c212664b37b8"
            + "a0f24f56810daa8382cd4fa3f77634ec"
            + "44dc54f1c2ed9bea86fafb7632d8be19"
            + "9ea165f5ad55dd9ce8"),
            ( "a81b2e8a70a5ac94ffdbcc9badfc3feb"
            + "0801f258578bb114ad44ece1ec0e799d"
            + "a08effb81c5d685c0c56f64eecaef8cd"
            + "f11cc38737838cf400"),
            m,
            "",
            ( "e301345a41a39a4d72fff8df69c98075"
            + "a0cc082b802fc9b2b6bc503f926b65bd"
            + "df7f4c8f1cb49f6396afc8a70abe6d8a"
            + "ef0db478d4c6b2970076c6a0484fe76d"
            + "76b3a97625d79f1ce240e7c576750d29"
            + "5528286f719b413de9ada3e8eb78ed57"
            + "3603ce30d8bb761785dc30dbc320869e"
            + "1a00"),
            "Ed448 Vector #1023");
    }

//    @Test
    public void testEd448phVector1()
    {
        checkEd448phVector(
            ( "833fe62409237b9d62ec77587520911e"
            + "9a759cec1d19755b7da901b96dca3d42"
            + "ef7822e0d5104127dc05d6dbefde69e3"
            + "ab2cec7c867c6e2c49"),
            ( "259b71c19f83ef77a7abd26524cbdb31"
            + "61b590a48f7d17de3ee0ba9c52beb743"
            + "c09428a131d6b1b57303d90d8132c276"
            + "d5ed3d5d01c0f53880"),
            "616263",
            "",
            ( "822f6901f7480f3d5f562c592994d969"
            + "3602875614483256505600bbc281ae38"
            + "1f54d6bce2ea911574932f52a4e6cadd"
            + "78769375ec3ffd1b801a0d9b3f4030cd"
            + "433964b6457ea39476511214f97469b5"
            + "7dd32dbc560a9a94d00bff07620464a3"
            + "ad203df7dc7ce360c3cd3696d9d9fab9"
            + "0f00"),
            "Ed448ph Vector #1");
    }

//    @Test
    public void testEd448phVector2()
    {
        checkEd448phVector(
            ( "833fe62409237b9d62ec77587520911e"
            + "9a759cec1d19755b7da901b96dca3d42"
            + "ef7822e0d5104127dc05d6dbefde69e3"
            + "ab2cec7c867c6e2c49"),
            ( "259b71c19f83ef77a7abd26524cbdb31"
            + "61b590a48f7d17de3ee0ba9c52beb743"
            + "c09428a131d6b1b57303d90d8132c276"
            + "d5ed3d5d01c0f53880"),
            "616263",
            "666f6f",
            ( "c32299d46ec8ff02b54540982814dce9"
            + "a05812f81962b649d528095916a2aa48"
            + "1065b1580423ef927ecf0af5888f90da"
            + "0f6a9a85ad5dc3f280d91224ba9911a3"
            + "653d00e484e2ce232521481c8658df30"
            + "4bb7745a73514cdb9bf3e15784ab7128"
            + "4f8d0704a608c54a6b62d97beb511d13"
            + "2100"),
            "Ed448ph Vector #2");
    }

    private static void checkEd448Vector(String sSK, String sPK, String sM, String sCTX, String sSig, String text)
    {
        byte[] sk = Hex.decode(sSK);
        byte[] pk = Hex.decode(sPK);

        byte[] pkGen = new byte[Ed448.PUBLIC_KEY_SIZE];
        Ed448.generatePublicKey(sk, 0, pkGen, 0);
        assertTrue(text, Arrays.areEqual(pk, pkGen));

        byte[] m = Hex.decode(sM);
        byte[] ctx = Hex.decode(sCTX);
        byte[] sig = Hex.decode(sSig);

        byte[] badsig = Arrays.clone(sig);
        badsig[Ed448.SIGNATURE_SIZE - 1] ^= 0x80;

        byte[] sigGen = new byte[Ed448.SIGNATURE_SIZE];
        Ed448.sign(sk, 0, ctx, m, 0, m.length, sigGen, 0);
        assertTrue(text, Arrays.areEqual(sig, sigGen));

        Ed448.sign(sk, 0, pk, 0, ctx, m, 0, m.length, sigGen, 0);
        assertTrue(text, Arrays.areEqual(sig, sigGen));

        boolean shouldVerify = Ed448.verify(sig, 0, pk, 0, ctx, m, 0, m.length);
        assertTrue(text, shouldVerify);

        boolean shouldNotVerify = Ed448.verify(badsig, 0, pk, 0, ctx, m, 0, m.length);
        assertFalse(text, shouldNotVerify);
    }

    private static void checkEd448phVector(String sSK, String sPK, String sM, String sCTX, String sSig, String text)
    {
        byte[] sk = Hex.decode(sSK);
        byte[] pk = Hex.decode(sPK);

        byte[] pkGen = new byte[Ed448.PUBLIC_KEY_SIZE];
        Ed448.generatePublicKey(sk, 0, pkGen, 0);
        assertTrue(text, Arrays.areEqual(pk, pkGen));

        byte[] m = Hex.decode(sM);
        byte[] ctx = Hex.decode(sCTX);
        byte[] sig = Hex.decode(sSig);

        byte[] badsig = Arrays.clone(sig);
        badsig[Ed448.SIGNATURE_SIZE - 1] ^= 0x80;

        byte[] sigGen = new byte[Ed448.SIGNATURE_SIZE];

        {
            Xof prehash = Ed448.createPrehash();
            prehash.update(m, 0, m.length);

            byte[] ph = new byte[Ed448.PREHASH_SIZE];
            prehash.doFinal(ph, 0, ph.length);

            Ed448.signPrehash(sk, 0, ctx, ph, 0, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));

            Ed448.signPrehash(sk, 0, pk, 0, ctx, ph, 0, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));

            boolean shouldVerify = Ed448.verifyPrehash(sig, 0, pk, 0, ctx, ph, 0);
            assertTrue(text, shouldVerify);

            boolean shouldNotVerify = Ed448.verifyPrehash(badsig, 0, pk, 0, ctx, ph, 0);
            assertFalse(text, shouldNotVerify);
        }

        {
            Xof ph = Ed448.createPrehash();
            ph.update(m, 0, m.length);

            Ed448.signPrehash(sk, 0, ctx, ph, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));
        }

        {
            Xof ph = Ed448.createPrehash();
            ph.update(m, 0, m.length);

            Ed448.signPrehash(sk, 0, pk, 0, ctx, ph, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));
        }

        {
            Xof ph = Ed448.createPrehash();
            ph.update(m, 0, m.length);

            boolean shouldVerify = Ed448.verifyPrehash(sig, 0, pk, 0, ctx, ph);
            assertTrue(text, shouldVerify);
        }

        {
            Xof ph = Ed448.createPrehash();
            ph.update(m, 0, m.length);

            boolean shouldNotVerify = Ed448.verifyPrehash(badsig, 0, pk, 0, ctx, ph);
            assertFalse(text, shouldNotVerify);
        }
    }
}
