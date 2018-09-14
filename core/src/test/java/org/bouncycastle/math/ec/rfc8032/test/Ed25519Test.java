package org.bouncycastle.math.ec.rfc8032.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Ed25519Test
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

//    @BeforeClass
//    public static void init()
    public void setUp()
    {
        Ed25519.precompute();
    }

//    @Test
    public void testEd25519Consistency()
    {
        byte[] sk = new byte[Ed25519.SECRET_KEY_SIZE];
        byte[] pk = new byte[Ed25519.PUBLIC_KEY_SIZE];
        byte[] m = new byte[255];
        byte[] sig1 = new byte[Ed25519.SIGNATURE_SIZE];
        byte[] sig2 = new byte[Ed25519.SIGNATURE_SIZE];

        RANDOM.nextBytes(m);

        for (int i = 0; i < 10; ++i)
        {
            RANDOM.nextBytes(sk);
            Ed25519.generatePublicKey(sk, 0, pk, 0);

            int mLen = RANDOM.nextInt() & 255;

            Ed25519.sign(sk, 0, m, 0, mLen, sig1, 0);
            Ed25519.sign(sk, 0, pk, 0, m, 0, mLen, sig2, 0);

            assertTrue("Ed25519 consistent signatures #" + i, Arrays.areEqual(sig1, sig2));

            boolean shouldVerify = Ed25519.verify(sig1, 0, pk, 0, m, 0, mLen);

            assertTrue("Ed25519 consistent sign/verify #" + i, shouldVerify);

            sig1[Ed25519.PUBLIC_KEY_SIZE - 1] ^= 0x80;
            boolean shouldNotVerify = Ed25519.verify(sig1, 0, pk, 0, m, 0, mLen);

            assertFalse("Ed25519 consistent verification failure #" + i, shouldNotVerify);
        }
    }
    
//    @Test
    public void testEd25519ctxConsistency()
    {
        byte[] sk = new byte[Ed25519.SECRET_KEY_SIZE];
        byte[] pk = new byte[Ed25519.PUBLIC_KEY_SIZE];
        byte[] ctx = new byte[RANDOM.nextInt() & 7];
        byte[] m = new byte[255];
        byte[] sig1 = new byte[Ed25519.SIGNATURE_SIZE];
        byte[] sig2 = new byte[Ed25519.SIGNATURE_SIZE];

        RANDOM.nextBytes(ctx);
        RANDOM.nextBytes(m);

        for (int i = 0; i < 10; ++i)
        {
            RANDOM.nextBytes(sk);
            Ed25519.generatePublicKey(sk, 0, pk, 0);

            int mLen = RANDOM.nextInt() & 255;

            Ed25519.sign(sk, 0, ctx, m, 0, mLen, sig1, 0);
            Ed25519.sign(sk, 0, pk, 0, ctx, m, 0, mLen, sig2, 0);

            assertTrue("Ed25519ctx consistent signatures #" + i, Arrays.areEqual(sig1, sig2));

            boolean shouldVerify = Ed25519.verify(sig1, 0, pk, 0, ctx, m, 0, mLen);

            assertTrue("Ed25519ctx consistent sign/verify #" + i, shouldVerify);

            sig1[Ed25519.PUBLIC_KEY_SIZE - 1] ^= 0x80;
            boolean shouldNotVerify = Ed25519.verify(sig1, 0, pk, 0, ctx, m, 0, mLen);

            assertFalse("Ed25519ctx consistent verification failure #" + i, shouldNotVerify);
        }
    }
    
//    @Test
    public void testEd25519phConsistency()
    {
        byte[] sk = new byte[Ed25519.SECRET_KEY_SIZE];
        byte[] pk = new byte[Ed25519.PUBLIC_KEY_SIZE];
        byte[] ctx = new byte[RANDOM.nextInt() & 7];
        byte[] m = new byte[255];
        byte[] ph = new byte[Ed25519.PREHASH_SIZE];
        byte[] sig1 = new byte[Ed25519.SIGNATURE_SIZE];
        byte[] sig2 = new byte[Ed25519.SIGNATURE_SIZE];

        RANDOM.nextBytes(ctx);
        RANDOM.nextBytes(m);

        for (int i = 0; i < 10; ++i)
        {
            RANDOM.nextBytes(sk);
            Ed25519.generatePublicKey(sk, 0, pk, 0);

            int mLen = RANDOM.nextInt() & 255;

            Digest prehash = Ed25519.createPrehash();
            prehash.update(m, 0, mLen);
            prehash.doFinal(ph, 0);

            Ed25519.signPrehash(sk, 0, ctx, ph, 0, sig1, 0);
            Ed25519.signPrehash(sk, 0, pk, 0, ctx, ph, 0, sig2, 0);

            assertTrue("Ed25519ph consistent signatures #" + i, Arrays.areEqual(sig1, sig2));

            boolean shouldVerify = Ed25519.verifyPrehash(sig1, 0, pk, 0, ctx, ph, 0);

            assertTrue("Ed25519ph consistent sign/verify #" + i, shouldVerify);

            sig1[Ed25519.PUBLIC_KEY_SIZE - 1] ^= 0x80;
            boolean shouldNotVerify = Ed25519.verifyPrehash(sig1, 0, pk, 0, ctx, ph, 0);

            assertFalse("Ed25519ph consistent verification failure #" + i, shouldNotVerify);
        }
    }

//    @Test
    public void testEd25519Vector1()
    {
        checkEd25519Vector(
            ( "9d61b19deffd5a60ba844af492ec2cc4"
            + "4449c5697b326919703bac031cae7f60"),
            ( "d75a980182b10ab7d54bfed3c964073a"
            + "0ee172f3daa62325af021a68f707511a"),
            "",
            ( "e5564300c360ac729086e2cc806e828a"
            + "84877f1eb8e5d974d873e06522490155"
            + "5fb8821590a33bacc61e39701cf9b46b"
            + "d25bf5f0595bbe24655141438e7a100b"),
            "Ed25519 Vector #1");
    }

//    @Test
    public void testEd25519Vector2()
    {
        checkEd25519Vector(
            ( "4ccd089b28ff96da9db6c346ec114e0f"
            + "5b8a319f35aba624da8cf6ed4fb8a6fb"),
            ( "3d4017c3e843895a92b70aa74d1b7ebc"
            + "9c982ccf2ec4968cc0cd55f12af4660c"),
            "72",
            ( "92a009a9f0d4cab8720e820b5f642540"
            + "a2b27b5416503f8fb3762223ebdb69da"
            + "085ac1e43e15996e458f3613d0f11d8c"
            + "387b2eaeb4302aeeb00d291612bb0c00"),
            "Ed25519 Vector #2");
    }

//    @Test
    public void testEd25519Vector3()
    {
        checkEd25519Vector(
            ( "c5aa8df43f9f837bedb7442f31dcb7b1"
            + "66d38535076f094b85ce3a2e0b4458f7"),
            ( "fc51cd8e6218a1a38da47ed00230f058"
            + "0816ed13ba3303ac5deb911548908025"),
            "af82",
            ( "6291d657deec24024827e69c3abe01a3"
            + "0ce548a284743a445e3680d7db5ac3ac"
            + "18ff9b538d16f290ae67f760984dc659"
            + "4a7c15e9716ed28dc027beceea1ec40a"),
            "Ed25519 Vector #3");
    }

//    @Test
    public void testEd25519Vector1023()
    {
        String m =
            "08b8b2b733424243760fe426a4b54908" +
            "632110a66c2f6591eabd3345e3e4eb98" +
            "fa6e264bf09efe12ee50f8f54e9f77b1" +
            "e355f6c50544e23fb1433ddf73be84d8" +
            "79de7c0046dc4996d9e773f4bc9efe57" +
            "38829adb26c81b37c93a1b270b20329d" +
            "658675fc6ea534e0810a4432826bf58c" +
            "941efb65d57a338bbd2e26640f89ffbc" +
            "1a858efcb8550ee3a5e1998bd177e93a" +
            "7363c344fe6b199ee5d02e82d522c4fe" +
            "ba15452f80288a821a579116ec6dad2b" +
            "3b310da903401aa62100ab5d1a36553e" +
            "06203b33890cc9b832f79ef80560ccb9" +
            "a39ce767967ed628c6ad573cb116dbef" +
            "efd75499da96bd68a8a97b928a8bbc10" +
            "3b6621fcde2beca1231d206be6cd9ec7" +
            "aff6f6c94fcd7204ed3455c68c83f4a4" +
            "1da4af2b74ef5c53f1d8ac70bdcb7ed1" +
            "85ce81bd84359d44254d95629e9855a9" +
            "4a7c1958d1f8ada5d0532ed8a5aa3fb2" +
            "d17ba70eb6248e594e1a2297acbbb39d" +
            "502f1a8c6eb6f1ce22b3de1a1f40cc24" +
            "554119a831a9aad6079cad88425de6bd" +
            "e1a9187ebb6092cf67bf2b13fd65f270" +
            "88d78b7e883c8759d2c4f5c65adb7553" +
            "878ad575f9fad878e80a0c9ba63bcbcc" +
            "2732e69485bbc9c90bfbd62481d9089b" +
            "eccf80cfe2df16a2cf65bd92dd597b07" +
            "07e0917af48bbb75fed413d238f5555a" +
            "7a569d80c3414a8d0859dc65a46128ba" +
            "b27af87a71314f318c782b23ebfe808b" +
            "82b0ce26401d2e22f04d83d1255dc51a" +
            "ddd3b75a2b1ae0784504df543af8969b" +
            "e3ea7082ff7fc9888c144da2af58429e" +
            "c96031dbcad3dad9af0dcbaaaf268cb8" +
            "fcffead94f3c7ca495e056a9b47acdb7" +
            "51fb73e666c6c655ade8297297d07ad1" +
            "ba5e43f1bca32301651339e22904cc8c" +
            "42f58c30c04aafdb038dda0847dd988d" +
            "cda6f3bfd15c4b4c4525004aa06eeff8" +
            "ca61783aacec57fb3d1f92b0fe2fd1a8" +
            "5f6724517b65e614ad6808d6f6ee34df" +
            "f7310fdc82aebfd904b01e1dc54b2927" +
            "094b2db68d6f903b68401adebf5a7e08" +
            "d78ff4ef5d63653a65040cf9bfd4aca7" +
            "984a74d37145986780fc0b16ac451649" +
            "de6188a7dbdf191f64b5fc5e2ab47b57" +
            "f7f7276cd419c17a3ca8e1b939ae49e4" +
            "88acba6b965610b5480109c8b17b80e1" +
            "b7b750dfc7598d5d5011fd2dcc5600a3" +
            "2ef5b52a1ecc820e308aa342721aac09" +
            "43bf6686b64b2579376504ccc493d97e" +
            "6aed3fb0f9cd71a43dd497f01f17c0e2" +
            "cb3797aa2a2f256656168e6c496afc5f" +
            "b93246f6b1116398a346f1a641f3b041" +
            "e989f7914f90cc2c7fff357876e506b5" +
            "0d334ba77c225bc307ba537152f3f161" +
            "0e4eafe595f6d9d90d11faa933a15ef1" +
            "369546868a7f3a45a96768d40fd9d034" +
            "12c091c6315cf4fde7cb68606937380d" +
            "b2eaaa707b4c4185c32eddcdd306705e" +
            "4dc1ffc872eeee475a64dfac86aba41c" +
            "0618983f8741c5ef68d3a101e8a3b8ca" +
            "c60c905c15fc910840b94c00a0b9d0";

        checkEd25519Vector(
            ( "f5e5767cf153319517630f226876b86c"
            + "8160cc583bc013744c6bf255f5cc0ee5"),
            ( "278117fc144c72340f67d0f2316e8386"
            + "ceffbf2b2428c9c51fef7c597f1d426e"),
            m,
            ( "0aab4c900501b3e24d7cdf4663326a3a"
            + "87df5e4843b2cbdb67cbf6e460fec350"
            + "aa5371b1508f9f4528ecea23c436d94b"
            + "5e8fcd4f681e30a6ac00a9704a188a03"),
            "Ed25519 Vector #1023");
    }

//    @Test
    public void testEd25519VectorSHAabc()
    {
        checkEd25519Vector(
            ( "833fe62409237b9d62ec77587520911e"
            + "9a759cec1d19755b7da901b96dca3d42"),
            ( "ec172b93ad5e563bf4932c70e1245034"
            + "c35467ef2efd4d64ebf819683467e2bf"),
            ( "ddaf35a193617abacc417349ae204131"
            + "12e6fa4e89a97ea20a9eeee64b55d39a"
            + "2192992a274fc1a836ba3c23a3feebbd"
            + "454d4423643ce80e2a9ac94fa54ca49f"),
            ( "dc2a4459e7369633a52b1bf277839a00"
            + "201009a3efbf3ecb69bea2186c26b589"
            + "09351fc9ac90b3ecfdfbc7c66431e030"
            + "3dca179c138ac17ad9bef1177331a704"),
            "Ed25519 Vector SHA(abc)");
    }

//    @Test
    public void testEd25519ctxVector1()
    {
        checkEd25519ctxVector(
            ( "0305334e381af78f141cb666f6199f57"
            + "bc3495335a256a95bd2a55bf546663f6"),
            ( "dfc9425e4f968f7f0c29f0259cf5f9ae"
            + "d6851c2bb4ad8bfb860cfee0ab248292"),
            "f726936d19c800494e3fdaff20b276a8",
            "666f6f",
            ( "55a4cc2f70a54e04288c5f4cd1e45a7b"
            + "b520b36292911876cada7323198dd87a"
            + "8b36950b95130022907a7fb7c4e9b2d5"
            + "f6cca685a587b4b21f4b888e4e7edb0d"),
            "Ed25519ctx Vector #1");
    }

//    @Test
    public void testEd25519ctxVector2()
    {
        checkEd25519ctxVector(
            ( "0305334e381af78f141cb666f6199f57"
            + "bc3495335a256a95bd2a55bf546663f6"),
            ( "dfc9425e4f968f7f0c29f0259cf5f9ae"
            + "d6851c2bb4ad8bfb860cfee0ab248292"),
            "f726936d19c800494e3fdaff20b276a8",
            "626172",
            ( "fc60d5872fc46b3aa69f8b5b4351d580"
            + "8f92bcc044606db097abab6dbcb1aee3"
            + "216c48e8b3b66431b5b186d1d28f8ee1"
            + "5a5ca2df6668346291c2043d4eb3e90d"),
            "Ed25519ctx Vector #2");
    }

//    @Test
    public void testEd25519ctxVector3()
    {
        checkEd25519ctxVector(
            ( "0305334e381af78f141cb666f6199f57"
            + "bc3495335a256a95bd2a55bf546663f6"),
            ( "dfc9425e4f968f7f0c29f0259cf5f9ae"
            + "d6851c2bb4ad8bfb860cfee0ab248292"),
            "508e9e6882b979fea900f62adceaca35",
            "666f6f",
            ( "8b70c1cc8310e1de20ac53ce28ae6e72"
            + "07f33c3295e03bb5c0732a1d20dc6490"
            + "8922a8b052cf99b7c4fe107a5abb5b2c"
            + "4085ae75890d02df26269d8945f84b0b"),
            "Ed25519ctx Vector #3");
    }

//    @Test
    public void testEd25519ctxVector4()
    {
        checkEd25519ctxVector(
            ( "ab9c2853ce297ddab85c993b3ae14bca"
            + "d39b2c682beabc27d6d4eb20711d6560"),
            ( "0f1d1274943b91415889152e893d80e9"
            + "3275a1fc0b65fd71b4b0dda10ad7d772"),
            "f726936d19c800494e3fdaff20b276a8",
            "666f6f",
            ( "21655b5f1aa965996b3f97b3c849eafb"
            + "a922a0a62992f73b3d1b73106a84ad85"
            + "e9b86a7b6005ea868337ff2d20a7f5fb"
            + "d4cd10b0be49a68da2b2e0dc0ad8960f"),
            "Ed25519ctx Vector #4");
    }

//    @Test
    public void testEd25519phVector1()
    {
        checkEd25519phVector(
            ( "833fe62409237b9d62ec77587520911e"
            + "9a759cec1d19755b7da901b96dca3d42"),
            ( "ec172b93ad5e563bf4932c70e1245034"
            + "c35467ef2efd4d64ebf819683467e2bf"),
            "616263",
            "",
            ( "98a70222f0b8121aa9d30f813d683f80"
            + "9e462b469c7ff87639499bb94e6dae41"
            + "31f85042463c2a355a2003d062adf5aa"
            + "a10b8c61e636062aaad11c2a26083406"),
            "Ed25519ph Vector #1");
    }

    private static void checkEd25519Vector(String sSK, String sPK, String sM, String sSig, String text)
    {
        byte[] sk = Hex.decode(sSK);
        byte[] pk = Hex.decode(sPK);

        byte[] pkGen = new byte[Ed25519.PUBLIC_KEY_SIZE];
        Ed25519.generatePublicKey(sk, 0, pkGen, 0);
        assertTrue(text, Arrays.areEqual(pk, pkGen));

        byte[] m = Hex.decode(sM);
        byte[] sig = Hex.decode(sSig);

        byte[] badsig = Arrays.clone(sig);
        badsig[Ed25519.SIGNATURE_SIZE - 1] ^= 0x80;

        byte[] sigGen = new byte[Ed25519.SIGNATURE_SIZE];
        Ed25519.sign(sk, 0, m, 0, m.length, sigGen, 0);
        assertTrue(text, Arrays.areEqual(sig, sigGen));

        Ed25519.sign(sk, 0, pk, 0, m, 0, m.length, sigGen, 0);
        assertTrue(text, Arrays.areEqual(sig, sigGen));

        boolean shouldVerify = Ed25519.verify(sig, 0, pk, 0, m, 0, m.length);
        assertTrue(text, shouldVerify);

        boolean shouldNotVerify = Ed25519.verify(badsig, 0, pk, 0, m, 0, m.length);
        assertFalse(text, shouldNotVerify);
    }

    private static void checkEd25519ctxVector(String sSK, String sPK, String sM, String sCTX, String sSig, String text)
    {
        byte[] sk = Hex.decode(sSK);
        byte[] pk = Hex.decode(sPK);

        byte[] pkGen = new byte[Ed25519.PUBLIC_KEY_SIZE];
        Ed25519.generatePublicKey(sk, 0, pkGen, 0);
        assertTrue(text, Arrays.areEqual(pk, pkGen));

        byte[] m = Hex.decode(sM);
        byte[] ctx = Hex.decode(sCTX);
        byte[] sig = Hex.decode(sSig);

        byte[] badsig = Arrays.clone(sig);
        badsig[Ed25519.SIGNATURE_SIZE - 1] ^= 0x80;

        byte[] sigGen = new byte[Ed25519.SIGNATURE_SIZE];
        Ed25519.sign(sk, 0, ctx, m, 0, m.length, sigGen, 0);
        assertTrue(text, Arrays.areEqual(sig, sigGen));

        Ed25519.sign(sk, 0, pk, 0, ctx, m, 0, m.length, sigGen, 0);
        assertTrue(text, Arrays.areEqual(sig, sigGen));

        boolean shouldVerify = Ed25519.verify(sig, 0, pk, 0, ctx, m, 0, m.length);
        assertTrue(text, shouldVerify);

        boolean shouldNotVerify = Ed25519.verify(badsig, 0, pk, 0, ctx, m, 0, m.length);
        assertFalse(text, shouldNotVerify);
    }

    private static void checkEd25519phVector(String sSK, String sPK, String sM, String sCTX, String sSig, String text)
    {
        byte[] sk = Hex.decode(sSK);
        byte[] pk = Hex.decode(sPK);

        byte[] pkGen = new byte[Ed25519.PUBLIC_KEY_SIZE];
        Ed25519.generatePublicKey(sk, 0, pkGen, 0);
        assertTrue(text, Arrays.areEqual(pk, pkGen));

        byte[] m = Hex.decode(sM);
        byte[] ctx = Hex.decode(sCTX);
        byte[] sig = Hex.decode(sSig);

        byte[] badsig = Arrays.clone(sig);
        badsig[Ed25519.SIGNATURE_SIZE - 1] ^= 0x80;

        byte[] sigGen = new byte[Ed25519.SIGNATURE_SIZE];

        {
            Digest prehash = Ed25519.createPrehash();
            prehash.update(m, 0, m.length);

            byte[] ph = new byte[Ed25519.PREHASH_SIZE];
            prehash.doFinal(ph, 0);

            Ed25519.signPrehash(sk, 0, ctx, ph, 0, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));

            Ed25519.signPrehash(sk, 0, pk, 0, ctx, ph, 0, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));

            boolean shouldVerify = Ed25519.verifyPrehash(sig, 0, pk, 0, ctx, ph, 0);
            assertTrue(text, shouldVerify);

            boolean shouldNotVerify = Ed25519.verifyPrehash(badsig, 0, pk, 0, ctx, ph, 0);
            assertFalse(text, shouldNotVerify);
        }

        {
            Digest ph = Ed25519.createPrehash();
            ph.update(m, 0, m.length);

            Ed25519.signPrehash(sk, 0, ctx, ph, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));
        }

        {
            Digest ph = Ed25519.createPrehash();
            ph.update(m, 0, m.length);

            Ed25519.signPrehash(sk, 0, pk, 0, ctx, ph, sigGen, 0);
            assertTrue(text, Arrays.areEqual(sig, sigGen));
        }

        {
            Digest ph = Ed25519.createPrehash();
            ph.update(m, 0, m.length);

            boolean shouldVerify = Ed25519.verifyPrehash(sig, 0, pk, 0, ctx, ph);
            assertTrue(text, shouldVerify);
        }

        {
            Digest ph = Ed25519.createPrehash();
            ph.update(m, 0, m.length);

            boolean shouldNotVerify = Ed25519.verifyPrehash(badsig, 0, pk, 0, ctx, ph);
            assertFalse(text, shouldNotVerify);
        }
    }
}
