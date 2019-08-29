package org.bouncycastle.math.ec.rfc7748.test;

import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class X448Test
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

//    @BeforeClass
//    public static void init()
    public void setUp()
    {
        X448.precompute();
    }

//    @Test
    public void testConsistency()
    {
        byte[] u = new byte[X448.POINT_SIZE];   u[0] = 5;
        byte[] k = new byte[X448.SCALAR_SIZE];
        byte[] rF = new byte[X448.POINT_SIZE];
        byte[] rV = new byte[X448.POINT_SIZE];

        for (int i = 1; i <= 100; ++i)
        {
            RANDOM.nextBytes(k);
            X448.scalarMultBase(k, 0, rF, 0);
            X448.scalarMult(k, 0, u, 0, rV, 0);
            assertTrue("Consistency #" + i, Arrays.areEqual(rF, rV));
        }
    }

//    @Test
    public void testECDH()
    {
        byte[] kA = new byte[X448.SCALAR_SIZE];
        byte[] kB = new byte[X448.SCALAR_SIZE];
        byte[] qA = new byte[X448.POINT_SIZE];
        byte[] qB = new byte[X448.POINT_SIZE];
        byte[] sA = new byte[X448.POINT_SIZE];
        byte[] sB = new byte[X448.POINT_SIZE];

        for (int i = 1; i <= 100; ++i)
        {
            // Each party generates an ephemeral private key, ...
            RANDOM.nextBytes(kA);
            RANDOM.nextBytes(kB);

            // ... publishes their public key, ...
            X448.scalarMultBase(kA, 0, qA, 0);
            X448.scalarMultBase(kB, 0, qB, 0);

            // ... computes the shared secret, ...
            X448.scalarMult(kA, 0, qB, 0, sA, 0);
            X448.scalarMult(kB, 0, qA, 0, sB, 0);

            // ... which is the same for both parties.
            assertTrue("ECDH #" + i, Arrays.areEqual(sA, sB));
        }
    }

//    @Test
    public void testECDHVector1()
    {
        checkECDHVector(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
            "ECDH Vector #1");
    }

//    @Test
    public void testRegression()
    {
        checkX448Vector(
            "c05bd19c61d1c2c0e79414345cfb9c138eed88054fac8f74b2c4b5e1e817aaad629d159903bef40c10c85a8b90b8433c7f35248d72bea2d1",
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "856b8707b16e1b21dfc547fdb04c61a4aed9f9001f3f26404901e9ba30933cdd7ca9e2a0e57700588eb8576312ead8ee5791a8ecff32efaa",
            "Regression #1");

        checkX448Vector(
            "24ba9df56ef036b4bcde7b0138b7983ae0fe3d2fd4b9d13ef0b8b0998c8394364d7dcb25a3885e571374f91615275440db0645ee7c0a6feb",
            "0000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "f1ef9174222c422cb3a6194da91dbdab62b0688179e77f47019cc9eb7c38da86f6f51fc250e8a46dd4b3341cc5f71f1d8daf0b28e873d818",
            "Regression #2");

        checkX448Vector(
            "40670a1efa7072a65c279f9618263a9e266fe12d82ff53c29b99d5e265e1fc7c32345227d6699a6d6b5517cf33b43ab156ee20df4878798e",
            "0000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "f27f02b452f9a5e95f08092e7e4058ae560732a4ffd5e4c4cc497af9d8e0d77f3d94d07dea932f0a79fa63c852a1cf03b60ab5a5201748ef",
            "Regression #3");

        checkX448Vector(
            "8c37fb35eac1dbda6a3b5bf492c1f642c761be3adf0ab7617a66002576c45bba8202970bae6c5e05f645f5439ca2f42b89dacace1a5d0e82",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040",
            "60c468df97e2e4427f27420cc6bc9eebaa2bceb827eb55a187fc5c29555e72a663243f6af4095641d72caeacb369720ea18cadd6efdbece6",
            "Regression #4");

        checkX448Vector(
            "e8761598ba212a4e9724eaab2f3c225b0cc019595fa702ae0361bf3d348d9d6f7a04352424a5fd3026650f2a04574499daebc71f4c6d0fd9",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffbf",
            "2521c283651396fb03bf074e3ce6d08d7b393de5fa85e9ac633cef328ac54576f6005f34c795425c56db62e8ceddf807d68e37646afb1184",
            "Regression #5");

        checkX448Vector(
            "5410735bd95cd0640fc1e2e11a028803f1cb4344f4efee75ae0b9eb9db5627d6e2a4b6dbad4af3fee986cce934bed60a0e8698204638b5a9",
            "fffffffffffffffefffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "8951b4fc362ccd60cb560fde65fa126158a9727a3d577c507566fa5b4a79c2ac6bfd6c69defeb9eb29830cc4aaf6427f2ae66b2cd320159d",
            "Regression #6");

        checkX448Vector(
            "08353724fbc03927b17359a88c121276ad697991ee89868e48890e95d1b03e603bcb51fdf6f296f1f1d10f5df10e00b8a25c9809f9aa1a94",
            "0000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "30b1d98154768a2a2af568e2fa3577a042a5c7e5f9ac91b100655ea332b42db568034b15fdf75c693d8c2d0c2de54fb9d6d17efa316aa543",
            "Regression #7");

        checkX448Vector(
            "98c6f36e1cb74528763f3aa11196ef9449c67be360e25e40ab06f1e39b742615a7dde3b29415ed827c68f07d4a47a4d9595c40c7fccb92a3",
            "ffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "c3c7aec97786a43b79f8a053cf185363112f04411a8ef3d3283f61eeac59a1f2918e10f54937932f5ac1e3b72fdbea57f34274598b17d768",
            "Regression #8");

        checkX448Vector(
            "4804afd055ec05f335b7e3eebbde2a6de010ce7495e6c0d02173fa8c48bb495375b7d149c67b92d2885acb8d8bbb51a317453788671efa9f",
            "fffffffffffffffffffffffffffffffffefffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "d6a2724dc9ca1579d94a8cc8815a3ed392b9e10b39f57c747f7b2d84f54969062c8b86929a1a12f466d3ef9598f1904773a4ee938f0f5df3",
            "Regression #9");

        checkX448Vector(
            "bc7bce37434c0a1d05eff428034f75ed7454ede6b2a6e34ed4fcedc050349c866c40a27c27898afec41b3b477f0df5c5356e57d7562cdda5",
            "fffffefffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "963ff8e5ea534178e1922cc06c638367c2c4690aba7e4aaab8342210b9035727062762631f79e709d2baf0646f0d9a37df02d531791bc940",
            "Regression #10");

        checkX448Vector(
            "c05bd19c61d1c2c0e79414345cfb9c138eed88054fac8f74b2c4b5e1e817aaad629d159903bef40c10c85a8b90b8433c7f35248d72bea2d1",
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "856b8707b16e1b21dfc547fdb04c61a4aed9f9001f3f26404901e9ba30933cdd7ca9e2a0e57700588eb8576312ead8ee5791a8ecff32efaa",
            "Regression #11");

        checkX448Vector(
            "742b8c0b0ab0104a9ef9634c0aad023f35e41fb953717121ce4c2aebc1a128e7c0431cd1347a6241685f7174a8512d417ebaaa46ee780a8a",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "d92b02d7bb9952f4ca826b2b51f1a3d4de1fd4459f0d019853f3a960d54f3354d8e40fb28d1be65637bb7dba0571ff83797b7106c7497459",
            "Regression #12");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "Regression #13");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "9fe4a6f810098a4faf078cdc888988bae53234d9dac49e0c39186789d8ce4b35530bfbe4e8a5520b84028f3c6d2234f6bf2e07375e927e48",
            "Regression #14");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "c51d92750f8491e669eabb9c30fc8d4d16bfd6a214fd8f1a884e6130f9d5121aef3ac1cb7eac7c128473d38fbdedc584c477575de332ad93",
            "Regression #15");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "ffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "a1840a0bd418dab5529353787f71042303ed65df615340845ba39e48c82b70022c3e10c3afbaec9f3c1559d5164a4c123672f308f55f5cb3",
            "Regression #16");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000",
            "c9c399826f4fdf4898f8abbccb7401541ca6084cf53e6f809d87d1fb614e867d6ff956058275944351917fe41675bce2f642f8aadf01a7bb",
            "Regression #17");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000",
            "b4209095fd21eb70a3e60b380191c43a85ca96a03f079d4493b215567af08514560fff03f9f6280bc0b357919c533686d0c02019f4866b2e",
            "Regression #18");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
            "8c46b8a63d37ea4ff2603b6ee0b72fd37f5d4be4c9076b0841d07540dc1f28c2d15ce01c5bccb8ba284b4f077b9d0f554d49bb1f5f9ebf7e",
            "Regression #19");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            "8c46b8a63d37ea4ff2603b6ee0b72fd37f5d4be4c9076b0841d07540dc1f28c2d15ce01c5bccb8ba284b4f077b9d0f554d49bb1f5f9ebf7e",
            "Regression #20");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040",
            "bbcb71fe09d61a0d78a310d6a8f97f15457e9c3e020a4b70f9fcdee93a897505494fbb1437a0eacaf79f526fce66c8a24ee4a0e75891af4c",
            "Regression #21");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "b21e0e2701e415d4ec3a46fecf167ffec7bb335cf96e902f1f8a63e90ef956381014149e86f3a6838a40a33ea6947b9955899cb622812ca1",
            "Regression #22");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
            "ad4be2907f519cc9e87006bb1b1fbe71475db52680fe7f27707b455e70c74a0e2600c6ff6de69365be551fcde234f9a25b4c269255174c5a",
            "Regression #23");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "00000000000000000000000000000000000000000000000000000000feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "663c7b4c123648242185c9f88352304f4476bf46580297c41714917eda81efa5e0ce2cf48529b587a7e7cd1afcff9d2afa887d0feab6109b",
            "Regression #24");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0b3587f884ca5ac777ac98bbb203dbddf3fda14f351488d0dcf60a9c13c2fec4b8595922a9ec09cfd5d9d20ac639f9f74369b34646288965",
            "Regression #25");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "fefffffffffffffffffffffffffffefffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "3921df4603cce60a982403d04a034160e3bde6b6a496f5be2c927b37dcab5137de990cc00a589b63ee12c9ee7e944bc1500d1b3ded48622c",
            "Regression #26");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "0000000000000000000000000000fffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "51ede7991c611ef33c0676584d1e8897cedf32cccf14e262515c043a7642048e01f2cc3ae392c40063459c34414d4cc809fd37253d7ee801",
            "Regression #27");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "ffffffffffffffffffffffffff7ffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "07538cec452af2888f2bc565f31a5a6e73489857752304e21a1907ff62f63874ef091a0c11d8514a3ed7a15af77efee84f6eec8fa0792423",
            "Regression #28");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "fdfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "5116bf8a4860bbfa28c2c8c96a1105cc9c139130417ed2226f2fe29a3d0b39096b0456faf34dab950bf430bb58c8c8b9320f39c7766c9fc1",
            "Regression #29");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "Regression #30");

        checkX448Vector(
            "244534ab5f22108381d4a35f308d51b19e20ce997d7e9dff253e1d5faf1a8ad6ab73ff586d1eee6dac0fe7b5593c3123c6f1424800fa9b88",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "006bc6af5644e8f5824ab7a1b1411d1b2f91d8038b545efcfcb9917c40a3ef48d698f342c1db57118936a18a2608c0427772c70bd0aae479",
            "Regression #31");
    }

//    @Test
    public void testX448Iterated()
    {
        checkIterated(1000);
    }

//    @Ignore
//    @Test
//    public void testX448IteratedFull()
//    {
//        checkIterated(1000000);
//    }

//    @Test
    public void testX448Vector1()
    {
        checkX448Vector(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
            "Vector #1");
    }

//    @Test
    public void testX448Vector2()
    {
        checkX448Vector(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
            "Vector #2");
    }

    private static void checkECDHVector(String sA, String sAPub, String sB, String sBPub, String sK, String text)
    {
        byte[] a = Hex.decode(sA);
        assertEquals(X448.SCALAR_SIZE, a.length);

        byte[] b = Hex.decode(sB);
        assertEquals(X448.SCALAR_SIZE, b.length);

        byte[] aPub = new byte[X448.POINT_SIZE];
        X448.scalarMultBase(a, 0, aPub, 0);
        checkValue(aPub, text, sAPub);

        byte[] bPub = new byte[X448.POINT_SIZE];
        X448.scalarMultBase(b, 0, bPub, 0);
        checkValue(bPub, text, sBPub);

        byte[] aK = new byte[X448.POINT_SIZE];
        X448.scalarMult(a, 0, bPub, 0, aK, 0);
        checkValue(aK, text, sK);

        byte[] bK = new byte[X448.POINT_SIZE];
        X448.scalarMult(b, 0, aPub, 0, bK, 0);
        checkValue(bK, text, sK);
    }

    private static void checkIterated(int count)
    {
        assertEquals(X448.POINT_SIZE, X448.SCALAR_SIZE);

        byte[] k = new byte[X448.POINT_SIZE];   k[0] = 5;
        byte[] u = new byte[X448.POINT_SIZE];   u[0] = 5;
        byte[] r = new byte[X448.POINT_SIZE];

        int iterations = 0;
        while (iterations < count)
        {
            X448.scalarMult(k, 0, u, 0, r, 0);

            System.arraycopy(k, 0, u, 0, X448.POINT_SIZE);
            System.arraycopy(r, 0, k, 0, X448.POINT_SIZE);

            switch (++iterations)
            {
            case 1:
                checkValue(k, "Iterated @1",
                    "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");
                break;
            case 1000:
                checkValue(k, "Iterated @1000",
                    "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38");
                break;
            case 1000000:
                checkValue(k, "Iterated @1000000",
                    "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37");
                break;
            default:
                break;
            }
        }
    }

    private static void checkValue(byte[] n, String text, String se)
    {
        byte[] e = Hex.decode(se);
        assertTrue(text, Arrays.areEqual(e, n));
    }

    private static void checkX448Vector(String sk, String su, String se, String text)
    {
        byte[] k = Hex.decode(sk);
        assertEquals(X448.SCALAR_SIZE, k.length);

        byte[] u = Hex.decode(su);
        assertEquals(X448.POINT_SIZE, u.length);

        byte[] r = new byte[X448.POINT_SIZE];
        X448.scalarMult(k, 0, u, 0, r, 0);
        checkValue(r, text, se);
    }
}
