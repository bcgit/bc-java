package org.bouncycastle.crypto.test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * ChaCha Test
 * <p>
 * Test cases generated using ref version of ChaCha20 in estreambench-20080905.
 */
public class ChaChaTest
    extends SimpleTest
{
    byte[] zeroes = Hex.decode(
          "00000000000000000000000000000000"
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000");

    String set1v0_0 = "FBB87FBB8395E05DAA3B1D683C422046"
        + "F913985C2AD9B23CFC06C1D8D04FF213"
        + "D44A7A7CDB84929F915420A8A3DC58BF"
        + "0F7ECB4B1F167BB1A5E6153FDAF4493D";

    String set1v0_192 = "D9485D55B8B82D792ED1EEA8E93E9BC1"
        + "E2834AD0D9B11F3477F6E106A2F6A5F2"
        + "EA8244D5B925B8050EAB038F58D4DF57"
        + "7FAFD1B89359DAE508B2B10CBD6B488E";

    String set1v0_256 = "08661A35D6F02D3D9ACA8087F421F7C8"
        + "A42579047D6955D937925BA21396DDD4"
        + "74B1FC4ACCDCAA33025B4BCE817A4FBF"
        + "3E5D07D151D7E6FE04934ED466BA4779";

    String set1v0_448 = "A7E16DD38BA48CCB130E5BE9740CE359"
        + "D631E91600F85C8A5D0785A612D1D987"
        + "90780ACDDC26B69AB106CCF6D866411D"
        + "10637483DBF08CC5591FD8B3C87A3AE0";

    String set1v9_0 = "A276339F99316A913885A0A4BE870F06"
        + "91E72B00F1B3F2239F714FE81E88E00C"
        + "BBE52B4EBBE1EA15894E29658C4CB145"
        + "E6F89EE4ABB045A78514482CE75AFB7C";

    String set1v9_192 = "0DFB9BD4F87F68DE54FBC1C6428FDEB0"
        + "63E997BE8490C9B7A4694025D6EBA2B1"
        + "5FE429DB82A7CAE6AAB22918E8D00449"
        + "6FB6291467B5AE81D4E85E81D8795EBB";

    String set1v9_256 = "546F5BB315E7F71A46E56D4580F90889"
        + "639A2BA528F757CF3B048738BA141AF3"
        + "B31607CB21561BAD94721048930364F4"
        + "B1227CFEB7CDECBA881FB44903550E68";

    String set1v9_448 = "6F813586E76691305A0CF048C0D8586D"
        + "C89460207D8B230CD172398AA33D19E9"
        + "2D24883C3A9B0BB7CD8C6B2668DB142E"
        + "37A97948A7A01498A21110297984CD20";

    String set6v0_0 = "57459975BC46799394788DE80B928387"
        + "862985A269B9E8E77801DE9D874B3F51"
        + "AC4610B9F9BEE8CF8CACD8B5AD0BF17D"
        + "3DDF23FD7424887EB3F81405BD498CC3";

    String set6v0_65472 = "EF9AEC58ACE7DB427DF012B2B91A0C1E"
        + "8E4759DCE9CDB00A2BD59207357BA06C"
        + "E02D327C7719E83D6348A6104B081DB0"
        + "3908E5186986AE41E3AE95298BB7B713";

    String set6v0_65536 = "17EF5FF454D85ABBBA280F3A94F1D26E"
        + "950C7D5B05C4BB3A78326E0DC5731F83"
        + "84205C32DB867D1B476CE121A0D7074B"
        + "AA7EE90525D15300F48EC0A6624BD0AF";

    String set6v1_0 = "92A2508E2C4084567195F2A1005E552B"
        + "4874EC0504A9CD5E4DAF739AB553D2E7"
        + "83D79C5BA11E0653BEBB5C116651302E"
        + "8D381CB728CA627B0B246E83942A2B99";

    String set6v1_65472 = "E1974EC3063F7BD0CBA58B1CE34BC874"
        + "67AAF5759B05EA46682A5D4306E5A76B"
        + "D99A448DB8DE73AF97A73F5FBAE2C776"
        + "35040464524CF14D7F08D4CE1220FD84";

    String set6v1_65536 = "BE3436141CFD62D12FF7D852F80C1344"
        + "81F152AD0235ECF8CA172C55CA8C031B"
        + "2E785D773A988CA8D4BDA6FAE0E493AA"
        + "71DCCC4C894D1F106CAC62A9FC0A9607";

    // ChaCha12
    String chacha12_set1v0_0 = "36CF0D56E9F7FBF287BC5460D95FBA94"
            + "AA6CBF17D74E7C784DDCF7E0E882DDAE"
            + "3B5A58243EF32B79A04575A8E2C2B73D"
            + "C64A52AA15B9F88305A8F0CA0B5A1A25";

    String chacha12_set1v0_192 = "83496792AB68FEC75ADB16D3044420A4"
        + "A00A6E9ADC41C3A63DBBF317A8258C85"
        + "A9BC08B4F76B413A4837324AEDF8BC2A"
        + "67D53C9AB9E1C5BC5F379D48DF9AF730";

    String chacha12_set1v0_256 = "BAA28ED593690FD760ADA07C95E3B888"
        + "4B4B64E488CA7A2D9BDC262243AB9251"
        + "394C5037E255F8BCCDCD31306C508FFB"
        + "C9E0161380F7911FCB137D46D9269250";

    String chacha12_set1v0_448 = "B7ECFB6AE0B51915762FE1FD03A14D0C"
        + "9E54DA5DC76EB16EBA5313BC535DE63D"
        + "C72D7F9F1874E301E99C8531819F4E37"
        + "75793F6A5D19C717FA5C78A39EB804A6";

    // ChaCha8
    String chacha8_set1v0_0 = "BEB1E81E0F747E43EE51922B3E87FB38"
            + "D0163907B4ED49336032AB78B67C2457"
            + "9FE28F751BD3703E51D876C017FAA435"
            + "89E63593E03355A7D57B2366F30047C5";
    
    String chacha8_set1v0_192 = "33B8B7CA8F8E89F0095ACE75A379C651"
            + "FD6BDD55703C90672E44C6BAB6AACDD8"
            + "7C976A87FD264B906E749429284134C2"
            + "38E3B88CF74A68245B860D119A8BDF43";
    
    String chacha8_set1v0_256 = "F7CA95BF08688BD3BE8A27724210F9DC"
            + "16F32AF974FBFB09E9F757C577A245AB"
            + "F35F824B70A4C02CB4A8D7191FA8A5AD"
            + "6A84568743844703D353B7F00A8601F4";
    
    String chacha8_set1v0_448 = "7B4117E8BFFD595CD8482270B08920FB"
            + "C9B97794E1809E07BB271BF07C861003"
            + "4C38DBA6ECA04E5474F399A284CBF6E2"
            + "7F70142E604D0977797DE5B58B6B25E0";
    


    public String getName()
    {
        return "ChaCha";
    }

    public void performTest()
    {
        chachaTest1(20, new ParametersWithIV(new KeyParameter(Hex.decode("80000000000000000000000000000000")), Hex.decode("0000000000000000")),
                  set1v0_0, set1v0_192,  set1v0_256,  set1v0_448);
        chachaTest1(20, new ParametersWithIV(new KeyParameter(Hex.decode("00400000000000000000000000000000")), Hex.decode("0000000000000000")),
                  set1v9_0, set1v9_192,  set1v9_256,  set1v9_448);
        chachaTest1(12, new ParametersWithIV(new KeyParameter(Hex.decode("80000000000000000000000000000000")), Hex.decode("0000000000000000")),
                chacha12_set1v0_0, chacha12_set1v0_192,  chacha12_set1v0_256,  chacha12_set1v0_448);
        chachaTest1(8, new ParametersWithIV(new KeyParameter(Hex.decode("80000000000000000000000000000000")), Hex.decode("0000000000000000")),
                chacha8_set1v0_0, chacha8_set1v0_192,  chacha8_set1v0_256,  chacha8_set1v0_448);
        chachaTest2(new ParametersWithIV(new KeyParameter(Hex.decode("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")), Hex.decode("0D74DB42A91077DE")),
                  set6v0_0, set6v0_65472, set6v0_65536);
        chachaTest2(new ParametersWithIV(new KeyParameter(Hex.decode("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")), Hex.decode("167DE44BB21980E7")),
                  set6v1_0, set6v1_65472, set6v1_65536);
        reinitBug();
        skipTest();

        // ChaCha with 96 bit nonce vectors from
        // http://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305#appendix-A.1 and
        // http://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305#appendix-A.2

        // ChaCha20 Block Function Vectors (96 bit nonce)
        chacha_96_Test1("96nonceB1", 0,
                new ParametersWithIV(new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")), Hex.decode("000000000000000000000000")), zeroes,
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    + "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
        chacha_96_Test1("96nonceB2", 1,
                new ParametersWithIV(new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")), Hex.decode("000000000000000000000000")), zeroes,
                "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed" +
                        "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");
        chacha_96_Test1("96nonceB3", 1,
                new ParametersWithIV(new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000001")), Hex.decode("000000000000000000000000")), zeroes,
                "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
                    + "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0");
        chacha_96_Test1("96nonceB4", 2,
                new ParametersWithIV(new KeyParameter(Hex.decode("00ff000000000000000000000000000000000000000000000000000000000000")), Hex.decode("000000000000000000000000")), zeroes,
                "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
                    + "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096");
        chacha_96_Test1("96nonceB5", 0,
                new ParametersWithIV(new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")), Hex.decode("000000000000000000000002")), zeroes,
                "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7" +
                        "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d");
        // ChaCha20 Encryption Test Vectors (96 bit nonce)
        // ChaCha20 encryption vector 1 is just ChaCha block function test 1
        chacha_96_Test1("96noncev2", 1,
                new ParametersWithIV(new KeyParameter(Hex
                        .decode("0000000000000000000000000000000000000000000000000000000000000001")), Hex
                        .decode("000000000000000000000002")),
                "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"
                        .getBytes(StandardCharsets.US_ASCII),
                "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250"
                    + "d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea8"
                    + "5ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e"
                    + "62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b0"
                    + "4b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a8"
                    + "6f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221");
        chacha_96_Test1("96noncev3",42,
                new ParametersWithIV(new KeyParameter(Hex
                        .decode("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")), Hex
                        .decode("000000000000000000000002")),
                "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe."
                        .getBytes(StandardCharsets.US_ASCII),
                "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf"
                    + "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb"
                    + "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
                    + "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1");

    }

    private void chachaTest1(int rounds, CipherParameters params, String v0, String v192, String v256, String v448)
    {
        StreamCipher chaCha = new ChaChaEngine(rounds);
        byte[]       buf = new byte[64];

        chaCha.init(true, params);

        for (int i = 0; i != 7; i++)
        {
            chaCha.processBytes(zeroes, 0, 64, buf, 0);
            switch (i)
            {
            case 0:
                if (!areEqual(buf, Hex.decode(v0)))
                {
                    mismatch("v0/" + rounds, v0, buf);
                }
                break;
            case 3:
                if (!areEqual(buf, Hex.decode(v192)))
                {
                    mismatch("v192/" + rounds, v192, buf);
                }
                break;
            case 4:
                if (!areEqual(buf, Hex.decode(v256)))
                {
                    mismatch("v256/" + rounds, v256, buf);
                }
                break;
            default:
                // ignore
            }
        }

        for (int i = 0; i != 64; i++)
        {
            buf[i] = chaCha.returnByte(zeroes[i]);
        }

        if (!areEqual(buf, Hex.decode(v448)))
        {
            mismatch("v448", v448, buf);
        }       
    }

    private void chachaTest2(CipherParameters params, String v0, String v65472, String v65536)
    {
        StreamCipher chaCha = new ChaChaEngine();
        byte[]       buf = new byte[64];

        chaCha.init(true, params);

        for (int i = 0; i != 1025; i++)
        {
            chaCha.processBytes(zeroes, 0, 64, buf, 0);
            switch (i)
            {
            case 0:
                if (!areEqual(buf, Hex.decode(v0)))
                {
                    mismatch("v0", v0, buf);
                }
                break;
            case 1023:
                if (!areEqual(buf, Hex.decode(v65472)))
                {
                    mismatch("v65472", v65472, buf);
                }
                break;
            case 1024:
                if (!areEqual(buf, Hex.decode(v65536)))
                {
                    mismatch("v65536", v65536, buf);
                }
                break;
            default:
                // ignore
            }
        }
    }

    private void chacha_96_Test1(String test,
                                 int blockCounter,
                                 CipherParameters params,
                                 byte[] plaintext,
                                 String expected)
    {
        SkippingStreamCipher chaCha = new ChaChaEngine();
        byte[] output = new byte[plaintext.length];

        chaCha.init(true, params);
        chaCha.seekTo(blockCounter * 64);
        chaCha.processBytes(plaintext, 0, plaintext.length, output, 0);

        if (!areEqual(output, Hex.decode(expected)))
        {
            mismatch(test, expected, output);
        }
    }

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }


    private void reinitBug()
    {
        KeyParameter key = new KeyParameter(Hex.decode("80000000000000000000000000000000"));
        ParametersWithIV parameters = new ParametersWithIV(key, Hex.decode("0000000000000000"));

        StreamCipher salsa = new ChaChaEngine();

        salsa.init(true, parameters);

        try
        {
            salsa.init(true, key);
            fail("Salsa20 should throw exception if no IV in Init");
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    private boolean areEqual(byte[] a, int aOff, byte[] b, int bOff)
    {
        for (int i = bOff; i != b.length; i++)
        {
            if (a[aOff + i - bOff] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    private void skipTest()
    {
        SecureRandom rand = new SecureRandom();
        byte[]       plain = new byte[5000];
        byte[]       cipher = new byte[5000];

        rand.nextBytes(plain);

        CipherParameters params = new ParametersWithIV(new KeyParameter(Hex.decode("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")), Hex.decode("0D74DB42A91077DE"));
        ChaChaEngine    engine = new ChaChaEngine();

        engine.init(true, params);

        engine.processBytes(plain, 0, plain.length, cipher, 0);

        byte[]      fragment = new byte[20];

        engine.init(true, params);

        engine.skip(10);

        engine.processBytes(plain, 10, fragment.length, fragment, 0);

        if (!areEqual(cipher, 10, fragment, 0))
        {
            fail("skip forward 10 failed");
        }

        engine.skip(1000);

        engine.processBytes(plain, 1010 + fragment.length, fragment.length, fragment, 0);

        if (!areEqual(cipher, 1010 + fragment.length, fragment, 0))
        {
            fail("skip forward 1000 failed");
        }

        engine.skip(-10);

        engine.processBytes(plain, 1010 + 2 * fragment.length - 10, fragment.length, fragment, 0);

        if (!areEqual(cipher, 1010 + 2 * fragment.length - 10, fragment, 0))
        {
            fail("skip back 10 failed");
        }

        engine.skip(-1000);

        if (engine.getPosition() != 60)
        {
            fail("skip position incorrect - " + 60 + " got " + engine.getPosition());
        }

        engine.processBytes(plain, 60, fragment.length, fragment, 0);

        if (!areEqual(cipher, 60, fragment, 0))
        {
            fail("skip back 1000 failed");
        }

        long pos = engine.seekTo(1010);
        if (pos != 1010)
        {
            fail("position wrong");
        }

        engine.processBytes(plain, 1010, fragment.length, fragment, 0);

        if (!areEqual(cipher, 1010, fragment, 0))
        {
            fail("seek to 1010 failed");
        }

        engine.reset();

        for (int i = 0; i != 1000; i++)
        {
            engine.skip(i);

            if (engine.getPosition() != i)
            {
                fail("skip forward at wrong position");
            }

            engine.processBytes(plain, i, fragment.length, fragment, 0);

            if (!areEqual(cipher, i, fragment, 0))
            {
                fail("skip forward i failed: " + i);
            }

            if (engine.getPosition() != i + fragment.length)
            {
                fail("cipher at wrong position: " + engine.getPosition() + " [" + i + "]");
            }

            engine.skip(-fragment.length);

            if (engine.getPosition() != i)
            {
                fail("skip back at wrong position");
            }

            engine.processBytes(plain, i, fragment.length, fragment, 0);

            if (!areEqual(cipher, i, fragment, 0))
            {
                fail("skip back i failed: " + i);
            }

            engine.reset();
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new ChaChaTest());
    }
}
