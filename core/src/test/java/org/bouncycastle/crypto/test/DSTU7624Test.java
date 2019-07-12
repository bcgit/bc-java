package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.DSTU7624WrapEngine;
import org.bouncycastle.crypto.macs.DSTU7624Mac;
import org.bouncycastle.crypto.macs.KGMac;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.KCCMBlockCipher;
import org.bouncycastle.crypto.modes.KCTRBlockCipher;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.modes.KXTSBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class DSTU7624Test
    extends CipherTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    
    private static byte[] randomBytes(int min, int max)
    {
        int count = min + RNGUtils.nextInt(RANDOM,max - min);
        byte[] result = new byte[count];
        RANDOM.nextBytes(result);
        return result;
    }

    static SimpleTest[] tests =
        {
            //ECB mode
            new BlockCipherVectorTest(0, new DSTU7624Engine(128), new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), "101112131415161718191A1B1C1D1E1F", "81BF1C7D779BAC20E1C9EA39B4D2AD06"),
            new BlockCipherVectorTest(1, new DSTU7624Engine(128), new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")), "202122232425262728292A2B2C2D2E2F", "58EC3E091000158A1148F7166F334F14"),
            new BlockCipherVectorTest(2, new DSTU7624Engine(256), new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")), "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", "F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C"),
            new BlockCipherVectorTest(3, new DSTU7624Engine(256), new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", "606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9"),
            new BlockCipherVectorTest(4, new DSTU7624Engine(512), new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F", "4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9"),

            //CBC mode
            new BlockCipherVectorTest(5, new CBCBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), Hex.decode("101112131415161718191A1B1C1D1E1F")), "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F", "A73625D7BE994E85469A9FAABCEDAAB6DBC5F65DD77BB35E06BD7D1D8EAFC8624D6CB31CE189C82B8979F2936DE9BF14"),
            new BlockCipherVectorTest(6, new CBCBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("0F0E0D0C0B0A09080706050403020100")), Hex.decode("1F1E1D1C1B1A19181716151413121110")), "88F2F048BA696170E3818915E0DBC0AFA6F141FEBC2F817138DA4AAB2DBF9CE490A488C9C82AC83FB0A6C0EEB64CFD22", "4F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120"),
            new BlockCipherVectorTest(7, new CBCBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")), Hex.decode("202122232425262728292A2B2C2D2E2F")), "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D8000", "13EA15843AD14C50BC03ECEF1F43E398E4217752D3EB046AC393DACC5CA1D6FA0EB9FCEB229362B4F1565527EE3D8433"),
            new BlockCipherVectorTest(8, new CBCBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")), Hex.decode("2F2E2D2C2B2A29282726252423222120")), "BC8F026FC603ECE05C24FDE87542730999B381870882AC0535D4368C4BABD81B884E96E853EE7E055262D9D204FBE212", "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A39383736353433323130"),
            new BlockCipherVectorTest(9, new CBCBlockCipher(new DSTU7624Engine(256)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")), Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F", "9CDFDAA75929E7C2A5CFC1BF16B42C5AE3886D0258E8C577DC01DAF62D185FB999B9867736B87110F5F1BC7481912C593F48FF79E2AFDFAB9F704A277EC3E557B1B0A9F223DAE6ED5AF591C4F2D6FB22E48334F5E9B96B1A2EA5200F30A406CE"),
            new BlockCipherVectorTest(10, new CBCBlockCipher(new DSTU7624Engine(256)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")), "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF", "B8A2474578C2FEBF3F94703587BD5FDC3F4A4D2F43575B6144A1E1031FB3D1452B7FD52F5E3411461DAC506869FF8D2FAEF4FEE60379AE00B33AA3EAF911645AF8091CD8A45D141D1FB150E5A01C1F26FF3DBD26AC4225EC7577B2CE57A5B0FF"),
            new BlockCipherVectorTest(11, new CBCBlockCipher(new DSTU7624Engine(256)), new ParametersWithIV(new KeyParameter(Hex.decode("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")), Hex.decode("5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140")), "C69A59E10D00F087319B62288A57417C074EAD07C732A87055F0A5AD2BB288105705C45E091A9A6726E9672DC7D8C76FC45C782BCFEF7C39D94DEB84B17035BC8651255A0D34373451B6E1A2C827DB97566C9FF5506C5579F982A0EFC5BA7C28", "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A69686766656463626160"),
            new BlockCipherVectorTest(12, new CBCBlockCipher(new DSTU7624Engine(512)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F")), "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", "D4739B829EF901B24C1162AE4FDEF897EDA41FAC7F5770CDC90E1D1CDF124E8D7831E06B4498A4B6F6EC815DF2461DC99BB0449B0F09FCAA2C84090534BCC9329626FD74EF8F0A0BCB5765184629C3CBF53B0FB134F6D0421174B1C4E884D1CD1069A7AD19752DCEBF655842E79B7858BDE01390A760D85E88925BFE38B0FA57"),
            new BlockCipherVectorTest(13, new CBCBlockCipher(new DSTU7624Engine(512)), new ParametersWithIV(new KeyParameter(Hex.decode("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")), Hex.decode("7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140")), "5D5B3E3DE5BAA70E0A0684D458856CE759C6018D0B3F087FC1DAC101D380236DD934F2880B02D56A575BCA35A0CE4B0D9BA1F4A39C16CA7D80D59956630F09E54EC91E32B6830FE08323ED393F8028D150BF03CAD0629A5AFEEFF6E44257980618DB2F32B7B2B65B96E8451F1090829D2FFFC615CC1581E9221438DCEAD1FD12", "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180"),

            //CFB mode
            new BlockCipherVectorTest(14, new CFBBlockCipher(new DSTU7624Engine(128), 128), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), Hex.decode("101112131415161718191A1B1C1D1E1F")), "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F", "A19E3E5E53BE8A07C9E0C01298FF83291F8EE6212110BE3FA5C72C88A082520B265570FE28680719D9B4465E169BC37A"),

            //OFB mode
            new BlockCipherVectorTest(15, new OFBBlockCipher(new DSTU7624Engine(128), 128), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), Hex.decode("101112131415161718191A1B1C1D1E1F")), "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F", "A19E3E5E53BE8A07C9E0C01298FF832953205C661BD85A51F3A94113BC785CAB634B36E89A8FDD16A12E4467F5CC5A26"),
            new BlockCipherVectorTest(16, new OFBBlockCipher(new DSTU7624Engine(128), 128), new ParametersWithIV(new KeyParameter(Hex.decode("0F0E0D0C0B0A09080706050403020100")), Hex.decode("1F1E1D1C1B1A19181716151413121110")), "649A1EAAE160AF20F5B3EF2F58D66C1178B82E00D26F30689C8EC22E8E86E9CBB0BD4FFEE39EB13C2311276A906DD636", "4F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120"),
            new BlockCipherVectorTest(17, new OFBBlockCipher(new DSTU7624Engine(128), 128), new ParametersWithIV(new KeyParameter(Hex.decode("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")), Hex.decode("2F2E2D2C2B2A29282726252423222120")), "1A66CFBFEC00C6D52E39923E858DD64B214AB787798D3D5059A6B498AD66B34EAC48C4074BEC0D98C6", "5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837"),
            new BlockCipherVectorTest(18, new OFBBlockCipher(new DSTU7624Engine(256), 256), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")), Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90", "B62F7F144A8C6772E693A96890F064C3F06831BF743F5B0DD061067F3D22877331AA6A99D939F05B7550E9402BD1615CC7B2D4A167E83EC0D8A894F92C72E176F3880B61C311D69CE1210C59184E818E19"),
            new BlockCipherVectorTest(19, new OFBBlockCipher(new DSTU7624Engine(256), 256), new ParametersWithIV(new KeyParameter(Hex.decode("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")), Hex.decode("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120")), "7758A939DD6BD00CAF9153E5A5D5A66129105CA1EA54A97C06FA4A40960A068F55E34F9339A14436216948F92FA2FB5286D3AB1E81543FC0018A0C4E8C493475F4D35DCFB0A7A5377F6669B857CDC978E4", "9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F"),
            new BlockCipherVectorTest(20, new OFBBlockCipher(new DSTU7624Engine(256), 256), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")), "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0", "0008F28A82D2D01D23BFB2F8BB4F06D8FE73BA4F48A2977585570ED3818323A668883C9DCFF610CC7E3EA5C025FBBC5CA6520F8F11CA35CEB9B07031E6DBFABE39001E9A3CC0A24BBC565939592B4DEDBD"),
            new BlockCipherVectorTest(21, new OFBBlockCipher(new DSTU7624Engine(256), 256), new ParametersWithIV(new KeyParameter(Hex.decode("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")), Hex.decode("5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140")), "98E122708FDABB1B1A5765C396DC79D7573221EC486ADDABD1770B147A6DD00B5FBC4F1EC68C59775B7AAA4D43C4CCE4F396D982DF64D30B03EF6C3B997BA0ED940BBC590BD30D64B5AE207147D71086B5", "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F"),
            new BlockCipherVectorTest(22, new OFBBlockCipher(new DSTU7624Engine(512), 512), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")), Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F")), "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0", "CAA761980599B3ED2E945C41891BAD95F72B11C73ED26536A6847458BC76C827357156B4B3FE0DC1877F5B9F17B866C37B21D89531DB48007D05DEC928B06766C014BB9080385EDF0677E48A0A39B5E7489E28E82FFFD1F84694F17296CB701656"),
            new BlockCipherVectorTest(23, new OFBBlockCipher(new DSTU7624Engine(512), 512), new ParametersWithIV(new KeyParameter(Hex.decode("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")), Hex.decode("7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140")), "06C061A4A66DFC0910034B3CFBDC4206D8908241C56BF41C4103CFD6DF322210B87F57EAE9F9AD815E606A7D1E8E6BD7CB1EBFBDBCB085C2D06BF3CC1586CB2EE1D81D38437F425131321647E42F5DE309D33F25B89DE37124683E4B44824FC56D", "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F"),

            //CTR mode
            new BlockCipherVectorTest(24, new KCTRBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), Hex.decode("101112131415161718191A1B1C1D1E1F")), "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748", "A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A"),
            new BlockCipherVectorTest(25, new KCTRBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), Hex.decode("101112131415161718191A1B1C1D1E1F")), "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F", "B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51"),
            new StreamCipherVectorTest(26, new KCTRBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), Hex.decode("101112131415161718191A1B1C1D1E1F")), "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748", "A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A"),
            new StreamCipherVectorTest(27, new KCTRBlockCipher(new DSTU7624Engine(128)), new ParametersWithIV(new KeyParameter(Hex.decode("000102030405060708090A0B0C0D0E0F")), Hex.decode("101112131415161718191A1B1C1D1E1F")), "303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F", "B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51")
        };


    public DSTU7624Test()
    {
        super(tests, new DSTU7624Engine(128), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "DSTU7624";
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        MacTests();
        KeyWrapTests();
        CCMModeTests();
        XTSModeTests();
        GCMModeTests();
    }

    public static void main(
        String[] args)
    {
        runTest(new DSTU7624Test());
    }


    private void MacTests()
    {

        //test 1
        byte[] key = Hex.decode("000102030405060708090A0B0C0D0E0F");

        byte[] authtext = Hex.decode("202122232425262728292A2B2C2D2E2F" +
            "303132333435363738393A3B3C3D3E3F" +
            "404142434445464748494A4B4C4D4E4F");

        byte[] expectedMac = Hex.decode("123B4EAB8E63ECF3E645A99C1115E241");

        byte[] mac = new byte[expectedMac.length];

        DSTU7624Mac dstu7624Mac = new DSTU7624Mac(128, 128);
        dstu7624Mac.init(new KeyParameter(key));
        dstu7624Mac.update(authtext, 0, authtext.length);
        dstu7624Mac.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed MAC test 1 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }


        //test 2
        key = Hex.decode("000102030405060708090A0B0C0D0E0F" +
            "101112131415161718191A1B1C1D1E1F" +
            "202122232425262728292A2B2C2D2E2F" +
            "303132333435363738393A3B3C3D3E3F");

        authtext = Hex.decode("404142434445464748494A4B4C4D4E4F" +
            "505152535455565758595A5B5C5D5E5F" +
            "606162636465666768696A6B6C6D6E6F" +
            "707172737475767778797A7B7C7D7E7F" +
            "808182838485868788898A8B8C8D8E8F" +
            "909192939495969798999A9B9C9D9E9F" +
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");

        expectedMac = Hex.decode("7279FA6BC8EF7525B2B35260D00A1743");

        dstu7624Mac = new DSTU7624Mac(512, 128);
        dstu7624Mac.init(new KeyParameter(key));
        dstu7624Mac.update(authtext, 0, authtext.length);
        dstu7624Mac.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed MAC test 2 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        // check that reset correctly on doFinal()
        dstu7624Mac.update(authtext, 0, authtext.length);
        dstu7624Mac.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed MAC test reset - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        // check that init reset correctly
        dstu7624Mac.init(new KeyParameter(key));
        dstu7624Mac.init(new KeyParameter(key));
        dstu7624Mac.update(authtext, 0, authtext.length);
        dstu7624Mac.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed MAC test double init - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        // check simple reset
        dstu7624Mac = new DSTU7624Mac(512, 128);
        dstu7624Mac.reset();
    }

    private void KeyWrapTests()
        throws Exception
    {
        //test 1
        /*
         * Initial implementation had bugs handling offset and length correctly, so for
         * this first test case we embed the input inside a larger buffer.
         */
        byte[] textA = randomBytes(1, 64);
        byte[] textB = randomBytes(1, 64);
        byte[] textToWrap = Arrays.concatenate(new byte[][]{ textA, Hex.decode("101112131415161718191A1B1C1D1E1F"), textB });

        byte[] key = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] expectedWrappedText = Hex.decode("1DC91DC6E52575F6DBED25ADDA95A1B6AD3E15056E489738972C199FB9EE2913");
        byte[] output = new byte[expectedWrappedText.length];

        DSTU7624WrapEngine wrapper = new DSTU7624WrapEngine(128);
        wrapper.init(true, new KeyParameter(key));
        output = wrapper.wrap(textToWrap, textA.length, textToWrap.length - textA.length - textB.length);

        if (!Arrays.areEqual(output, expectedWrappedText))
        {
            fail("Failed KW (wrapping) test 1 - expected "
                + Hex.toHexString(expectedWrappedText)
                + " got " + Hex.toHexString(output));
        }

        output = Arrays.concatenate(new byte[][]{ textB, output, textA });

        wrapper.init(false, new KeyParameter(key));
        output = wrapper.unwrap(output, textB.length, output.length - textB.length - textA.length);

        byte[] expected = Arrays.copyOfRange(textToWrap, textA.length, textToWrap.length - textB.length);
        if (!Arrays.areEqual(output, expected))
        {
            fail("Failed KW (unwrapping) test 1 - expected "
                + Hex.toHexString(expected)
                + " got " + Hex.toHexString(output));
        }

        //test 2
        key = Hex.decode("000102030405060708090A0B0C0D0E0F");
        textToWrap = Hex.decode("101112131415161718191A1B1C1D1E1F20219000000000000000800000000000");
        expectedWrappedText = Hex.decode("0EA983D6CE48484D51462C32CC61672210FCC44196ABE635BAF878FDB83E1A63114128585D49DB355C5819FD38039169");

        output = new byte[expectedWrappedText.length];

        wrapper.init(true, new KeyParameter(key));
        output = wrapper.wrap(textToWrap, 0, textToWrap.length);


        if (!Arrays.areEqual(output, expectedWrappedText))
        {
            fail("Failed KW (wrapping) test 2 - expected "
                + Hex.toHexString(expectedWrappedText)
                + " got " + Hex.toHexString(output));
        }


        wrapper.init(false, new KeyParameter(key));

        output = wrapper.unwrap(expectedWrappedText, 0, expectedWrappedText.length);
        if (!Arrays.areEqual(output, textToWrap))
        {
            fail("Failed KW (unwrapping) test 2 - expected "
                + Hex.toHexString(textToWrap)
                + " got " + Hex.toHexString(output));
        }

        //test 3
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        textToWrap = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
        expectedWrappedText = Hex.decode("2D09A7C18E6A5A0816331EC27CEA596903F77EC8D63F3BDB73299DE7FD9F4558E05992B0B24B39E02EA496368E0841CC1E3FA44556A3048C5A6E9E335717D17D");

        output = new byte[expectedWrappedText.length];

        wrapper = new DSTU7624WrapEngine(128);
        wrapper.init(true, new KeyParameter(key));
        output = wrapper.wrap(textToWrap, 0, textToWrap.length);


        if (!Arrays.areEqual(output, expectedWrappedText))
        {
            fail("Failed KW (wrapping) test 3 - expected "
                + Hex.toHexString(expectedWrappedText)
                + " got " + Hex.toHexString(output));
        }

        wrapper.init(false, new KeyParameter(key));

        output = wrapper.unwrap(expectedWrappedText, 0, expectedWrappedText.length);

        if (!Arrays.areEqual(output, textToWrap))
        {
            fail("Failed KW (unwrapping) test 3 - expected "
                + Hex.toHexString(textToWrap)
                + " got " + Hex.toHexString(output));
        }

        //test 4
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        textToWrap = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464E8040000000000020");
        expectedWrappedText = Hex.decode("37E3EECB91150C6FA04CFD19D6FC57B7168C9FA5C5ED18601C68EE4AFD7301F8C8C51D7A0A5CD34F6FAB0D8AF11845CC1E4B16E0489FDA1D76BA4EFCFD161F76");

        output = new byte[expectedWrappedText.length];

        wrapper = new DSTU7624WrapEngine(128);
        wrapper.init(true, new KeyParameter(key));
        output = wrapper.wrap(textToWrap, 0, textToWrap.length);


        if (!Arrays.areEqual(output, expectedWrappedText))
        {
            fail("Failed KW (wrapping) test 4 - expected "
                + Hex.toHexString(expectedWrappedText)
                + " got " + Hex.toHexString(output));
        }

        wrapper.init(false, new KeyParameter(key));

        output = wrapper.unwrap(expectedWrappedText, 0, expectedWrappedText.length);

        if (!Arrays.areEqual(output, textToWrap))
        {
            fail("Failed KW (unwrapping) test 4 - expected "
                + Hex.toHexString(textToWrap)
                + " got " + Hex.toHexString(output));
        }

        //test 5
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        textToWrap = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
        expectedWrappedText = Hex.decode("BE59D3C3C31B2685A8FA57CD000727F16AF303F0D87BC2D7ABD80DC2796BBC4CDBC4E0408943AF4DAF7DE9084DC81BFEF15FDCDD0DF399983DF69BF730D7AE2A199CA4F878E4723B7171DD4D1E8DF59C0F25FA0C20946BA64F9037D724BB1D50B6C2BD9788B2AF83EF6163087CD2D4488BC19F3A858D813E3A8947A529B6D65D");

        output = new byte[expectedWrappedText.length];

        wrapper = new DSTU7624WrapEngine(256);
        wrapper.init(true, new KeyParameter(key));
        output = wrapper.wrap(textToWrap, 0, textToWrap.length);


        if (!Arrays.areEqual(output, expectedWrappedText))
        {
            fail("Failed KW (wrapping) test 5 - expected "
                + Hex.toHexString(expectedWrappedText)
                + " got " + Hex.toHexString(output));
        }

        wrapper.init(false, new KeyParameter(key));

        output = wrapper.unwrap(expectedWrappedText, 0, expectedWrappedText.length);

        if (!Arrays.areEqual(output, textToWrap))
        {
            fail("Failed KW (unwrapping) test 5 - expected "
                + Hex.toHexString(textToWrap)
                + " got " + Hex.toHexString(output));
        }
    }

    private void CCMModeTests()
        throws Exception
    {
        //test 1
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] iv = Hex.decode("101112131415161718191a1b1c1d1e1f");
        byte[] input = Hex.decode("303132333435363738393a3b3c3d3e3f");
        byte[] authText = Hex.decode("202122232425262728292a2b2c2d2e2f");

        byte[] expectedMac = Hex.decode("26a936173a4dc9160d6e3fda3a974060");
        byte[] expectedEncrypted = Hex.decode("b91a7b8790bbcfcfe65d04e5538e98e2704454c9dd39adace0b19d03f6aab07e");

        byte[] mac;
        byte[] encrypted = new byte[expectedEncrypted.length];

        byte[] decrypted = new byte[encrypted.length];
        byte[] expectedDecrypted = new byte[input.length + expectedMac.length];
        System.arraycopy(input, 0, expectedDecrypted, 0, input.length);
        System.arraycopy(expectedMac, 0, expectedDecrypted, input.length, expectedMac.length);
        int len;


        AEADParameters param = new AEADParameters(new KeyParameter(key), 128, iv);

        KCCMBlockCipher dstu7624ccm = new KCCMBlockCipher(new DSTU7624Engine(128));

        dstu7624ccm.init(true, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(input, 0, input.length, encrypted, 0);


        dstu7624ccm.doFinal(encrypted, len);

        mac = dstu7624ccm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed CCM mac test 1 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedEncrypted))
        {
            fail("Failed CCM encrypt test 1 - expected "
                + Hex.toHexString(expectedEncrypted)
                + " got " + Hex.toHexString(encrypted));
        }

        dstu7624ccm.init(false, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(expectedEncrypted, 0, expectedEncrypted.length, decrypted, 0);

        dstu7624ccm.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, expectedDecrypted))
        {
            fail("Failed CCM decrypt/verify mac test 1 - expected "
                + Hex.toHexString(expectedDecrypted)
                + " got " + Hex.toHexString(decrypted));
        }

        //test 2
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        iv = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        input = Hex.decode("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
        authText = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

        expectedMac = Hex.decode("9AB831B4B0BF0FDBC36E4B4FD58F0F00");
        expectedEncrypted = Hex.decode("7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE809C48AD90A9E12A68380EF1C1B7C83EE1");

        mac = new byte[expectedMac.length];
        encrypted = new byte[expectedEncrypted.length];

        decrypted = new byte[encrypted.length];
        expectedDecrypted = new byte[input.length + expectedMac.length];
        System.arraycopy(input, 0, expectedDecrypted, 0, input.length);
        System.arraycopy(expectedMac, 0, expectedDecrypted, input.length, expectedMac.length);


        param = new AEADParameters(new KeyParameter(key), 128, iv);

        dstu7624ccm = new KCCMBlockCipher(new DSTU7624Engine(256));

        dstu7624ccm.init(true, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(input, 0, input.length, encrypted, 0);

        dstu7624ccm.doFinal(encrypted, len);

        mac = dstu7624ccm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed CCM mac test 2 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedEncrypted))
        {
            fail("Failed CCM encrypt test 2 - expected "
                + Hex.toHexString(expectedEncrypted)
                + " got " + Hex.toHexString(encrypted));
        }

        dstu7624ccm.init(false, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(expectedEncrypted, 0, expectedEncrypted.length, decrypted, 0);

        dstu7624ccm.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, expectedDecrypted))
        {
            fail("Failed CCM decrypt/verify mac test 2 - expected "
                + Hex.toHexString(expectedDecrypted)
                + " got " + Hex.toHexString(decrypted));
        }

        //test 3
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        iv = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        input = Hex.decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");
        authText = Hex.decode("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");

        expectedMac = Hex.decode("924FA0326824355595C98028E84D86279CEA9135FAB35F22054AE3203E68AE46");
        expectedEncrypted = Hex.decode("3EBDB4584B5169A26FBEBA0295B4223F58D5D8A031F2950A1D7764FAB97BA058E9E2DAB90FF0C519AA88435155A71B7B53BB100F5D20AFFAC0552F5F2813DEE8DD3653491737B9615A5CCD83DB32F1E479BF227C050325BBBFF60BCA9558D7FE");

        mac = new byte[expectedMac.length];
        encrypted = new byte[expectedEncrypted.length];

        decrypted = new byte[encrypted.length];
        expectedDecrypted = new byte[input.length + expectedMac.length];
        System.arraycopy(input, 0, expectedDecrypted, 0, input.length);
        System.arraycopy(expectedMac, 0, expectedDecrypted, input.length, expectedMac.length);


        param = new AEADParameters(new KeyParameter(key), 256, iv);

        dstu7624ccm = new KCCMBlockCipher(new DSTU7624Engine(256), 6);

        dstu7624ccm.init(true, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(input, 0, input.length, encrypted, 0);

        dstu7624ccm.doFinal(encrypted, len);

        mac = dstu7624ccm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed CCM mac test 3 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedEncrypted))
        {
            fail("Failed CCM encrypt test 3 - expected "
                + Hex.toHexString(expectedEncrypted)
                + " got " + Hex.toHexString(encrypted));
        }

        dstu7624ccm.init(false, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(expectedEncrypted, 0, expectedEncrypted.length, decrypted, 0);

        dstu7624ccm.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, expectedDecrypted))
        {
            fail("Failed CCM decrypt/verify mac test 3 - expected "
                + Hex.toHexString(expectedDecrypted)
                + " got " + Hex.toHexString(decrypted));
        }

        //test 4
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        iv = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
        input = Hex.decode("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        authText = Hex.decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");

        expectedMac = Hex.decode("D4155EC3D888C8D32FE184AC260FD60F567705E1DF362A6F1F9C287156AA96D91BC4C56F9709E72F3D79CF0A9AC8BDC2BA836BE50E823AB50FB1B39080390923");
        expectedEncrypted = Hex.decode("220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99BD8F80CE149143C04FC2490272A31B029DDADA82F055FE4ABEF452A7D438B21E59C1D8B3DD4606BAD66A6F36300EF3CE0E5F3BB59F11416E80B7FC5A8E8B057A");

        mac = new byte[expectedMac.length];
        encrypted = new byte[expectedEncrypted.length];

        decrypted = new byte[encrypted.length];
        expectedDecrypted = new byte[input.length + expectedMac.length];
        System.arraycopy(input, 0, expectedDecrypted, 0, input.length);
        System.arraycopy(expectedMac, 0, expectedDecrypted, input.length, expectedMac.length);


        param = new AEADParameters(new KeyParameter(key), 512, iv);

        dstu7624ccm = new KCCMBlockCipher(new DSTU7624Engine(512), 8);

        dstu7624ccm.init(true, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(input, 0, input.length, encrypted, 0);

        dstu7624ccm.doFinal(encrypted, len);

        mac = dstu7624ccm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed CCM mac test 4 - expected "
                + Hex.toHexString(expectedMac)
                + " got " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedEncrypted))
        {
            fail("Failed CCM encrypt test 4 - expected "
                + Hex.toHexString(expectedEncrypted)
                + " got " + Hex.toHexString(encrypted));
        }

        dstu7624ccm.init(false, param);

        dstu7624ccm.processAADBytes(authText, 0, authText.length);

        len = dstu7624ccm.processBytes(expectedEncrypted, 0, expectedEncrypted.length, decrypted, 0);

        dstu7624ccm.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, expectedDecrypted))
        {
            fail("Failed CCM decrypt/verify mac test 4 - expected "
                + Hex.toHexString(expectedDecrypted)
                + " got " + Hex.toHexString(decrypted));
        }

        doFinalTest(new KCCMBlockCipher(new DSTU7624Engine(512), 8), key, iv, authText, input, expectedEncrypted);
    }

    private void XTSModeTests()
        throws Exception
    {

        //test 1
        byte[] key = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] iv = Hex.decode("101112131415161718191A1B1C1D1E1F");
        byte[] plainText = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        byte[] output = new byte[plainText.length];
        byte[] expectedCipherText = Hex.decode("B3E431B3FBAF31108C302669EE7116D1CF518B6D329D30618DF5628E426BDEF1");

        byte[] decrypted = new byte[plainText.length];


        int len;

        KXTSBlockCipher dstu7624xts = new KXTSBlockCipher(new DSTU7624Engine(128));
        ParametersWithIV param = new ParametersWithIV(new KeyParameter(key), iv);

        dstu7624xts.init(true, param);
        len = dstu7624xts.processBytes(plainText, 0, plainText.length, output, 0);

        dstu7624xts.doFinal(output, len);

        if (!Arrays.areEqual(output, expectedCipherText))
        {
            fail("Failed XTS encrypt test 1 - expected "
                + Hex.toHexString(expectedCipherText)
                + " got " + Hex.toHexString(output));
        }


        dstu7624xts.init(false, param);
        len = dstu7624xts.processBytes(expectedCipherText, 0, expectedCipherText.length, decrypted, 0);
        dstu7624xts.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed XTS decrypt test 1 - expected "
                + Hex.toHexString(plainText)
                + " got " + Hex.toHexString(decrypted));
        }

        //test 2
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        iv = Hex.decode("202122232425262728292A2B2C2D2E2F");
        plainText = Hex.decode("303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");

        output = new byte[plainText.length];
        expectedCipherText = Hex.decode("830AC78A6F629CB4C7D5D156FD84955BD0998CA1E0BC1FF135676BF2A2598FA1");

        decrypted = new byte[plainText.length];


        dstu7624xts = new KXTSBlockCipher(new DSTU7624Engine(128));
        param = new ParametersWithIV(new KeyParameter(key), iv);

        dstu7624xts.init(true, param);
        len = dstu7624xts.processBytes(plainText, 0, plainText.length, output, 0);
        dstu7624xts.doFinal(output, len);

        if (!Arrays.areEqual(output, expectedCipherText))
        {
            fail("Failed XTS encrypt test 2 - expected "
                + Hex.toHexString(expectedCipherText)
                + " got " + Hex.toHexString(output));
        }


        dstu7624xts.init(false, param);
        len = dstu7624xts.processBytes(expectedCipherText, 0, expectedCipherText.length, decrypted, 0);
        dstu7624xts.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed XTS decrypt test 2 - expected "
                + Hex.toHexString(plainText)
                + " got " + Hex.toHexString(decrypted));
        }


        //test 3
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        iv = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        plainText = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");

        output = new byte[plainText.length];
        expectedCipherText = Hex.decode("E0E51EAEA6A3134600758EA7F87E88025D8B82897C8DB099B843054C3A51883756913571530BA8FA23003E337627E698674B807E847EC6B2292627736562F9F62B2DE9E6AAC5DF74C09A0C5CF80280174AEC9BDD4E73F7D63EDBC29A6922637A");

        decrypted = new byte[plainText.length];

        dstu7624xts = new KXTSBlockCipher(new DSTU7624Engine(256));
        param = new ParametersWithIV(new KeyParameter(key), iv);

        dstu7624xts.init(true, param);
        len = dstu7624xts.processBytes(plainText, 0, plainText.length, output, 0);
        dstu7624xts.doFinal(output, len);

        if (!Arrays.areEqual(output, expectedCipherText))
        {
            fail("Failed XTS encrypt test 3 - expected "
                + Hex.toHexString(expectedCipherText)
                + " got " + Hex.toHexString(output));
        }

        dstu7624xts.init(false, param);
        len = dstu7624xts.processBytes(expectedCipherText, 0, expectedCipherText.length, decrypted, 0);
        dstu7624xts.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed XTS decrypt test 3 - expected "
                + Hex.toHexString(plainText)
                + " got " + Hex.toHexString(decrypted));
        }

        //test 4
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        iv = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        plainText = Hex.decode("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");

        output = new byte[plainText.length];
        expectedCipherText = Hex.decode("30663E4686574B343A1898E46973CD37DB9D775D356512EB59E723397F2A333CE2C0E96538781FF48EA1D93BDF88FFF8BB7BC4FB80A609881220C7FE21881C7374F65B232A8F94CD0E3DDC7614830C23CFCE98ADC5113496F9E106E8C8BFF3AB");

        decrypted = new byte[plainText.length];

        dstu7624xts = new KXTSBlockCipher(new DSTU7624Engine(256));
        param = new ParametersWithIV(new KeyParameter(key), iv);

        dstu7624xts.init(true, param);
        len = dstu7624xts.processBytes(plainText, 0, plainText.length, output, 0);
        dstu7624xts.doFinal(output, len);

        if (!Arrays.areEqual(output, expectedCipherText))
        {
            fail("Failed XTS encrypt test 4 - expected "
                + Hex.toHexString(expectedCipherText)
                + " got " + Hex.toHexString(output));
        }


        dstu7624xts.init(false, param);
        len = dstu7624xts.processBytes(expectedCipherText, 0, expectedCipherText.length, decrypted, 0);
        dstu7624xts.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed XTS decrypt test 4 - expected "
                + Hex.toHexString(plainText)
                + " got " + Hex.toHexString(decrypted));
        }

        //test 5
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        iv = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
        plainText = Hex.decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");

        output = new byte[plainText.length];
        expectedCipherText = Hex.decode("5C6250BD2E40AAE27E1E57512CD38E6A51D0C2B04F0D6A50E0CB43358B8C4E8BA361331436C6FFD38D77BBBBF5FEC56A234108A6CC8CB298360943E849E5BD64D26ECA2FA8AEAD070656C3777BA412BCAF3D2F08C26CF86CA8F0921043A15D709AE1112611E22D4396E582CCB661E0F778B6F38561BC338AFD5D1036ED8B322D");

        decrypted = new byte[plainText.length];

        dstu7624xts = new KXTSBlockCipher(new DSTU7624Engine(512));
        param = new ParametersWithIV(new KeyParameter(key), iv);

        dstu7624xts.init(true, param);
        len = dstu7624xts.processBytes(plainText, 0, plainText.length, output, 0);
        dstu7624xts.doFinal(output, len);

        if (!Arrays.areEqual(output, expectedCipherText))
        {
            fail("Failed XTS encrypt test 5 - expected "
                + Hex.toHexString(expectedCipherText)
                + " got " + Hex.toHexString(output));
        }


        dstu7624xts.init(false, param);
        len = dstu7624xts.processBytes(expectedCipherText, 0, expectedCipherText.length, decrypted, 0);
        dstu7624xts.doFinal(decrypted, len);

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed XTS decrypt test 5 - expected "
                + Hex.toHexString(plainText)
                + " got " + Hex.toHexString(decrypted));
        }
    }

    private void GCMModeTests()
        throws Exception
    {
        //test 1
        byte[] key = Hex.decode("000102030405060708090A0B0C0D0E0F");

        byte[] iv = Hex.decode("101112131415161718191A1B1C1D1E1F");

        byte[] authText = Hex.decode("202122232425262728292A2B2C2D2E2F");

        byte[] plainText = Hex.decode("303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");

        byte[] expectedEncrypted = Hex.decode("B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51");

        byte[] expectedMac = Hex.decode("C8310571CD60F9584B45C1B4ECE179AF");

        byte[] expectedOutput = new byte[expectedEncrypted.length + expectedMac.length];
        System.arraycopy(expectedEncrypted, 0, expectedOutput, 0, expectedEncrypted.length);
        System.arraycopy(expectedMac, 0, expectedOutput, expectedEncrypted.length, expectedMac.length);

        byte[] mac = new byte[expectedMac.length];

        byte[] encrypted = new byte[expectedEncrypted.length + mac.length];

        byte[] decrypted = new byte[plainText.length + mac.length];

        System.arraycopy(expectedMac, 0, decrypted, plainText.length, mac.length);

        int len;

        AEADParameters parameters = new AEADParameters(new KeyParameter(key), 128, iv);

        KGCMBlockCipher dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(128));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);

        len = dstu7624gcm.processBytes(plainText, 0, plainText.length, encrypted, 0);
        dstu7624gcm.doFinal(encrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 1 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedOutput))
        {
            fail("Failed GCM/GMAC test 1 - expected encrypted: "
                + Hex.toHexString(expectedOutput)
                + " got encrypted: " + Hex.toHexString(encrypted));
        }


        dstu7624gcm.init(false, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);

        len = dstu7624gcm.processBytes(expectedOutput, 0, expectedOutput.length, decrypted, 0);
        dstu7624gcm.doFinal(decrypted, len);


        mac = dstu7624gcm.getMac();
        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 1 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //remove mac at the end of decrypted data
        byte[] tempDecrypted = new byte[plainText.length];
        System.arraycopy(decrypted, 0, tempDecrypted, 0, plainText.length);
        decrypted = tempDecrypted;


        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed GCM/GMAC test 1 - expected decrypted: "
                + Hex.toHexString(plainText)
                + " got decrypted: " + Hex.toHexString(decrypted));
        }

        //test 2
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        iv = Hex.decode("202122232425262728292A2B2C2D2E2F");

        authText = Hex.decode("303132333435363738393A3B3C3D3E3F");

        plainText = Hex.decode("505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F");

        expectedEncrypted = Hex.decode("FF83F27C6D4EA26101B1986235831406A297940D6C0E695596D612623E0E7CDC");

        expectedMac = Hex.decode("3C474281AFEAE4FD6D61E995258747AB");

        expectedOutput = new byte[expectedEncrypted.length + expectedMac.length];
        System.arraycopy(expectedEncrypted, 0, expectedOutput, 0, expectedEncrypted.length);
        System.arraycopy(expectedMac, 0, expectedOutput, expectedEncrypted.length, expectedMac.length);


        mac = new byte[expectedMac.length];

        encrypted = new byte[expectedEncrypted.length + mac.length];

        decrypted = new byte[plainText.length + mac.length];

        System.arraycopy(expectedMac, 0, decrypted, plainText.length, mac.length);

        parameters = new AEADParameters(new KeyParameter(key), 128, iv);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(128));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(plainText, 0, plainText.length, encrypted, 0);

        dstu7624gcm.doFinal(encrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 2 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedOutput))
        {
            fail("Failed GCM/GMAC test 2 - expected encrypted: "
                + Hex.toHexString(expectedOutput)
                + " got encrypted: " + Hex.toHexString(encrypted));
        }


        dstu7624gcm.init(false, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(expectedOutput, 0, expectedOutput.length, decrypted, 0);

        dstu7624gcm.doFinal(decrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 2 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //remove mac at the end of decrypted data
        tempDecrypted = new byte[plainText.length];
        System.arraycopy(decrypted, 0, tempDecrypted, 0, plainText.length);
        decrypted = tempDecrypted;

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed GCM/GMAC test 2 - expected decrypted: "
                + Hex.toHexString(plainText)
                + " got decrypted: " + Hex.toHexString(decrypted));
        }

        //test 3
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        iv = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        authText = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

        plainText = Hex.decode("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");

        expectedEncrypted = Hex.decode("7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE80");

        expectedMac = Hex.decode("1D61B0A3018F6B849CBA20AF1DDDA245");

        expectedOutput = new byte[expectedEncrypted.length + expectedMac.length];
        System.arraycopy(expectedEncrypted, 0, expectedOutput, 0, expectedEncrypted.length);
        System.arraycopy(expectedMac, 0, expectedOutput, expectedEncrypted.length, expectedMac.length);


        mac = new byte[expectedMac.length];

        encrypted = new byte[expectedEncrypted.length + mac.length];

        decrypted = new byte[plainText.length + mac.length];

        System.arraycopy(expectedMac, 0, decrypted, plainText.length, mac.length);


        parameters = new AEADParameters(new KeyParameter(key), 128, iv);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(256));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(plainText, 0, plainText.length, encrypted, 0);

        dstu7624gcm.doFinal(encrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 3 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedOutput))
        {
            fail("Failed GCM/GMAC test 3 - expected encrypted: "
                + Hex.toHexString(expectedOutput)
                + " got encrypted: " + Hex.toHexString(encrypted));
        }

        dstu7624gcm.init(false, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(expectedOutput, 0, expectedOutput.length, decrypted, 0);

        dstu7624gcm.doFinal(decrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 3 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //remove mac at the end of decrypted data
        tempDecrypted = new byte[plainText.length];
        System.arraycopy(decrypted, 0, tempDecrypted, 0, plainText.length);
        decrypted = tempDecrypted;

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed GCM/GMAC test 3 - expected decrypted: "
                + Hex.toHexString(plainText)
                + " got decrypted: " + Hex.toHexString(decrypted));
        }

        //test 4
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        iv = Hex.decode("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        authText = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

        plainText = Hex.decode("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");

        expectedEncrypted = Hex.decode("7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE80");

        expectedMac = Hex.decode("1D61B0A3018F6B849CBA20AF1DDDA245B1B296258AC0352A52D3F372E72224CE");

        expectedOutput = new byte[expectedEncrypted.length + expectedMac.length];
        System.arraycopy(expectedEncrypted, 0, expectedOutput, 0, expectedEncrypted.length);
        System.arraycopy(expectedMac, 0, expectedOutput, expectedEncrypted.length, expectedMac.length);


        mac = new byte[expectedMac.length];

        encrypted = new byte[expectedEncrypted.length + mac.length];

        decrypted = new byte[plainText.length + mac.length];

        System.arraycopy(expectedMac, 0, decrypted, plainText.length, mac.length);

        parameters = new AEADParameters(new KeyParameter(key), 256, iv);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(256));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(plainText, 0, plainText.length, encrypted, 0);

        dstu7624gcm.doFinal(encrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 4 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedOutput))
        {
            fail("Failed GCM/GMAC test 4 - expected encrypted: "
                + Hex.toHexString(expectedOutput)
                + " got encrypted: " + Hex.toHexString(encrypted));
        }


        dstu7624gcm.init(false, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(expectedOutput, 0, expectedOutput.length, decrypted, 0);

        dstu7624gcm.doFinal(decrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 4 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //remove mac at the end of decrypted data
        tempDecrypted = new byte[plainText.length];
        System.arraycopy(decrypted, 0, tempDecrypted, 0, plainText.length);
        decrypted = tempDecrypted;

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed GCM/GMAC test 4 - expected decrypted: "
                + Hex.toHexString(plainText)
                + " got decrypted: " + Hex.toHexString(decrypted));
        }

        //test 5
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        iv = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

        authText = Hex.decode("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");

        plainText = Hex.decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");

        expectedEncrypted = Hex.decode("3EBDB4584B5169A26FBEBA0295B4223F58D5D8A031F2950A1D7764FAB97BA058E9E2DAB90FF0C519AA88435155A71B7B53BB100F5D20AFFAC0552F5F2813DEE8");

        expectedMac = Hex.decode("8555FD3D9B02C2325ACA3CC9309D6B4B9AFC697D13BBBFF067198D5D86CB9820");

        expectedOutput = new byte[expectedEncrypted.length + expectedMac.length];
        System.arraycopy(expectedEncrypted, 0, expectedOutput, 0, expectedEncrypted.length);
        System.arraycopy(expectedMac, 0, expectedOutput, expectedEncrypted.length, expectedMac.length);


        mac = new byte[expectedMac.length];

        encrypted = new byte[expectedEncrypted.length + mac.length];

        decrypted = new byte[plainText.length + mac.length];

        System.arraycopy(expectedMac, 0, decrypted, plainText.length, mac.length);


        parameters = new AEADParameters(new KeyParameter(key), 256, iv);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(256));
        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(plainText, 0, plainText.length, encrypted, 0);

        dstu7624gcm.doFinal(encrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 5 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedOutput))
        {
            fail("Failed GCM/GMAC test 5 - expected encrypted: "
                + Hex.toHexString(expectedOutput)
                + " got encrypted: " + Hex.toHexString(encrypted));
        }


        dstu7624gcm.init(false, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(expectedOutput, 0, expectedOutput.length, decrypted, 0);

        dstu7624gcm.doFinal(decrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 5 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //remove mac at the end of decrypted data
        tempDecrypted = new byte[plainText.length];
        System.arraycopy(decrypted, 0, tempDecrypted, 0, plainText.length);
        decrypted = tempDecrypted;

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed GCM/GMAC test 5 - expected decrypted: "
                + Hex.toHexString(plainText)
                + " got decrypted: " + Hex.toHexString(decrypted));
        }

        //test 6
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        iv = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");

        authText = Hex.decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");

        plainText = Hex.decode("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");

        expectedEncrypted = Hex.decode("220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99");

        expectedMac = Hex.decode("78A77E5948F5DC05F551486FDBB44898C9AB1BD439D7519841AE31007C09E1B312E5EA5929F952F6A3EEF5CBEAEF262B8EC1884DFCF4BAAF7B5C9291A22489E1");

        expectedOutput = new byte[expectedEncrypted.length + expectedMac.length];
        System.arraycopy(expectedEncrypted, 0, expectedOutput, 0, expectedEncrypted.length);
        System.arraycopy(expectedMac, 0, expectedOutput, expectedEncrypted.length, expectedMac.length);


        mac = new byte[expectedMac.length];

        encrypted = new byte[expectedEncrypted.length + mac.length];

        decrypted = new byte[plainText.length + mac.length];

        System.arraycopy(expectedMac, 0, decrypted, plainText.length, mac.length);

        parameters = new AEADParameters(new KeyParameter(key), 512, iv);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(512));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(plainText, 0, plainText.length, encrypted, 0);

        dstu7624gcm.doFinal(encrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 6 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        if (!Arrays.areEqual(encrypted, expectedOutput))
        {
            fail("Failed GCM/GMAC test 6 - expected encrypted: "
                + Hex.toHexString(expectedOutput)
                + " got encrypted: " + Hex.toHexString(encrypted));
        }

        dstu7624gcm.init(false, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        len = dstu7624gcm.processBytes(expectedOutput, 0, expectedOutput.length, decrypted, 0);

        dstu7624gcm.doFinal(decrypted, len);

        mac = dstu7624gcm.getMac();

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 6 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //remove mac at the end of decrypted data
        tempDecrypted = new byte[plainText.length];
        System.arraycopy(decrypted, 0, tempDecrypted, 0, plainText.length);
        decrypted = tempDecrypted;

        if (!Arrays.areEqual(decrypted, plainText))
        {
            fail("Failed GCM/GMAC test 6 - expected decrypted: "
                + Hex.toHexString(plainText)
                + " got decrypted: " + Hex.toHexString(decrypted));
        }

        /* Testing mac producing without encryption */
        //test 7
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        authText = Hex.decode("303132333435363738393A3B3C3D3E3F");

        expectedMac = Hex.decode("5AE309EE80B583C6523397ADCB5704C4");

        mac = new byte[expectedMac.length];

        parameters = new AEADParameters(new KeyParameter(key), 128, new byte[16]);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(128));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        dstu7624gcm.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 7 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //test 8
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        authText = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

        expectedMac = Hex.decode("FF48B56F2C26CC484B8F5952D7B3E1FE");

        mac = new byte[expectedMac.length];

        parameters = new AEADParameters(new KeyParameter(key), 128, new byte[16]);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(256));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        dstu7624gcm.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 8 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //test 9
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        authText = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");

        expectedMac = Hex.decode("FF48B56F2C26CC484B8F5952D7B3E1FE69577701C50BE96517B33921E44634CD");

        mac = new byte[expectedMac.length];

        parameters = new AEADParameters(new KeyParameter(key), 256, new byte[32]);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(256));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        dstu7624gcm.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 9 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //test 10
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        authText = Hex.decode("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");

        expectedMac = Hex.decode("96F61FA0FDE92883C5041D748F9AE91F3A0A50415BFA1466855340A5714DC01F");

        mac = new byte[expectedMac.length];

        parameters = new AEADParameters(new KeyParameter(key), 256, new byte[32]);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(256));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        dstu7624gcm.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 10 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        //test 11
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        authText = Hex.decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");

        expectedMac = Hex.decode("897C32E05E776FD988C5171FE70BB72949172E514E3308A871BA5BD898FB6EBD6E3897D2D55697D90D6428216C08052E3A5E7D4626F4DBBF1546CE21637357A3");

        mac = new byte[expectedMac.length];

        parameters = new AEADParameters(new KeyParameter(key), 512, new byte[32]);

        dstu7624gcm = new KGCMBlockCipher(new DSTU7624Engine(512));

        dstu7624gcm.init(true, parameters);
        dstu7624gcm.processAADBytes(authText, 0, authText.length);
        dstu7624gcm.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 11 - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }

        doFinalTest(new KGCMBlockCipher(new DSTU7624Engine(512)), key, new byte[32], authText, null, expectedMac);

        //test 11 - as KGMac
        key = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

        authText = Hex.decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");

        expectedMac = Hex.decode("897C32E05E776FD988C5171FE70BB72949172E514E3308A871BA5BD898FB6EBD6E3897D2D55697D90D6428216C08052E3A5E7D4626F4DBBF1546CE21637357A3");

        mac = new byte[expectedMac.length];

        KGMac dstuGmac = new KGMac(new KGCMBlockCipher(new DSTU7624Engine(512)));

        dstuGmac.init(new ParametersWithIV(new KeyParameter(key), new byte[32]));

        dstuGmac.update(authText, 0, authText.length);

        dstuGmac.doFinal(mac, 0);

        if (!Arrays.areEqual(mac, expectedMac))
        {
            fail("Failed GCM/GMAC test 11 (mac) - expected mac: "
                + Hex.toHexString(expectedMac)
                + " got mac: " + Hex.toHexString(mac));
        }
    }

    private void doFinalTest(AEADBlockCipher cipher, byte[] key, byte[] iv, byte[] authText, byte[] input, byte[] expected)
        throws Exception
    {
        byte[] output = new byte[expected.length];

        AEADParameters parameters = new AEADParameters(new KeyParameter(key), cipher.getUnderlyingCipher().getBlockSize() * 8, iv);

        cipher.init(true, parameters);
        cipher.processAADBytes(authText, 0, authText.length);

        int off = 0;
        if (input != null)
        {
            off = cipher.processBytes(input, 0, input.length, output, 0);
        }

        cipher.doFinal(output, off);

        if (!Arrays.areEqual(output, expected))
        {
            System.err.println(Hex.toHexString(output));
            System.err.println(Hex.toHexString(expected));
            fail("Failed doFinal test - init: " + cipher.getAlgorithmName());
        }

        cipher.processAADBytes(authText, 0, authText.length);

        off = 0;
        if (input != null)
        {
            off = cipher.processBytes(input, 0, input.length, output, 0);
        }

        cipher.doFinal(output, off);

        if (!Arrays.areEqual(output, expected))
        {
            fail("Failed doFinal test - after: " + cipher.getAlgorithmName());
        }
    }
}
