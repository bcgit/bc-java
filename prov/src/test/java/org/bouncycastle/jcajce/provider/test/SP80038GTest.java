package org.bouncycastle.jcajce.provider.test;

import java.security.GeneralSecurityException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AlphabetMapper;
import org.bouncycastle.crypto.util.BasicAlphabetMapper;
import org.bouncycastle.jcajce.spec.FPEParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SP80038GTest
    extends TestCase
{
    // FF1 Tests
    String ff1_alphabet_1 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    String[][] ff1_alphabet_1_tests = {
        // tweak, pt, key
        {"", "iTwLK4", "236B76B3FDF9CBA78EDB7BC730AA5B39","mmTasG"},
        {"2F51E5D59488D510AEA456CD417718E3", "ZyYCiDJ0ioosItgaxXRq9yhW", "9324AA7DE3741E56CF645E2637E35A1D","khcC1Ke64gP1war6Q9zu9SJG"},
        {"F66612F14F0D8739203E", "AtxMqnP3mXzKF", "9BDFCDFA503E4CC611D43C1F1FD1AF7A","fjaV934e8Onzo"},
        {"E7C2580A4749", "72PT7muromMDY3", "D641EAA6E3AECD442ABE8A8A0CCD8D98","mdHbTLMlG0AuUh"},
        {"80090227B0", "LkljZAYwCMg8PPpGZKS", "AA2B43695693682BBB0D75FEB5D2AE5D","jCaadHhLuMHgKnWTWo6"},
        {"E7BCC93E147CD87C6ABD875F", "M5qNoOKl9wtHOZcUGuKGl", "658DBE84FFFD3FB0B467BD494716A389","fWFLuaTkrIcS7SKamjnif"},
        {"E26F0CF77F900E309F7E23", "1Fka2x1jPZM", "A9BB6084FB2C4D953ED0D7664E297F00","j0hfWHfbjtR"},
        {"A7", "g4Gd2y", "693358783292A53684F2C61B667271ED","kEf93S"},
        {"ECFC67AA", "YryCEUazh2qOa1Xpn", "67CA66410765DFCF32E509421FB33758","BnKkjx9qF310Xu7TA"},
        {"ED52", "yFbVz60ugnq6y78KLf7F", "A09EB6F2E6368F978E82A134B546A142","VLWCLN7IyPPLltMOd1vQ"},
        {"F74132FF7072D8", "EUueCSoE6h", "62A98D0070E3E55B671A967C3D9D9767","puF78lA1b8"},
        {"00F7CD7917DCEA72BA", "lwtmPkqP", "2D463A97016DFC0A921EC8E46A16A518","tNuNthtF"},
        {"BC5F62", "GIRgzzrboCoqywF", "64BFB746D06FBF5EEB281A77B866045B","LEZLZZBhEWET92g"},
        {"", "CfCxoaKNWoVHO9IjXKjKnv", "5B9A45BA73F2FC029926B8D535A79878","3OiON9S9g1lsobmzFL9IDF"},
        {"25772FEC1082D470", "8NR9WrfjM", "EB9A93FF8AB18F65FA91F301E6BC008C","NwFSccVY3"},
        {"411A6494AAAC9FBC2D", "T2h0UCGKlMux2I6m", "A2F43410345DC5E5C7ED4BD385B331A5","V3B594LYtotBRQ3j"},
        {"2AD8CAB86706", "nnLrG3O", "C841BBE822C3E7BEA4F69DD42E567D6C","lXQJuNe"},
        {"", "NOwJT9flDhbVeohveLjnFfT", "137874621536242A7CABD8CFBCD9BD4B","5W5yW0OaUzDxGiyoDJulYzV"},
        {"C8", "STgCiabmxon9p2pNod", "895E47F18CDFE73CF1C23B9D33505799","UpZ7aLkxYZ7oqu2xcs"},
        {"72EB86EBD34B98", "rgCZlyWGKYhQ", "4004E4CB30ACD801A6C21B433ADF46CB","PkEghx5N7Chd"},
        {"5B3AEA4CA61101B4", "bv1myl91ae9dDkwuKYclXAaa", "C8A1C281AC16177089D6C599861CF427","fSIZfkTKO1aklEOO1sNap0Tq"},
        {"45CC", "h1x9H8BV59ITQwUE", "71F9CFD5502735B5C68D02F8E8776BEB","v0Ey3lUDIDosWohc"},
        {"C39B126F", "g21McrCLkEcB7", "E56C38B4F9F98EF775342C2048A6A799","NaFndzsRlqNrj"},
        {"94409527E3", "DFrc60FnEG4RgVdhC39q", "ACF071585A7240C1BB6272088DF10634","mVHPO5Xs88V0jePKqKA1"},
        {"BDC1BA", "uiQq1K57vMH20YECaf", "3C16616C39C2BE262E1BA70C2F5EADDB","cTLHZvSM8WlKUmvDGO"}
    };

    String ff1_alphabet_2 = "0123456789";
    String[][] ff1_alphabet_2_tests = {
        {"", "941511", "B76C5A89AA2251C6EC54637DBD664B51","732619"},
        {"8FBC94F4B2C99A8259D38F5BAC64BE52", "1232039186865318286011911779189", "4FB391936BBC92B86DAC47A47D2CAEC9","4592871033297781572090499660092"},
        {"", "25630389453998269", "74C42820E7F9247198E04A9B37242884","83536783621072273"},
        {"0F656FE51769CD", "8094398109190408843335", "31CA8C5E008FB8223CAB5504D064151A","7658928649613018288620"},
        {"6EC7EADFBD961D2E076E", "6431000", "4CA05916E845CF1912709076B0B42605","5139463"},
        {"4294FFA0C7442E95", "99751922499737565065562", "995082112CC7A6B7133B94C6F9B54157","17534502466636251616850"},
        {"5416", "26420939498", "EED416A3BC51EF25A9D68F43863EC1D4","94241565426"},
        {"95FFD7835AD6DC432F", "5852149426392", "F6FC89EFC5B2B16809653F0C75A94426","3948602854358"},
        {"72D483", "52384999066127573799", "C52A3B73C917A1AF91DD6049C6713A19","17241163715017068578"},
        {"23", "7781630609983249598602441884", "EAE126C9195BA2776AAF3E69D9423D5B","8226191406083149435763280508"},
        {"59C179AFAA5D34D9DFFE32", "594169", "DA4E2000A2F5106E7D6A3BCE6B23D276","277594"},
        {"709A69CA70", "49231776", "D97A6102FE40A83F6309D826A920BCBB","92051520"},
        {"9E74E427B902F80E04F255DE", "1736401597114933818", "69870E228CA346837326791BBDDFAA6D","1815362759959228402"},
        {"533FD4A4E9FA", "69497020046931960918249189", "5A502BA79B960C035BE742FE78EB1471","18476323752557799524272071"},
        {"23209162", "0869547388", "63979FD2C82EE1E08AE95404CB600E63","0130712927"},
        {"B316", "1683394831336669741338373838617", "F067970A0689CEFE66BA0556229E4E85","4257089221362547126689424193294"},
        {"2483E9BE54", "533074664397097457310570205393", "3195D5A0A2624BFB4E12192ABC0ECEFF","346963017066801134013790241009"},
        {"", "472471564", "A218FDA782FB45763F28DCFCDF7556E4","153477820"},
        {"1600585E3C5986F3", "32583897681638", "9B82F75D7B8D20B9ADCC122E7F7725DB","79887347386178"},
        {"49585B914C5123B373", "593511424668614769644849354", "C333A8F6940C9A59E32F0733C71A1885","790968331551503710851072211"},
        {"C248E5D8", "707346889590178007053", "6562A8A9557C4274C21AE7F6DA5C8F24","067832504510782897805"},
        {"8387A7653311", "053015318497", "C01D0C303618720767DF0BC78C804D9C","343962035252"},
        {"B6AD7B9B915B38", "993507394067891", "0CEF08E8CA4747BC08EBEB6E26D20D02","605327487391309"},
        {"DE", "0810942310565223", "1124CF3E4BD76C2A55A4970B36036928","3773229235760461"},
        {"1A93FD", "37270593298489037293320078931", "24320B4097F1AA595B924647713CA4AC", "37543918372406027841182838238"},
    };

    String ff3_1_alphabet_1 = "0123456789";
    String[][] ff3_1_alphabet_1_tests = {
        {"67C7CBF6042FFF", "659776", "1A7F85D44F1979EC49C79845A6598B76","098288"},
        {"5423F27B4017B7", "4444944989", "D02225AF674E40AE894C4DE08DA000B3","9427514963"},
        {"E7185946C94478", "86865094", "3BAC1ED3C66117EADC8DF3136CF5524F","89918178"},
        {"D0A6619C11A158", "9072428", "0B135CB23061CE100320CDAA60B85AC2","5894529"},
        {"A2E9D0C9C85F25", "040382", "C1B926F9E3AB4FCE8604E7DB72CA6110","811762"},
        {"FB835576867705", "610086897", "056F4C0B5D73B4AB90358134F45D328C","720637716"},
        {"AE775D88ADF6A9", "5833034655", "08436C1438245C79376EF7BD33C92C55","6455353822"},
        {"6BEE40A9F6AB4D", "039365366", "78D15FB9D331DC144CDE51419E707EA0","384151042"},
        {"9BDF25A3DFB17C", "935230", "71E8AB4FE012CAECCA3CC3E9C95E1DA0","219915"},
        {"66A22895B93E81", "8304333", "E8B59438F67C62101A4C312E65A5A187","1699146"},
        {"2A7A462D949DD2", "0163530805", "AA7DB8044C3148F2C9337B75F1C495D6","0011297714"},
        {"9473BF859BDB8B", "01087821", "BD7FDDF9B0B2E52CDA683CA5F600DFF0","22932374"},
        {"D57D9EC489FF05", "743163", "B3A3AB75A0C048B9AE9D9FA41FCEDE37","517838"},
        {"D9E480BFC17F12", "8001487", "89581E1C3F259CAB5F03877CD9333C32","4040353"},
        {"2C04E837059906", "74097913", "A62E267CA06125B77DE93A71431F087D","00000261"},
        {"32B3B5C2086789", "273890663", "40DDE58FA4C66A1C301B4E4ED881A1B7","244541620"},
        {"6D9EDA3BFAF9C6", "2185011854", "F0843B0C5DE8F9EB9ECC10E71F712189","2134186361"},
        {"0B4F11B2808BB4", "960697", "79F1EC7A3116E2CEBD56EB7A8C2EAFAB","978180"},
        {"D6C4F2C80B5937", "0648611508", "C6CC2DF1F219A244AD86AED7BE6E36C7","3281035514"},
        {"92F2E385E1BFF3", "55774183", "AA78E43041509678DEAF6A8E6D02A4EC","94109636"},
        {"147327D5BEBA88", "7837803", "D94DA0A8A80E10C00D0BCE6C36092F4F","3287773"},
        {"2F2C22D1838A5E", "280645", "F726214B45706F67737DC7E77B91D98C","017364"},
        {"AC72FFC00575C1", "272547558", "03E7FBA53C1054F172916212F9FFE1D7","469385749"},
        {"79B5F8D5767B1A", "4261219151", "CC94EA01C67002C097AD445118EEFEC5","1299273759"},
        {"BAE22A67A706E3", "814522578", "1EA898816D747EC3A07E31A42E71AB3D","857110537"}
    };

    String ff3_1_alphabet_2 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    String[][] ff3_1_alphabet_2_tests = {
        {"2E7FD784D949A1", "pQGE0r", "E750192D456E4C14CA647B510A52F185","VtIJyP"},
        {"441ED3F0D3EE81", "GahgItA0D8VHRhLr2vOVCuCQ", "5C47180DE6D410273E8817F5463E0269","yKUycnMu0F9eqkRll2B5L9G5"},
        {"7AF00BDF5930E0", "aL9zoeV", "7EFB6FDD245F96D35778033FF05B17C7","OMWOxES"},
        {"E4442411B0218E", "r8hBeIitT2gtmldegSrFa7", "D2AE6D19D8920FDBA01B9F135D529039","lbJtnOeL3UlOT1duLl25Ip"},
        {"2336EAE72F3B4B", "fKPmqCyt5p", "07F65AB7931A88E8AA3482F8739827BA","98W484eRYy"},
        {"84B7FBDA0A3C8B", "kHxHj1qVIDZA", "66FD18B39538CE5B9CAE58008B7DCD51","FMs7tjq1uzWv"},
        {"D763AF168AB303", "9oiz8GQxqn9p6tvj42wvQY2", "5DBD948D229FCDDFFFB6B8E3019104F1","egfNbG0WODcKrGsR7YCiOjT"},
        {"DC465143E387AB", "L2h9THkhBkb7uvCVctjeZ", "05ABBA0D70AABE2B69500BDA5C876C96","6KQbOt3J1gvREytEJI7d1"},
        {"BA9A48AE6FA9E8", "M2MvNb24SrGKpcT", "A53609E37C390833D24F538E7E91DDB1","qMfWhbikGY4HdN9"},
        {"159DE043249FF3", "qUG7pFiX2RiBw", "76B3C253E9ED8D20B4328010271D6955","Boh2pLMysCq3Z"},
        {"2A311736388386", "WV3B6ec3517imaFUU3t", "8FB4EB42CA589F62FA1BFB7594243047","y3L8PRUtbaNgzvCLytX"},
        {"B21FC28499D46F", "E3c9Zqb4Z", "7E119D345C253BE799BF4DF735655DDD","DZmcYFsSU"},
        {"2DF752065365D1", "VQE39cLXzFd6emTB8", "53759E8460DD4B46BD1DAEECF8D0194B","1eIZ43IRqKXil6FLI"},
        {"FB35BC8AECA8A2", "U0FZwfxnXzXnqIuK5Q7sGHUX", "D9FE3E8D4302464153FF27DDBB816F8D","61SUhnusflY2batTvd04AKhB"},
        {"71E06B5A4ACC69", "cuDf8JGHyy8WmrDh", "30BFE56AC6F8D6B2FD440FBB78B62323","TcX9qqUbQK7m6XLd"},
        {"5C05AA601D387A", "9WtNZGEoPD1A4eeslb", "D5E5FAA65F949DD472817518A408BB4B","eNnxHetdpAGD2Q4ics"},
        {"6188DCBF1AAE16", "A9ZZMNjM2YA", "E9C94107BB671B01DBCA010D4792C8C3","qXf9KDmjCie"},
        {"3268638C286FD4", "4KFHSP", "B04FF77A5C75D09C7E1CF0499983B12B","8b0W2e"},
        {"6195983FAD66D8", "sqhpOScWraLAwI", "80C9860235506BEADE45229A276DC21E","UBupQZwbAVqDkv"},
        {"DCE735C1B8C248", "uRMl3HFqkQrq7QVowU9l", "A52150054AB93AB0F6E5A12DFCB7E271","d5jHMrqorMEyAm1IZN2q"},
        {"3832057786F946", "VWx3wDoO", "C1F02DA2A7D8B821D2BDE1F8E67A9D20","aXlHdjAZ"},
        {"3A942449CB7C62", "mQGs6ptG3OJlV1UfeSxJhbn", "F6D10EC8D864EE7115D183DB039B5FCA","h0bwjcc8iIHVvXa0Hu6Vw6v"},
        {"7F64262731A953", "6M4Ar2NqibTHgv38X", "E7C702C22D8755B7ACD2638B7F26D06A","abLAgEsLKmciQoF7X"},
        {"8EBF33D978EF3C", "rUsHWyn1m0ccgVIk6cM", "742F66DA00893DB30016C43FA0ED64A4","q1ixOcnICbfdpQmGEXW"},
        {"153E68A504DD02", "gRF2VlclPDIO7G", "13496D4317B2A9EAB2EFBDE9DC826D7C","qAySYAClwXeYhW"}
    };
    
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static class FFSample
    {
        private final int radix;
        private final byte[] key;
        private final byte[] plaintext;
        private final byte[] ciphertext;
        private final byte[] tweak;

        public static FFSample from(int radix, String hexKey, String asciiPT, String asciiCT, String hexTweak)
        {
            return new FFSample(radix, fromHex(hexKey), fromAscii(radix, asciiPT), fromAscii(radix, asciiCT), fromHex(hexTweak));
        }

        private static byte fromAlphaNumeric(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return (byte)(c - '0');
            }
            else if (c >= 'a' && c <= 'z')
            {
                return (byte)(10 + (c - 'a'));
            }
            else if (c >= 'A' && c <= 'Z')
            {
                return (byte)(36 + (c - 'A'));
            }
            else
            {
                throw new IllegalArgumentException();
            }
        }

        private static byte[] fromAscii(int radix, String ascii)
        {
            byte[] result = new byte[ascii.length()];
            for (int i = 0; i < result.length; ++i)
            {
                result[i] = fromAlphaNumeric(ascii.charAt(i));
                if (result[i] < 0 || result[i] >= radix)
                {
                    throw new IllegalArgumentException();
                }
            }
            return result;
        }

        private static byte[] fromHex(String hex)
        {
            return Hex.decode(hex);
        }

        private FFSample(int radix, byte[] key, byte[] plaintext, byte[] ciphertext, byte[] tweak)
        {
            this.radix = radix;
            this.key = key;
            this.plaintext = plaintext;
            this.ciphertext = ciphertext;
            this.tweak = tweak;
        }

        public byte[] getCiphertext()
        {
            return ciphertext;
        }

        public byte[] getKey()
        {
            return key;
        }

        public byte[] getPlaintext()
        {
            return plaintext;
        }

        public int getRadix()
        {
            return radix;
        }

        public byte[] getTweak()
        {
            return tweak;
        }
    }

    private static FFSample[] ff1Samples = new FFSample[]
    {
        // FF1-AES128
        FFSample.from(10, "2B7E151628AED2A6ABF7158809CF4F3C", "0123456789", "2433477484", ""),
        FFSample.from(10, "2B7E151628AED2A6ABF7158809CF4F3C", "0123456789", "6124200773", "39383736353433323130"),
        FFSample.from(36, "2B7E151628AED2A6ABF7158809CF4F3C", "0123456789abcdefghi", "a9tv40mll9kdu509eum", "3737373770717273373737"),

        // FF1-AES192
        FFSample.from(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "0123456789", "2830668132", ""),
        FFSample.from(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "0123456789", "2496655549", "39383736353433323130"),
        FFSample.from(36, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "0123456789abcdefghi", "xbj3kv35jrawxv32ysr", "3737373770717273373737"),

        // FF1-AES256
        FFSample.from(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "0123456789", "6657667009", ""),
        FFSample.from(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "0123456789", "1001623463", "39383736353433323130"),
        FFSample.from(36, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "0123456789abcdefghi", "xs8a0azh2avyalyzuwd", "3737373770717273373737"),
    };

    private static FFSample[] ff3_1Samples = new FFSample[]
    {
        // FF3_1-AES128
        FFSample.from(10, "7894F6CA9AFD070207889FDE082C53FA", "679635", "008662", "42B09446564534"),
        FFSample.from(10, "616158DE404DEE451D70F62CC9061FD8", "850388266", "536654352", "2F43F21EB28D47"),
        FFSample.from(10, "2ACF5B28369F8619F64AB73D4D4E78DF", "1027683234", "2953753300", "85AC0E3BEF39D6"),
        FFSample.from(10, "0BF0DF9B9080F96610586FD447EEC73D", "9305179131", "5344105124", "176C217004D2E5"),
        FFSample.from(36, "F98C49A9F11BE224BDB67DB22AEC2A31", "j7q1zysej7lcxg1z1oo5yn2c", "ffxcw4c0mdbkzvkp75f7lr5p", "7AF682A9DCB147"),
        FFSample.from(62, "7793833CE891B496381BD5B882F77EA1", "YbpT3hDo0J9xwCQ5qUWt93iv", "dDEYxViK56lGbV1WdZTPTe4w", "C58797C2580174"),

//        // FF3_1-AES192
        FFSample.from(10, "F89B050F6E4DB61F984E0C600CF4F29181B89DF2748F77A8", "0986735492", "1007137594", "ABF2A1E789C0EF"),
//        FFSample.from(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "890121234567890000", "961610514491424446", "9A768A92F60E12D8"),
//        FFSample.from(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "89012123456789000000789000000", "53048884065350204541786380807", "D8E7920AFA330A73"),
//        FFSample.from(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "89012123456789000000789000000", "98083802678820389295041483512", "0000000000000000"),
//        FFSample.from(26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "0123456789abcdefghi", "i0ihe2jfj7a9opf9p88", "9A768A92F60E12D8"),
//
//        // FF3_1-AES256
        FFSample.from(10, "1A58964B681384806A5A7639915ED0BE837C9C50C150AFD8F73445C0438CACF3", "4752683571", "2234571788", "CE3EBD69454984"),
//        FFSample.from(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "890121234567890000", "504149865578056140", "9A768A92F60E12D8"),
//        FFSample.from(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "89012123456789000000789000000", "04344343235792599165734622699", "D8E7920AFA330A73"),
//        FFSample.from(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "89012123456789000000789000000", "30859239999374053872365555822", "0000000000000000"),
//        FFSample.from(26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "0123456789abcdefghi", "p0b2godfja9bhb7bk38", "9A768A92F60E12D8"),
    };

    public void testFF1()
        throws Exception
    {
        for (int i = 0; i < ff1Samples.length; ++i)
        {
            testFF1Sample(ff1Samples[i]);
        }
    }

    public void testFF1Vectors()
        throws Exception
    {
        for (int i = 0; i < ff1_alphabet_1_tests.length; ++i)
        {
            testFF1Vector(ff1_alphabet_1, ff1_alphabet_1_tests[i]);
        }
        
        for (int i = 0; i < ff1_alphabet_2_tests.length; ++i)
        {
            testFF1Vector(ff1_alphabet_2, ff1_alphabet_2_tests[i]);
        }
    }

    public void testFF3_1()
        throws Exception
    {
        for (int i = 0; i < ff3_1Samples.length; ++i)
        {
            testFF3Sample(ff3_1Samples[i]);
        }
    }

    public void testFF3_1Vectors()
        throws Exception
    {
        for (int i = 0; i < ff3_1_alphabet_1_tests.length; ++i)
        {
            testFF3_1Vector(ff3_1_alphabet_1, ff3_1_alphabet_1_tests[i]);
        }

        for (int i = 0; i < ff3_1_alphabet_2_tests.length; ++i)
        {
            testFF3_1Vector(ff3_1_alphabet_2, ff3_1_alphabet_2_tests[i]);
        }
    }

    private void testFF1Sample(FFSample ff1)
        throws Exception
    {
        Cipher in, out;

        in = Cipher.getInstance("AES/FF1/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(ff1.getKey(), "AES"), new FPEParameterSpec(ff1.getRadix(), ff1.getTweak()));

        byte[] enc = in.doFinal(ff1.getPlaintext());

        assertTrue(Arrays.areEqual(ff1.getCiphertext(), enc));

        out = Cipher.getInstance("AES/FF1/NoPadding", "BC");

        out.init(Cipher.DECRYPT_MODE, new SecretKeySpec(ff1.getKey(), "AES"), new FPEParameterSpec(ff1.getRadix(), ff1.getTweak()));

        byte[] dec = out.doFinal(ff1.getCiphertext());

        assertTrue(Arrays.areEqual(ff1.getPlaintext(), dec));
    }

    private void testFF1Vector(String alphabet, String[] v)
        throws Exception
    {
        Cipher in, out;
        SecretKey key = new SecretKeySpec(Hex.decode(v[2]), "AES");

        in = Cipher.getInstance("AES/FF1/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new FPEParameterSpec(alphabet.length(), Hex.decode(v[0])));

        AlphabetMapper mapper = new BasicAlphabetMapper(alphabet);

        byte[] pt = mapper.convertToIndexes(v[1].toCharArray());
        byte[] enc = in.doFinal(pt);

        if (v.length == 4)
        {
            assertTrue(Arrays.areEqual(v[3].toCharArray(), mapper.convertToChars(enc)));
        }
        
        out = Cipher.getInstance("AES/FF1/NoPadding", "BC");

        out.init(Cipher.DECRYPT_MODE, key, new FPEParameterSpec(alphabet.length(), Hex.decode(v[0])));

        byte[] dec = out.doFinal(enc);

        assertTrue(Arrays.areEqual(v[1].toCharArray(), mapper.convertToChars(dec)));
    }

    private void testFF3Sample(FFSample ff3)
        throws Exception
    {
        Cipher in, out;

        in = Cipher.getInstance("AES/FF3-1/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(ff3.getKey(), "AES"), new FPEParameterSpec(ff3.getRadix(), ff3.getTweak()));

        byte[] enc = in.doFinal(ff3.getPlaintext());

        assertTrue(Arrays.areEqual(ff3.getCiphertext(), enc));

        out = Cipher.getInstance("AES/FF3-1/NoPadding", "BC");

        out.init(Cipher.DECRYPT_MODE, new SecretKeySpec(ff3.getKey(), "AES"), new FPEParameterSpec(ff3.getRadix(), ff3.getTweak()));

        byte[] dec = out.doFinal(ff3.getCiphertext());

        assertTrue(Arrays.areEqual(ff3.getPlaintext(), dec));
    }

    private void testFF3_1Vector(String alphabet, String[] v)
        throws Exception
    {
        Cipher in, out;
        SecretKey key = new SecretKeySpec(Hex.decode(v[2]), "AES");

        in = Cipher.getInstance("AES/FF3-1/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new FPEParameterSpec(alphabet.length(), Hex.decode(v[0])));

        AlphabetMapper mapper = new BasicAlphabetMapper(alphabet);

        byte[] pt = mapper.convertToIndexes(v[1].toCharArray());
        byte[] enc = in.doFinal(pt);

        if (v.length == 4)
        {
            assertTrue(Arrays.areEqual(v[3].toCharArray(), mapper.convertToChars(enc)));
        }

        out = Cipher.getInstance("AES/FF3-1/NoPadding", "BC");

        out.init(Cipher.DECRYPT_MODE, key, new FPEParameterSpec(alphabet.length(), Hex.decode(v[0])));

        byte[] dec = out.doFinal(enc);

        assertTrue(Arrays.areEqual(v[1].toCharArray(), mapper.convertToChars(dec)));
    }

    public void testUtility()
        throws Exception
    {
        FPECharEncryptor fpeEnc = new FPECharEncryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), "0123456789".toCharArray());

        String s1 = "01234567890123456";
        char[] encrypted = fpeEnc.process(s1.toCharArray());

        FPECharDecryptor fpeDec = new FPECharDecryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), "0123456789".toCharArray());
        char[] decrypted = fpeDec.process(encrypted);

        assertEquals(s1, new String(decrypted));

        String bigAlpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "\u0400\u0401\u0402\u0403\u0404\u0405\u0406\u0407\u0408\u0409\u040a\u040b\u040c\u040d\u040e\u040f"
            + "\u0410\u0411\u0412\u0413\u0414\u0415\u0416\u0417\u0418\u0419\u041a\u041b\u041c\u041d\u041e\u041f"
            + "\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427\u0428\u0429\u042a\u042b\u042c\u042d\u042e\u042f"
            + "\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437\u0438\u0439\u043a\u043b\u043c\u043d\u043e\u043f"
            + "\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447\u0448\u0449\u044a\u044b\u044c\u044d\u044e\u044f"
            + "\u0450\u0451\u0452\u0453\u0454\u0455\u0456\u0457\u0458\u0459\u045a\u045b\u045c\u045d\u045e\u045f"
            + "\u0210\u0211\u0212\u0213\u0214\u0215\u0216\u0217\u0218\u0219\u021a\u021b\u021c\u021d\u021e\u021f"
            + "\u0220\u0221\u0222\u0223\u0224\u0225\u0226\u0227\u0228\u0229\u022a\u022b\u022c\u022d\u022e\u022f"
            + "\u0230\u0231\u0232\u0233\u0234\u0235\u0236\u0237\u0238\u0239\u023a\u023b\u023c\u023d\u023e\u023f"
            + "\u0240\u0241\u0242\u0243\u0244\u0245\u0246\u0247\u0248\u0249\u024a\u024b\u024c\u024d\u024e\u024f"
            + "\u2210\u2211\u2212\u2213\u2214\u2215\u2216\u2217\u2218\u2219\u221a\u221b\u221c\u221d\u221e\u221f"
            + "\u2220\u2221\u2222\u2223\u2224\u2225\u2226\u2227\u2228\u2229\u222a\u222b\u222c\u222d\u222e\u222f"
            + "\u2230\u2231\u2232\u2233\u2234\u2235\u2236\u2237\u2238\u2239\u223a\u223b\u223c\u223d\u223e\u223f"
            + "\u2240\u2241\u2242\u2243\u2244\u2245\u2246\u2247\u2248\u2249\u224a\u224b\u224c\u224d\u224e\u224f";

        fpeEnc = new FPECharEncryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), bigAlpha.toCharArray());

        s1 = "01234567890123456\u0222\u0223\u0224\u0225\u0226abcdefg\u224f";

        encrypted = fpeEnc.process(s1.toCharArray());
      
        fpeDec = new FPECharDecryptor(new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES"), bigAlpha.toCharArray());
        decrypted = fpeDec.process(encrypted);

        assertEquals(s1, new String(decrypted));
    }

    public void testCipherReuseThroughDoFinal_Encrypt()
        throws Exception
    {
        FPEParameterSpec parameterSpec = new FPEParameterSpec(100, new byte[0]);
        SecretKey aesKey = new SecretKeySpec(new byte[32], "AES");

        Cipher multipleOperationsCipher = Cipher.getInstance("AES/FF1/NoPadding", "BC");
        multipleOperationsCipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);

        Cipher singleOperationCipher = Cipher.getInstance("AES/FF1/NoPadding", "BC");
        singleOperationCipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);

        multipleOperationsCipher.doFinal(new byte[] { 84, 13, 92, 49 });
        byte[] ciphertext1 = multipleOperationsCipher.doFinal(new byte[] { 99, 0, 27, 3 });

        byte[] ciphertext2 = singleOperationCipher.doFinal(new byte[] { 99, 0, 27, 3 });

        assertTrue(Arrays.areEqual(ciphertext1, ciphertext2));
    }

    public void testCipherReuseThroughDoFinal_Decrypt()
        throws Exception
    {
        FPEParameterSpec parameterSpec = new FPEParameterSpec(100, new byte[0]);
        SecretKey aesKey = new SecretKeySpec(new byte[32], "AES");

        Cipher multipleOperationsCipher = Cipher.getInstance("AES/FF1/NoPadding", "BC");
        multipleOperationsCipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec);

        Cipher singleOperationCipher = Cipher.getInstance("AES/FF1/NoPadding", "BC");
        singleOperationCipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec);

        multipleOperationsCipher.doFinal(new byte[] { 84, 13, 92, 49 });
        byte[] ciphertext1 = multipleOperationsCipher.doFinal(new byte[] { 99, 0, 27, 3 });

        byte[] ciphertext2 = singleOperationCipher.doFinal(new byte[] { 99, 0, 27, 3 });

        assertTrue(Arrays.areEqual(ciphertext1, ciphertext2));
    }

    public class FPECharEncryptor
    {
        private Cipher cipher;
        private AlphabetMapper alphabetMapper;

        public FPECharEncryptor(SecretKey key, char[] alphabet)
            throws GeneralSecurityException
        {
            this(key, new byte[0], alphabet);
        }

        public FPECharEncryptor(SecretKey key, byte[] tweak, char[] alphabet)
            throws GeneralSecurityException
        {
            alphabetMapper = new BasicAlphabetMapper(alphabet);
            cipher = Cipher.getInstance(key.getAlgorithm() + "/FF1/NoPadding", "BC");

            cipher.init(Cipher.ENCRYPT_MODE, key, new FPEParameterSpec(alphabet.length, tweak));
        }

        public char[] process(char[] input)
            throws GeneralSecurityException
        {
            byte[] encData = cipher.doFinal(alphabetMapper.convertToIndexes(input));

            return alphabetMapper.convertToChars(encData);
        }
    }

    public class FPECharDecryptor
    {
        private Cipher cipher;
        private AlphabetMapper alphabetMapper;

        public FPECharDecryptor(SecretKey key, char[] alphabet)
            throws GeneralSecurityException
        {
            this(key, new byte[0], alphabet);
        }

        public FPECharDecryptor(SecretKey key, byte[] tweak, char[] alphabet)
            throws GeneralSecurityException
        {
            alphabetMapper = new BasicAlphabetMapper(alphabet);
            cipher = Cipher.getInstance(key.getAlgorithm() + "/FF1/NoPadding", "BC");

            cipher.init(Cipher.DECRYPT_MODE, key, new FPEParameterSpec(alphabet.length, tweak));
        }

        public char[] process(char[] input)
            throws GeneralSecurityException
        {
            byte[] encData = cipher.doFinal(alphabetMapper.convertToIndexes(input));

            return alphabetMapper.convertToChars(encData);
        }
    }
}
