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

    public void testFF3_1()
        throws Exception
    {
        for (int i = 0; i < ff3_1Samples.length; ++i)
        {
            testFF3Sample(ff3_1Samples[i]);
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
