package org.bouncycastle.crypto.test;

import java.io.IOException;

import org.bouncycastle.crypto.AlphabetMapper;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.fpe.FPEEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.fpe.FPEFF3_1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.BasicAlphabetMapper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SP80038GTest
    extends SimpleTest
{
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
            // FF3-AES128
            FFSample.from(62, "7793833CE891B496381BD5B882F77EA1", "YbpT3hDo0J9xwCQ5qUWt93iv", "dDEYxViK56lGbV1WdZTPTe4w", "C58797C2580174"),
        };

    private void testFF1()
        throws Exception
    {
        for (int i = 0; i < ff1Samples.length; ++i)
        {
            testFF1Sample(ff1Samples[i]);
        }

        byte[] key = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.decode("0327035100210215");
        byte[] tweak = Hex.decode("39383736353433323130");

        FPEEngine fpeEngine = new FPEFF1Engine();

        fpeEngine.init(true, new FPEParameters(new KeyParameter(key), 24, tweak));

        try
        {
            fpeEngine.processBlock(plainText, 0, plainText.length, plainText, 0);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("input data outside of radix", e.getMessage());
        }

        try
        {
            fpeEngine.processBlock(new byte[] { 1 }, 0, 1, plainText, 0);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("input too short", e.getMessage());
        }
    }

    public void testFF1w()
        throws Exception
    {
        byte[] key = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.decode("0327035100210215");
        byte[] cipherText = Hex.decode("022701f80217020a");
        byte[] tweak = Hex.decode("39383736353433323130");

        FPEEngine fpeEngine = new FPEFF1Engine();

        fpeEngine.init(true, new FPEParameters(new KeyParameter(key), 1024, tweak));

        byte[] enc = new byte[plainText.length];

        fpeEngine.processBlock(plainText, 0, plainText.length, enc, 0);

        isTrue(areEqual(cipherText, enc));

        fpeEngine.init(false, new FPEParameters(new KeyParameter(key), 1024, tweak));

        fpeEngine.processBlock(cipherText, 0, cipherText.length, enc, 0);

        isTrue(areEqual(plainText, enc));

        byte[] outPt = Hex.decode("03270F5100210215");

        try
        {
            fpeEngine.processBlock(outPt, 0, outPt.length, enc, 0);
        }
        catch (IllegalArgumentException e)
        {
            isEquals("input data outside of radix", e.getMessage());
        }
    }

    public void testFF3_1()
        throws Exception
    {
        for (int i = 0; i < ff3_1Samples.length; ++i)
        {
            testFF3_1Sample(ff3_1Samples[i]);
        }

        byte[] key = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.decode("0327035100210215");
        byte[] tweak = Hex.decode("39383736353433");

        FPEEngine fpeEngine = new FPEFF3_1Engine();

        fpeEngine.init(true, new FPEParameters(new KeyParameter(key), 24, tweak));

        try
        {
            fpeEngine.processBlock(plainText, 0, plainText.length, plainText, 0);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("input data outside of radix", e.getMessage());
        }

        try
        {
            fpeEngine.init(true, new FPEParameters(new KeyParameter(key), 24, Hex.decode("beef")));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("tweak should be 56 bits", e.getMessage());
        }
    }

    private void testFF3_1w()
        throws Exception
    {
        byte[] key = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.decode("0327035100210215");
        byte[] cipherText = Hex.decode("02fb024900310220");
        byte[] tweak = Hex.decode("39383736353433");

        FPEEngine fpeEngine = new FPEFF3_1Engine();

        fpeEngine.init(true, new FPEParameters(new KeyParameter(key), 1024, tweak));

        byte[] enc = new byte[plainText.length];

        fpeEngine.processBlock(plainText, 0, plainText.length, enc, 0);

        isTrue("enc failed: " + Hex.toHexString(enc), areEqual(cipherText, enc));

        fpeEngine.init(false, new FPEParameters(new KeyParameter(key), 1024, tweak));

        fpeEngine.processBlock(cipherText, 0, cipherText.length, enc, 0);

        isTrue(areEqual(plainText, enc));

        byte[] outPt = Hex.decode("03270F5100210215");

        try
        {
            fpeEngine.processBlock(outPt, 0, outPt.length, enc, 0);
        }
        catch (IllegalArgumentException e)
        {
            isEquals("input data outside of radix", e.getMessage());
        }
    }

    private void testDisable()
        throws Exception
    {
        System.setProperty("org.bouncycastle.fpe.disable", "true");
        try
        {
            testFF1();
            fail("no exception");
        }
        catch (UnsupportedOperationException e)
        {
            isEquals("FF1 encryption disabled", e.getMessage());
        }

        try
        {
            testFF3_1();
            fail("no exception");
        }
        catch (UnsupportedOperationException e)
        {
            isEquals("FPE disabled", e.getMessage());
        }
        System.setProperty("org.bouncycastle.fpe.disable", "false");

        System.setProperty("org.bouncycastle.fpe.disable_ff1", "true");
        try
        {
            testFF1();
            fail("no exception");
        }
        catch (UnsupportedOperationException e)
        {
            isEquals("FF1 encryption disabled", e.getMessage());
        }

        testFF3_1();
        System.setProperty("org.bouncycastle.fpe.disable_ff1", "false");
    }

    private void testFF3_1_255()
    {
        byte[] key = Hex.decode("339BB5B1F2D44BAABF87CA1B7380CDC8");
        byte[] tweak = Hex.decode("3F096DE35BFA31");
        int radix = 256;

        FPEEngine fpeEngine = new FPEFF3_1Engine();

        fpeEngine.init(true, new FPEParameters(new KeyParameter(key), radix, tweak));

        long valueToEncrypt = 0x31009155FFL;

        byte[] bytes = Pack.longToBigEndian(valueToEncrypt);
        byte[] enc = new byte[bytes.length];
        //Encrypt

        fpeEngine.processBlock(bytes, 0, bytes.length, enc, 0);

        isTrue(Arrays.areEqual(Hex.decode("18fa139dc978a681"), enc));

        //Decrypt
        fpeEngine.init(false, new FPEParameters(new KeyParameter(key), radix, tweak));

        fpeEngine.processBlock(enc, 0, enc.length, enc, 0);

        isTrue(Arrays.areEqual(bytes, enc));
    }

    private void testExceptions()
    {
        byte[] key = Hex.decode("339BB5B1F2D44BAABF87CA1B7380CDC8");
        byte[] tweak = Hex.decode("3F096DE35BFA31");
        int radix = 256;

        FPEEngine fpeEngine = new FPEFF3_1Engine();

        try
        {
            fpeEngine.processBlock(null, 0, 0, null, 0);
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("FPE engine not initialized", e.getMessage());
        }

        fpeEngine.init(true, new FPEParameters(new KeyParameter(key), radix, tweak));

        try
        {
            fpeEngine.processBlock(null, 0, 0, null, 0);
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            isEquals("buffer value is null", e.getMessage());
        }

        try
        {
            fpeEngine.processBlock(new byte[2], 0, 2, null, 0);
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            isEquals("buffer value is null", e.getMessage());
        }

        try
        {
            fpeEngine.processBlock(new byte[2], 0, -1, new byte[2], 0);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("input length cannot be negative", e.getMessage());
        }

        try
        {
            fpeEngine.processBlock(new byte[4], 0, 6, new byte[6], 0);
            fail("no exception");
        }
        catch (DataLengthException e)
        {
            isEquals("input buffer too short", e.getMessage());
        }

        try
        {
            fpeEngine.processBlock(new byte[4], 0, 4, new byte[2], 0);
            fail("no exception");
        }
        catch (OutputLengthException e)
        {
            isEquals("output buffer too short", e.getMessage());
        }
    }

    private void testFF1Sample(FFSample ff1)
    {
        FPEEngine fpeEngine = new FPEFF1Engine();

        fpeEngine.init(true, new FPEParameters(new KeyParameter(ff1.getKey()), ff1.getRadix(), ff1.getTweak()));

        byte[] plain = ff1.getPlaintext();
        byte[] enc = new byte[plain.length];

        fpeEngine.processBlock(plain, 0, plain.length, enc, 0);

        isTrue(areEqual(ff1.getCiphertext(), enc));

        fpeEngine.init(false, new FPEParameters(new KeyParameter(ff1.getKey()), ff1.getRadix(), ff1.getTweak()));

        fpeEngine.processBlock(ff1.ciphertext, 0, ff1.ciphertext.length, enc, 0);

        isTrue(areEqual(ff1.getPlaintext(), enc));
    }

    private void testFF3_1Sample(FFSample ff3_1)
        throws Exception
    {
        FPEEngine fpeEngine = new FPEFF3_1Engine();

        fpeEngine.init(true, new FPEParameters(new KeyParameter(ff3_1.getKey()), ff3_1.getRadix(), ff3_1.getTweak()));

        byte[] plain = ff3_1.getPlaintext();
        byte[] enc = new byte[plain.length];

        fpeEngine.processBlock(plain, 0, plain.length, enc, 0);

        isTrue(Arrays.areEqual(ff3_1.getCiphertext(), enc));

        fpeEngine.init(false, new FPEParameters(new KeyParameter(ff3_1.getKey()), ff3_1.getRadix(), ff3_1.getTweak()));

        fpeEngine.processBlock(ff3_1.getCiphertext(), 0, plain.length, enc, 0);

        isTrue(Arrays.areEqual(ff3_1.getPlaintext(), enc));
    }

    public void testFF1Bounds()
        throws IOException
    {
        byte[] key = Hex.decode("339BB5B1F2D44BAABF87CA1B7380CDC8");
        byte[] tweak = Hex.decode("3F096DE35BFA31");

        FPEEngine fpeEngine = new FPEFF1Engine();

        try
        {
            AlphabetMapper alphabetMapper = new BasicAlphabetMapper("ABCDEFGHI");

            fpeEngine.init(true, new FPEParameters(new KeyParameter(key),
                        alphabetMapper.getRadix(), tweak));

            process(fpeEngine, new byte[] { 1, 2, 3 });
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
           isEquals("input too short", e.getMessage());
        }

        try
        {
            AlphabetMapper alphabetMapper = new BasicAlphabetMapper("ABCD");

            fpeEngine.init(true, new FPEParameters(new KeyParameter(key),
                        alphabetMapper.getRadix(), tweak));

            process(fpeEngine, new byte[] { 1, 2, 3 });
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("input too short", e.getMessage());
        }
    }

    private void testFF3_1Bounds()
        throws IOException
    {
        String bigAlpha = "+-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";

        AlphabetMapper alphabetMapper = new BasicAlphabetMapper(bigAlpha);

        ff3_1Test(alphabetMapper, "467094C27E47978FE616F475215BF4F1", "ECC8AA7B87B41C", "9RwG+t8cKfa9JweBYgHAA6fHUShNZ5tc", "-DXMBhb3AFPq5Xf4oUva4WbB8eagGK2u");
        ff3_1Test(alphabetMapper, "4DB04B58E97819015A08BA7A39A79C303968A34DB0936FAD", "26B3A632FAADFE", "k5Kop6xYpT0skr1zHHPEt5rPWQ4s4O-3", "JyWzuPL6SNsciOXdEgwnKZJxHiKaTu4Z");
        ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "ZpztPp90Oo5ekoNRzqArsAqAbnmM--W6", "NPxEDufvnYzVX3jxupv+iJOuPVpWRPjD");
        try
        {
            ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "ZpztPp90Oo5ekoNRzqArsAqAbnmM+-W6ZZ", "L1yx-4YLQG9W1P5yTI7Wp2h0IDcRoBq1kk");
            fail("no exception 1");
        }
        catch (IllegalArgumentException e)
        {
           isEquals("maximum input length is 32", e.getMessage());
        }

        try
        {
            ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "Z", "L");
            fail("no exception 2");
        }
        catch (IllegalArgumentException e)
        {
           isEquals("input too short", e.getMessage());
        }

        try
        {
            alphabetMapper = new BasicAlphabetMapper("ABCDEFGHI");

            ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "AB", "ZZ");
            fail("no exception 3");
        }
        catch (IllegalArgumentException e)
        {
           isEquals("input too short", e.getMessage());
        }
    }

    private void ff3_1Test(AlphabetMapper alphabetMapper, String skey, String stweak, String input, String output)
        throws IOException
    {
        FPEEngine fpeEncEngine = new FPEFF3_1Engine();
        FPEEngine fpeDecEngine = new FPEFF3_1Engine();

        byte[] key = Hex.decode(skey);
        byte[] tweak = Hex.decode(stweak);
        int radix = alphabetMapper.getRadix();

        fpeEncEngine.init(true, new FPEParameters(new KeyParameter(key), radix, tweak));
        fpeDecEngine.init(false, new FPEParameters(new KeyParameter(key), radix, tweak));

        byte[] bytes = alphabetMapper.convertToIndexes(input.toCharArray());

        byte[] encryptedBytes = process(fpeEncEngine, bytes);
        isEquals(output, new String(alphabetMapper.convertToChars(encryptedBytes)));

        byte[] decryptedBytes = process(fpeDecEngine, encryptedBytes);
        isTrue(Arrays.areEqual(bytes, decryptedBytes));
        char[] chars = alphabetMapper.convertToChars(decryptedBytes);
        isEquals(input, String.valueOf(chars));
    }

    private byte[] process(FPEEngine fpeEngine, byte[] bytes)
        throws IOException
    {
        byte[] rv = new byte[bytes.length];

        fpeEngine.processBlock(bytes, 0, bytes.length, rv, 0);

        return rv;
    }

    public void testUtility()
        throws Exception
    {
        FPECharEncryptor fpeEnc = new FPECharEncryptor(new FPEFF1Engine(), Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "0123456789".toCharArray());

        char[] input = "01234567890123456".toCharArray();
        char[] encrypted = fpeEnc.process(input);

        FPECharDecryptor fpeDec = new FPECharDecryptor(new FPEFF1Engine(), Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "0123456789".toCharArray());
        char[] decrypted = fpeDec.process(encrypted);

        isTrue("no match", Arrays.areEqual(input, decrypted));
    }

    public String getName()
    {
        return "SP80038GTest";
    }

    public void performTest()
        throws Exception
    {
        testFF1();
        testFF1w();
        testFF1Bounds();
        testFF3_1();
        testFF3_1w();
        testFF3_1_255();
        testFF3_1Bounds();
        testDisable();
        testUtility();
        testExceptions();
    }

    public static void main(
        String[]    args)
    {
        runTest(new SP80038GTest());
    }

    public class FPECharEncryptor
    {
        private final FPEEngine fpeEngine;
        private AlphabetMapper alphabetMapper;

        public FPECharEncryptor(FPEEngine fpeEngine, byte[] key, char[] alphabet)
        {
            this(fpeEngine, key, new byte[0], alphabet);
        }

        public FPECharEncryptor(FPEEngine fpeEngine, byte[] key, byte[] tweak, char[] alphabet)
        {
            this.fpeEngine = fpeEngine;

            alphabetMapper = new BasicAlphabetMapper(alphabet);

            fpeEngine.init(true, new FPEParameters(new KeyParameter(key), alphabetMapper.getRadix(), tweak));
        }

        public char[] process(char[] input)
            throws IOException
        {
            byte[] bytes = alphabetMapper.convertToIndexes(input);

            fpeEngine.processBlock(bytes, 0, bytes.length, bytes, 0);

            return alphabetMapper.convertToChars(bytes);
        }
    }

    public class FPECharDecryptor
    {
        private final FPEEngine fpeEngine;
        private AlphabetMapper alphabetMapper;

        public FPECharDecryptor(FPEEngine fpeEngine, byte[] key, char[] alphabet)
        {
            this(fpeEngine, key, new byte[0], alphabet);
        }

        public FPECharDecryptor(FPEEngine fpeEngine, byte[] key, byte[] tweak, char[] alphabet)
        {
            this.fpeEngine = fpeEngine;

            alphabetMapper = new BasicAlphabetMapper(alphabet);

            fpeEngine.init(false, new FPEParameters(new KeyParameter(key), alphabetMapper.getRadix(), tweak));
        }

        public char[] process(char[] input)
            throws IOException
        {
            byte[] bytes = alphabetMapper.convertToIndexes(input);

            fpeEngine.processBlock(bytes, 0, bytes.length, bytes, 0);

            return alphabetMapper.convertToChars(bytes);
        }
    }
}
