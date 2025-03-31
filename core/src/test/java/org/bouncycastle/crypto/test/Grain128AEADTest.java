package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.Grain128AEADEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.TestFailedException;

public class Grain128AEADTest
    extends SimpleTest
{
    public String getName()
    {
        return "Grain-128AEAD";
    }

    public void performTest()
        throws Exception
    {
        CipherTest.testOverlapping(this, 16, 12, 8, 20, new Grain128AEADEngine());
        CipherTest.implTestVectorsEngine(new Grain128AEADEngine(), "crypto", "LWC_AEAD_KAT_128_96.txt", this);
        checkAEADCipherOutputSize(this, 16, 12, 8, new Grain128AEADEngine());
        CipherTest.checkCipher(32, 12, 100, 128, new CipherTest.Instance()
        {
            @Override
            public AEADCipher createInstance()
            {
                return new Grain128AEADEngine();
            }
        });
        CipherTest.checkAEADCipherMultipleBlocks(this, 1024, 7, 100, 128, 12, new Grain128AEADEngine());


        CipherTest.checkAEADParemeter(this, 16, 12, 8, 20, new Grain128AEADEngine());

        testSplitUpdate();
        testExceptions();
        testLongAEAD();
    }


    private void testSplitUpdate()
        throws InvalidCipherTextException
    {
        byte[] Key = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] Nonce = Hex.decode("000102030405060708090A0B");
        byte[] PT = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        byte[] AD = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        byte[] CT = Hex.decode("EAD60EF559493ACEF6A3C238C018835DE3ABB6AA621A9AA65EFAF7B9D05BBE6C0913DFC8674BACC9");

        Grain128AEADEngine grain = new Grain128AEADEngine();
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(Key), Nonce);
        grain.init(true, params);

        grain.processAADBytes(AD, 0, 10);
        grain.processAADByte(AD[10]);
        grain.processAADBytes(AD, 11, AD.length - 11);

        byte[] rv = new byte[CT.length];
        int len = grain.processBytes(PT, 0, 10, rv, 0);
        len += grain.processByte(PT[10], rv, len);
        len += grain.processBytes(PT, 11, PT.length - 11, rv, len);

        grain.doFinal(rv, len);

        isTrue(Arrays.areEqual(rv, CT));
        grain.init(true, params);
        grain.processBytes(PT, 0, 10, rv, 0);
        try
        {
            grain.processAADByte((byte)0x01);
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("Grain-128 AEAD needs to be initialized", e.getMessage());
        }

        try
        {
            grain.processAADBytes(AD, 0, AD.length);
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("Grain-128 AEAD needs to be initialized", e.getMessage());
        }
    }

    private void testLongAEAD()
        throws InvalidCipherTextException
    {
        byte[] Key = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] Nonce = Hex.decode("000102030405060708090A0B");
        byte[] PT = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        byte[] AD = Hex.decode(   // 186 bytes
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9");
        byte[] CT = Hex.decode("731DAA8B1D15317A1CCB4E3DD320095FB27E5BB2A10F2C669F870538637D4F162298C70430A2B560");

        Grain128AEADEngine grain = new Grain128AEADEngine();
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(Key), Nonce);
        grain.init(true, params);

        grain.processAADBytes(AD, 0, AD.length);

        byte[] rv = new byte[CT.length];
        int len = grain.processBytes(PT, 0, 10, rv, 0);
        len += grain.processByte(PT[10], rv, len);
        len += grain.processBytes(PT, 11, PT.length - 11, rv, len);

        grain.doFinal(rv, len);

        isTrue(Arrays.areEqual(rv, CT));
        grain.init(true, params);
        grain.processBytes(PT, 0, 10, rv, 0);
        try
        {
            grain.processAADByte((byte)0x01);
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("Grain-128 AEAD needs to be initialized", e.getMessage());
        }

        try
        {
            grain.processAADBytes(AD, 0, AD.length);
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("Grain-128 AEAD needs to be initialized", e.getMessage());
        }
    }

    private void testExceptions()
        throws InvalidCipherTextException
    {
        try
        {
            Grain128AEADEngine grain128 = new Grain128AEADEngine();

            grain128.init(true, new KeyParameter(new byte[10]));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("invalid parameters passed to Grain-128 AEAD", e.getMessage());
        }

        try
        {
            Grain128AEADEngine grain128 = new Grain128AEADEngine();

            grain128.init(true, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[8]));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Grain-128 AEAD requires exactly 12 bytes of IV", e.getMessage());
        }

        try
        {
            Grain128AEADEngine grain128 = new Grain128AEADEngine();

            grain128.init(true, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[12]));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Grain-128 AEAD key must be 16 bytes long", e.getMessage());
        }
    }

    static void checkAEADCipherOutputSize(SimpleTest parent, int keySize, int ivSize, int tagSize, AEADCipher cipher)
        throws InvalidCipherTextException
    {
        final SecureRandom random = new SecureRandom();
        int tmpLength = random.nextInt(tagSize - 1) + 1;
        final byte[] plaintext = new byte[tmpLength];
        byte[] key = new byte[keySize];
        byte[] iv = new byte[ivSize];
        random.nextBytes(key);
        random.nextBytes(iv);
        random.nextBytes(plaintext);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)];
        //before the encrypt
        isEqualTo(parent, plaintext.length + tagSize, ciphertext.length);
        isEqualTo(parent, plaintext.length, cipher.getUpdateOutputSize(plaintext.length));
        //during the encrypt process of the first block
        int len = cipher.processBytes(plaintext, 0, tmpLength, ciphertext, 0);
        isEqualTo(parent, plaintext.length + tagSize, len + cipher.getOutputSize(plaintext.length - tmpLength));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(plaintext.length - tmpLength));
        //process doFinal
        len += cipher.doFinal(ciphertext, len);
        isEqualTo(parent, len, ciphertext.length);

        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        //before the encrypt
        isEqualTo(parent, plaintext.length, cipher.getOutputSize(ciphertext.length));
        isEqualTo(parent, plaintext.length, cipher.getUpdateOutputSize(ciphertext.length));
        //during the encrypt process of the first block
        len = cipher.processBytes(ciphertext, 0, tmpLength, plaintext, 0);
        isEqualTo(parent, plaintext.length, len + cipher.getOutputSize(ciphertext.length - tmpLength));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(ciphertext.length - tmpLength));
        //process doFinal
        len = cipher.processBytes(ciphertext, tmpLength, tagSize, plaintext, 0);
        len += cipher.doFinal(plaintext, len);
        isEqualTo(parent, len, plaintext.length);
    }

    static void isEqualTo(
        SimpleTest parent,
        int a,
        int b)
    {
        if (a != b)
        {
            throw new TestFailedException(SimpleTestResult.failed(parent, "no message"));
        }
    }

    public static void main(String[] args)
    {
        runTest(new Grain128AEADTest());
    }
}
