package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ARIATest
    extends SimpleTest
{
    private static SecureRandom R = new SecureRandom();

    private static final String[][] TEST_VECTORS_RFC5794 = {
        {
            "128-Bit Key",
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "d718fbd6ab644c739da95f3be6451778"
        },
        {
            "192-Bit Key",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "26449c1805dbe7aa25a468ce263a9e79"
        },
        {
            "256-Bit Key",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "f92bd7c79fb72e2f2b8f80c1972d24fc"
        },
    };

    public String getName()
    {
        return "ARIA";
    }

    public void performTest() throws Exception
    {
        checkTestVectors_RFC5794();

        for (int i = 0; i < 100; ++i)
        {
            checkRandomRoundtrips();
        }

        new MyARIAEngine().checkImplementation();
    }

    private void checkRandomRoundtrips()
    {
        ARIAEngine ce = new ARIAEngine();
        ARIAEngine cd = new ARIAEngine();

        byte[] txt = new byte[ce.getBlockSize()];
        byte[] enc = new byte[ce.getBlockSize()];
        byte[] dec = new byte[ce.getBlockSize()];

        for (int keyLen = 16; keyLen <= 32; keyLen += 8)
        {
            byte[] K = new byte[keyLen];

            R.nextBytes(K);

            KeyParameter key = new KeyParameter(K);
            ce.init(true, key);
            cd.init(false, key);

            R.nextBytes(txt);

            for (int i = 0; i < 100; ++i)
            {
                ce.processBlock(txt, 0, enc, 0);
                cd.processBlock(enc, 0, dec, 0);

                isTrue(Arrays.areEqual(txt, dec));

                System.arraycopy(enc, 0, txt, 0, enc.length);
            }
        }
    }

    private void checkTestVector_RFC5794(String[] tv)
    {
        String name = "'" + tv[0] + "'";

        BlockCipher c = new ARIAEngine();
        int blockSize = c.getBlockSize();
        isTrue("Wrong block size returned from getBlockSize() for " + name, 16 == blockSize);

        KeyParameter key = new KeyParameter(Hex.decode(tv[1]));
        byte[] plaintext = Hex.decode(tv[2]);
        byte[] ciphertext = Hex.decode(tv[3]);

        isTrue("Unexpected plaintext length for " + name, blockSize == plaintext.length);
        isTrue("Unexpected ciphertext length for " + name, blockSize == ciphertext.length);

        c.init(true, key);

        byte[] actual = new byte[blockSize];
        int num = c.processBlock(plaintext, 0, actual, 0);

        isTrue("Wrong length returned from processBlock() (encryption) for " + name, blockSize == num);
        isTrue("Incorrect ciphertext computed for " + name, Arrays.areEqual(ciphertext, actual));

        c.init(false, key);
        num = c.processBlock(ciphertext, 0, actual, 0);

        isTrue("Wrong length returned from processBlock() (decryption) for " + name, blockSize == num);
        isTrue("Incorrect plaintext computed for " + name, Arrays.areEqual(plaintext, actual));
    }

    private void checkTestVectors_RFC5794()
    {
        for (int i = 0; i < TEST_VECTORS_RFC5794.length; ++i)
        {
            checkTestVector_RFC5794(TEST_VECTORS_RFC5794[i]);
        }
    }

    public static void main(String[] args)
    {
        runTest(new ARIATest());
    }

    private class MyARIAEngine extends ARIAEngine
    {
        public void checkImplementation()
        {
            checkInvolution();
            checkSBoxes();
        }

        private void checkInvolution()
        {
            byte[] x = new byte[16], y = new byte[16];

            for (int i = 0; i < 100; ++i)
            {
                R.nextBytes(x);
                System.arraycopy(x, 0, y, 0, 16);
                A(y);
                A(y);
                ARIATest.this.isTrue(Arrays.areEqual(x, y));
            }
        }

        private void checkSBoxes()
        {
            for (int i = 0; i < 256; ++i)
            {
                byte x = (byte)i;

                ARIATest.this.isTrue(x == SB1(SB3(x)));
                ARIATest.this.isTrue(x == SB3(SB1(x)));

                ARIATest.this.isTrue(x == SB2(SB4(x)));
                ARIATest.this.isTrue(x == SB4(SB2(x)));
            }
        }
    }
}
