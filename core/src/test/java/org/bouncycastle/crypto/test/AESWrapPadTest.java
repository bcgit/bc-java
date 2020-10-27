package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESWrapPadEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * This is a test harness I use because I cannot modify the BC test harness without
 * invalidating the signature on their signed provider library. The code here is not
 * high quality but it does test the RFC vectors as well as randomly generated values.
 * The RFC test vectors are tested by making sure both the ciphertext and decrypted
 * values match the expected values whereas the random values are just checked to make
 * sure that:
 * <p>unwrap(wrap(random_value, random_kek), random_kek) == random_value.</p>
 */

public class AESWrapPadTest
    extends SimpleTest
{

    private final int numOfRandomIterations = 100;

    public AESWrapPadTest()
    {

    }

    private void wrapAndUnwrap(byte[] kek, byte[] key, byte[] expected)
        throws Exception
    {
        Wrapper wrapper = new AESWrapPadEngine();

        wrapper.init(true, new KeyParameter(kek));

        byte[] cipherText = wrapper.wrap(key, 0, key.length);
        if (!areEqual(cipherText, expected))
        {
            fail("Wrapped value does not match expected.");
        }
        wrapper.init(false, new KeyParameter(kek));
        byte[] plainText = wrapper.unwrap(cipherText, 0, cipherText.length);

        if (!areEqual(key, plainText))
        {
            fail("Unwrapped value does not match original.");
        }
    }

    private void wrapAndUnwrap(byte[] kek, byte[] key)
        throws Exception
    {
        Wrapper wrapper = new AESWrapPadEngine();

        wrapper.init(true, new KeyParameter(kek));

        byte[] cipherText = wrapper.wrap(key, 0, key.length);

        wrapper.init(false, new KeyParameter(kek));
        byte[] plainText = wrapper.unwrap(cipherText, 0, cipherText.length);

        if (!areEqual(key, plainText))
        {
            fail("Unwrapped value does not match original.");
        }
    }

    private void wrapWithIVTest()
        throws Exception
    {
        byte[] kek = Hex.decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        byte[] key = Hex.decode("c37b7e6492584340bed12207808941155068f738");
        byte[] expected = Hex.decode("5cbdb3fb71351d0e628b85dbcba1a1890d4db26d1335e11d1aabea11124caad0");

        Wrapper wrapper = new AESWrapPadEngine();

        wrapper.init(true, new ParametersWithIV(new KeyParameter(kek), Hex.decode("33333333")));

        byte[] cipherText = wrapper.wrap(key, 0, key.length);
        if (!areEqual(cipherText, expected))
        {
            fail("Wrapped value does not match expected.");
        }
        wrapper.init(false, new ParametersWithIV(new KeyParameter(kek), Hex.decode("33333333")));
        byte[] plainText = wrapper.unwrap(cipherText, 0, cipherText.length);

        if (!areEqual(key, plainText))
        {
            fail("Unwrapped value does not match original.");
        }
    }

    public String getName()
    {
        return "AESWrapPad";
    }

    public void performTest()
        throws Exception
    {
        // test RFC 5649 test vectors
        byte[] kek = Hex.decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        byte[] key = Hex.decode("c37b7e6492584340bed12207808941155068f738");
        byte[] wrap = Hex.decode("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

        wrapAndUnwrap(kek, key, wrap);

        wrap = Hex.decode("afbeb0f07dfbf5419200f2ccb50bb24f");
        key = Hex.decode("466f7250617369");
        wrapAndUnwrap(kek, key, wrap);

        wrapWithIVTest();

        //
        // offset test
        //
        Wrapper wrapper = new AESWrapPadEngine();

        byte[] pText = new byte[5 + key.length];
        byte[]  cText;

        System.arraycopy(key, 0, pText, 5, key.length);

        wrapper.init(true, new KeyParameter(kek));

        cText = wrapper.wrap(pText, 5, key.length);
        if (!Arrays.areEqual(cText, wrap))
        {
            fail("failed offset wrap test expected " + new String(Hex.encode(wrap)) + " got " + new String(Hex.encode(cText)));
        }

        wrapper.init(false, new KeyParameter(kek));

        cText = new byte[6 + wrap.length];
        System.arraycopy(wrap, 0, cText, 6, wrap.length);

        pText = wrapper.unwrap(cText, 6, wrap.length);
        if (!Arrays.areEqual(pText, key))
        {
            fail("failed offset unwrap test expected " + new String(Hex.encode(key)) + " got " + new String(Hex.encode(pText)));
        }

        // test random values
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < numOfRandomIterations; i++)
        {
            int kekLength = 128;
            boolean shouldIncrease = (rnd.nextInt() & 0x01) != 0;
            if (shouldIncrease)
            {
                kekLength = 256;
            }
            kek = new byte[kekLength / 8];
            rnd.nextBytes(kek);
            int keyToWrapSize = RNGUtils.nextInt(rnd, 256 / 8 - 8) + 8;
            byte[] keyToWrap = new byte[keyToWrapSize];
            rnd.nextBytes(keyToWrap);
            wrapAndUnwrap(kek, keyToWrap);
        }

        performFailTests();
    }

    private void performFailTests() {
        // Tests of specific failure modes. Each failure mode should produce an InvalidCipherTextException
        byte[] kek = Hex.decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        Wrapper wrapper = new AESWrapPadEngine();
        wrapper.init(false, new KeyParameter(kek));

        try {
            // not a multiple of 8 bytes, so invalid
            wrapper.unwrap(new byte[23],0,23);
            fail("Data which was not a multiple of 8 bytes was accepted");
        } catch ( InvalidCipherTextException e ) {
            // correct behaviour
        }

        try {
            // zero bytes is too short
            wrapper.unwrap(new byte[0],0,0);
            fail("Data of zero bytes was accepted");
        } catch ( InvalidCipherTextException e ) {
            // correct behaviour
        }

        try {
            // only 8 bytes - so too short
            wrapper.unwrap(new byte[8],0,8);
            fail("Data which was not a multiple of 8 bytes was accepted");
        } catch ( InvalidCipherTextException e ) {
            // correct behaviour
        }

        try {
            // usable number of bytes, but cannot be decrypted.
            // This value produces a negative MLI.
            wrapper.unwrap(Hex.decode("000000000000000000000000000000000000000000000000"),0,24);
            fail("Invalid data was accepted");
        } catch ( InvalidCipherTextException e ) {
            // correct behaviour
        }


        try {
            // usable number of bytes, but cannot be decrypted.
            // This value produces a large positive MLI
            wrapper.unwrap(Hex.decode("000000000000000000000000000000000000000000000002"),0,24);
            fail("Invalid data was accepted");
        } catch ( InvalidCipherTextException e ) {
            // correct behaviour
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new AESWrapPadTest());
    }
}

