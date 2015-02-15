package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.engines.AESWrapPadEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestFailedException;
import org.bouncycastle.util.test.TestResult;

/**
 * Wrap Test
 */
public class AESWrapTest
    extends SimpleTest
{
    public String getName()
    {
        return "AESWrap";
    }

    private void wrapTest(
        int     id,
        byte[]  kek,
        byte[]  in,
        byte[]  out)
    {
        wrapTest(id, kek, in, out, false);
    }

    private void wrapTest(
        int     id,
        byte[]  kek,
        byte[]  in,
        byte[]  out,
        boolean useReverseDirection)
    {
        Wrapper wrapper = new AESWrapEngine(useReverseDirection);

        wrapper.init(true, new KeyParameter(kek));

        try
        {
            byte[]  cText = wrapper.wrap(in, 0, in.length);
            if (!Arrays.areEqual(cText, out))
            {
                fail("failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
            }
        }
        catch (TestFailedException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            fail("failed wrap test exception " + e.toString());
        }

        wrapper.init(false, new KeyParameter(kek));

        try
        {
            byte[]  pText = wrapper.unwrap(out, 0, out.length);
            if (!Arrays.areEqual(pText, in))
            {
                fail("failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText)));
            }
        }
        catch (TestFailedException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            fail("failed unwrap test exception.", e);
        }

        //
        // offset test
        //
        byte[] pText = new byte[5 + in.length];
        byte[]  cText;

        System.arraycopy(in, 0, pText, 5, in.length);

        wrapper.init(true, new KeyParameter(kek));

        try
        {
            cText = wrapper.wrap(pText, 5, in.length);
            if (!Arrays.areEqual(cText, out))
            {
                fail("failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
            }
        }
        catch (Exception e)
        {
            fail("failed wrap test exception " + e.toString());
        }

        wrapper.init(false, new KeyParameter(kek));

        cText = new byte[6 + out.length];
        System.arraycopy(out, 0, cText, 6, out.length);

        try
        {
            pText = wrapper.unwrap(cText, 6, out.length);
            if (!Arrays.areEqual(pText, in))
            {
                fail("failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText)));
            }
        }
        catch (Exception e)
        {
            fail("failed unwrap test exception.", e);
        }
    }

    private void heapIssueTest()
    {
   		byte[] key = Hex.decode("d305ef52a6b9e72c810b821261d2d678");
   		byte[] ciphertext = Hex.decode("d2b2906d209a46261d8f6794eca3179d");

   		Wrapper aes = new AESWrapPadEngine();
   		aes.init(false, new KeyParameter(key));
        try
        {
            byte[] result = aes.unwrap(ciphertext, 0, ciphertext.length);

            fail("incorrect pad not detected");
        }
        catch (InvalidCipherTextException e)
        {
            // ignore
        }
    }

    public void performTest()
        throws Exception
    {
        byte[]  kek1 = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[]  in1 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out1 = Hex.decode("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");

        wrapTest(1, kek1, in1, out1);

        byte[]  kek2 = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
        byte[]  in2 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out2 = Hex.decode("96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d");

        wrapTest(2, kek2, in2, out2);

        byte[]  kek3 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[]  in3 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out3 = Hex.decode("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7");

        wrapTest(3, kek3, in3, out3);

        byte[]  kek4 = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
        byte[]  in4 = Hex.decode("00112233445566778899aabbccddeeff0001020304050607");
        byte[]  out4 = Hex.decode("031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2");
        wrapTest(4, kek4, in4, out4);

        byte[]  kek5 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[]  in5 = Hex.decode("00112233445566778899aabbccddeeff0001020304050607");
        byte[]  out5 = Hex.decode("a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1");
        wrapTest(5, kek5, in5, out5);

        byte[]  kek6 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[]  in6 = Hex.decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        byte[]  out6 = Hex.decode("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");
        wrapTest(6, kek6, in6, out6);

        byte[]  kek7 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[]  in7 = Hex.decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        byte[]  out7 = Hex.decode("cba01acbdb4c7c39fa59babb383c485f318837208731a81c735b5be6ba710375a1159e26a9b57228");
        wrapTest(7, kek7, in7, out7, true);

        Wrapper      wrapper = new AESWrapEngine();
        KeyParameter key = new KeyParameter(new byte[16]);
        byte[]       buf = new byte[16];

        try
        {
            wrapper.init(true, key);

            wrapper.unwrap(buf, 0, buf.length);

            fail("failed unwrap state test.");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        catch (InvalidCipherTextException e)
        {
            fail("unexpected exception: " + e, e);
        }

        try
        {
            wrapper.init(false, key);

            wrapper.wrap(buf, 0, buf.length);

            fail("failed unwrap state test.");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        //
        // short test
        //
        try
        {
            wrapper.init(false, key);

            wrapper.unwrap(buf, 0, buf.length / 2);

            fail("failed unwrap short test.");
        }
        catch (InvalidCipherTextException e)
        {
            // expected
        }

        try
        {
            wrapper.init(true, key);

            wrapper.wrap(buf, 0, 15);

            fail("ailed wrap length test.");
        }
        catch (DataLengthException e)
        {
            // expected
        }

        heapIssueTest();
    }

    public static void main(
        String[]    args)
    {
        AESWrapTest     test = new AESWrapTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
