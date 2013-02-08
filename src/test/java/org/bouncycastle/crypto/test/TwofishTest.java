package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class TwofishTest
    extends CipherTest
{
    static String key1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    static String key2 = "000102030405060708090a0b0c0d0e0f1011121314151617";
    static String key3 = "000102030405060708090a0b0c0d0e0f";

    static String input = "000102030405060708090A0B0C0D0E0F";

    static SimpleTest[]  tests =
    {
        new BlockCipherVectorTest(0, new TwofishEngine(),
                new KeyParameter(Hex.decode(key1)),
                input, "8ef0272c42db838bcf7b07af0ec30f38"),
        new BlockCipherVectorTest(1, new TwofishEngine(),
                new KeyParameter(Hex.decode(key2)),
                input, "95accc625366547617f8be4373d10cd7"),
        new BlockCipherVectorTest(2, new TwofishEngine(),
                new KeyParameter(Hex.decode(key3)),
                input, "9fb63337151be9c71306d159ea7afaa4")
    };

    TwofishTest()
    {
        super(tests, new TwofishEngine(), new KeyParameter(new byte[32]));
    }
    
    public String getName()
    {
        return "Twofish";
    }

    public static void main(
        String[]    args)
    {
        runTest(new TwofishTest());
    }
}
