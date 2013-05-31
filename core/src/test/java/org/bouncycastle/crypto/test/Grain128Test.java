package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Grain128Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Grain-128 Test
 */
public class Grain128Test
    extends SimpleTest
{

    String keyStream1 = "f09b7bf7d7f6b5c2de2ffc73ac21397f";
    String keyStream2 = "afb5babfa8de896b4b9c6acaf7c4fbfd";

    public String getName()
    {
        return "Grain-128";
    }

    public void performTest()
    {
        Grain128Test1(new ParametersWithIV(new KeyParameter(Hex
            .decode("00000000000000000000000000000000")), Hex
            .decode("000000000000000000000000")));
        Grain128Test2(new ParametersWithIV(new KeyParameter(Hex
            .decode("0123456789abcdef123456789abcdef0")), Hex
            .decode("0123456789abcdef12345678")));
        Grain128Test3(new ParametersWithIV(new KeyParameter(Hex
            .decode("0123456789abcdef123456789abcdef0")), Hex
            .decode("0123456789abcdef12345678")));
    }

    private void Grain128Test1(CipherParameters params)
    {
        StreamCipher grain = new Grain128Engine();
        byte[] in = new byte[16];
        byte[] out = new byte[16];

        grain.init(true, params);

        grain.processBytes(in, 0, in.length, out, 0);

        if (!areEqual(out, Hex.decode(keyStream1)))
        {
            mismatch("Keystream 1", keyStream1, out);
        }

        grain.reset();

        grain.processBytes(in, 0, in.length, out, 0);

        if (!areEqual(out, Hex.decode(keyStream1)))
        {
            mismatch("Keystream 1", keyStream1, out);
        }
    }

    private void Grain128Test2(CipherParameters params)
    {
        StreamCipher grain = new Grain128Engine();
        byte[] in = new byte[16];
        byte[] out = new byte[16];

        grain.init(true, params);

        grain.processBytes(in, 0, in.length, out, 0);

        if (!areEqual(out, Hex.decode(keyStream2)))
        {
            mismatch("Keystream 2", keyStream2, out);
        }

        grain.reset();

        grain.processBytes(in, 0, in.length, out, 0);

        if (!areEqual(out, Hex.decode(keyStream2)))
        {
            mismatch("Keystream 2", keyStream2, out);
        }
    }

    private void Grain128Test3(CipherParameters params)
    {
        StreamCipher grain = new Grain128Engine();
        byte[] in = "Encrypt me!".getBytes();
        byte[] cipher = new byte[in.length];
        byte[] clear = new byte[in.length];

        grain.init(true, params);

        grain.processBytes(in, 0, in.length, cipher, 0);
        grain.reset();
        grain.processBytes(cipher, 0, cipher.length, clear, 0);

        if (!areEqual(in, clear))
        {
            mismatch("Test 3", new String(Hex.encode(in)), clear);
        }
    }

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new Grain128Test());
    }
}
