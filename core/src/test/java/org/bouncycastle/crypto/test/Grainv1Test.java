package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Grainv1Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Grain v1 Test
 */
public class Grainv1Test
    extends SimpleTest
{

    String keyStream1 = "dee931cf1662a72f77d0";
    String keyStream2 = "7f362bd3f7abae203664";
    String keyStream4 = "017D13ECB20AE0C9ACF784CB06525F72"
        + "CE6D52BEBB948F124668C35064559024"
        + "49EEA505C19F3EE4D052C3D19DA9C4D1"
        + "B92DBC7F07AFEA6A3D845DE60D8471FD";

    public String getName()
    {
        return "Grain v1";
    }

    public void performTest()
    {
        Grainv1Test1(new ParametersWithIV(new KeyParameter(Hex
            .decode("00000000000000000000")), Hex
            .decode("0000000000000000")));
        Grainv1Test2(new ParametersWithIV(new KeyParameter(Hex
            .decode("0123456789abcdef1234")), Hex
            .decode("0123456789abcdef")));
        Grainv1Test3(new ParametersWithIV(new KeyParameter(Hex
            .decode("0123456789abcdef1234")), Hex
            .decode("0123456789abcdef")));
        Grainv1Test4(new ParametersWithIV(new KeyParameter(Hex
            .decode("0F62B5085BAE0154A7FA")), Hex
            .decode("288FF65DC42B92F9")));
    }

    private void Grainv1Test1(CipherParameters params)
    {
        StreamCipher grain = new Grainv1Engine();
        byte[] in = new byte[10];
        byte[] out = new byte[10];

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

    private void Grainv1Test2(CipherParameters params)
    {
        StreamCipher grain = new Grainv1Engine();
        byte[] in = new byte[10];
        byte[] out = new byte[10];

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

    private void Grainv1Test3(CipherParameters params)
    {
        StreamCipher grain = new Grainv1Engine();
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

    private void Grainv1Test4(CipherParameters params)
    {
        StreamCipher grain = new Grainv1Engine();
        byte[] in = new byte[keyStream4.length() / 2];
        byte[] out = new byte[in.length];

        grain.init(true, params);

        grain.processBytes(in, 0, in.length, out, 0);

        if (!areEqual(out, Hex.decode(keyStream4)))
        {
            mismatch("Keystream 4", keyStream4, out);
        }
    }

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new Grainv1Test());
    }
}
