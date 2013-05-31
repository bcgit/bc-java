package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.IDEAEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 */
public class IDEATest
    extends CipherTest
{
    static SimpleTest[] tests =
            {
                new BlockCipherVectorTest(0, new IDEAEngine(),
                        new KeyParameter(Hex.decode("00112233445566778899AABBCCDDEEFF")),
                        "000102030405060708090a0b0c0d0e0f", "ed732271a7b39f475b4b2b6719f194bf"),
                new BlockCipherVectorTest(0, new IDEAEngine(),
                        new KeyParameter(Hex.decode("00112233445566778899AABBCCDDEEFF")),
                        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "b8bc6ed5c899265d2bcfad1fc6d4287d")
            };

    IDEATest()
    {
        super(tests, new IDEAEngine(), new KeyParameter(new byte[32]));
    }

    public String getName()
    {
        return "IDEA";
    }

    public static void main(
        String[]    args)
    {
        runTest(new IDEATest());
    }
}
