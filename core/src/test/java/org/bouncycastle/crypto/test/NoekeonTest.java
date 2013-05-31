package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.NoekeonEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Noekeon tester
 */
public class NoekeonTest
    extends CipherTest
{
    static SimpleTest[]  tests =
    {
        new BlockCipherVectorTest(0, new NoekeonEngine(),
            new KeyParameter(Hex.decode("00000000000000000000000000000000")),
            "00000000000000000000000000000000",
            "b1656851699e29fa24b70148503d2dfc"),
        new BlockCipherVectorTest(1, new NoekeonEngine(),
            new KeyParameter(Hex.decode("ffffffffffffffffffffffffffffffff")),
            "ffffffffffffffffffffffffffffffff",
            "2a78421b87c7d0924f26113f1d1349b2"),
        new BlockCipherVectorTest(2, new NoekeonEngine(),
            new KeyParameter(Hex.decode("b1656851699e29fa24b70148503d2dfc")),
            "2a78421b87c7d0924f26113f1d1349b2",
            "e2f687e07b75660ffc372233bc47532c")
    };

    NoekeonTest()
    {
        super(tests, new NoekeonEngine(), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "Noekeon";
    }

    public static void main(
        String[]    args)
    {
        runTest(new NoekeonTest());
    }
}
