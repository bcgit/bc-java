package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Threefish256Test
    extends CipherTest
{
    // Test cases from skein_golden_kat_internals.txt in Skein 1.3 NIST CD
    static SimpleTest[] tests =
        {
            new BlockCipherVectorTest(0, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256),
                new TweakableBlockCipherParameters(
                    new KeyParameter(new byte[32]),
                    new byte[16]),
                "0000000000000000000000000000000000000000000000000000000000000000",
                "84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8"),
            new BlockCipherVectorTest(1, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256),
                new TweakableBlockCipherParameters(
                    new KeyParameter(Hex.decode(
                        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")),
                    Hex.decode("000102030405060708090a0b0c0d0e0f")),
                "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
                "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df")
        };

    Threefish256Test()
    {
        super(tests, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256), new KeyParameter(new byte[32]));
    }

    public String getName()
    {
        return "Threefish-256";
    }

    public static void main(
        String[] args)
    {
        runTest(new Threefish256Test());
    }
}
