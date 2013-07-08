package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Threefish512Test
    extends CipherTest
{
    // Test cases from skein_golden_kat_internals.txt in Skein 1.3 NIST CD
    static SimpleTest[] tests =
        {
            new BlockCipherVectorTest(0, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512),
                new TweakableBlockCipherParameters(
                    new KeyParameter(new byte[64]),
                    new byte[16]),
                "0000000000000000000000000000000000000000000000000000000000000000" +
                    "0000000000000000000000000000000000000000000000000000000000000000",
                "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b" +
                    "7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),
            new BlockCipherVectorTest(1, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512),
                new TweakableBlockCipherParameters(
                    new KeyParameter(Hex.decode(
                        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
                            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")),
                    Hex.decode("000102030405060708090a0b0c0d0e0f")),
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
                    "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0",
                "e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779" +
                    "272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d")
        };

    Threefish512Test()
    {
        super(tests, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512), new KeyParameter(new byte[64]));
    }

    public String getName()
    {
        return "Threefish-512";
    }

    public static void main(
        String[] args)
    {
        runTest(new Threefish512Test());
    }
}
