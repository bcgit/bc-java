package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Threefish1024Test
    extends CipherTest
{
    // Test cases from skein_golden_kat_internals.txt in Skein 1.3 NIST CD
    static SimpleTest[] tests =
        {
            new BlockCipherVectorTest(0, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024),
                new TweakableBlockCipherParameters(
                    new KeyParameter(new byte[128]),
                    new byte[16]),
                "0000000000000000000000000000000000000000000000000000000000000000" +
                    "0000000000000000000000000000000000000000000000000000000000000000" +
                    "0000000000000000000000000000000000000000000000000000000000000000" +
                    "0000000000000000000000000000000000000000000000000000000000000000",
                "f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90d" +
                    "f0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a2" +
                    "0b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa" +
                    "9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e"),
            new BlockCipherVectorTest(1, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024),
                new TweakableBlockCipherParameters(
                    new KeyParameter(Hex.decode(
                        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
                            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f" +
                            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f" +
                            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")),
                    Hex.decode("000102030405060708090a0b0c0d0e0f")),
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
                    "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0" +
                    "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0" +
                    "9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180",
                "a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c" +
                    "94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd" +
                    "8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c8" +
                    "3313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde")
        };

    Threefish1024Test()
    {
        super(tests, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024), new KeyParameter(new byte[128]));
    }

    public String getName()
    {
        return "Threefish-1024";
    }

    public static void main(
        String[] args)
    {
        runTest(new Threefish1024Test());
    }
}
