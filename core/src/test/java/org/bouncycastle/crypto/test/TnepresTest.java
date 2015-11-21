package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.TnepresEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors based on Floppy 4 of the Serpent AES submission.
 */
public class TnepresTest
    extends CipherTest
{
    static SimpleTest[]  tests = 
            {
               new BlockCipherVectorTest(0, new TnepresEngine(),
                       new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                      "00000000000000000000000000000000", "8910494504181950f98dd998a82b6749"),
                new BlockCipherVectorTest(1, new TnepresEngine(),
                       new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                      "80000000000000000000000000000000", "10b5ffb720b8cb9002a1142b0ba2e94a"),
                new BlockCipherVectorTest(2, new TnepresEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000008000000000000000000000", "4f057a42d8d5bd9746e434680ddcd5e5"),
                new BlockCipherVectorTest(3, new TnepresEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000400000000000", "99407bf8582ef12550886ef5b6f169b9"),
                new BlockCipherVectorTest(4, new TnepresEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "40000000000000000000000000000000", "d522a3b8d6d89d4d2a124fdd88f36896"),
                new BlockCipherVectorTest(5, new TnepresEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "00000000000200000000000000000000", "189b8ec3470085b3da97e82ca8964e32"),
                new BlockCipherVectorTest(6, new TnepresEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "00000000000000000000008000000000", "f77d868cf760b9143a89809510ccb099"),
                new BlockCipherVectorTest(7, new TnepresEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "08000000000000000000000000000000", "d43b7b981b829342fce0e3ec6f5f4c82"),
                new BlockCipherVectorTest(8, new TnepresEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "00000000000000000100000000000000", "0bf30e1a0c33ccf6d5293177886912a7"),
                new BlockCipherVectorTest(9, new TnepresEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "00000000000000000000000000000001", "6a7f3b805d2ddcba49b89770ade5e507"),
                new BlockCipherVectorTest(10, new TnepresEngine(),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "49afbfad9d5a34052cd8ffa5986bd2dd"),
                new BlockCipherVectorTest(11, new TnepresEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000004000000000000000000000")),
                        "00000000000000000000000000000000", "ba8829b1de058c4b48615d851fc74f17"),
                new BlockCipherVectorTest(12, new TnepresEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000100000000")),
                        "00000000000000000000000000000000", "89f64377bf1e8a46c8247044e8056a98"),
/*
                new BlockCipherMonteCarloTest(13, 10000, new TnepresEngine(),
                        new KeyParameter(Hex.decode("47f5f881daab9b67b43bd1342e339c19")),
                        "7a4f7db38c52a8b711b778a38d203b6b", "003380e19f10065740394f48e2fe80b7"),
*/
                new BlockCipherMonteCarloTest(13, 100, new TnepresEngine(),
                        new KeyParameter(Hex.decode("47f5f881daab9b67b43bd1342e339c19")),
                        "7a4f7db38c52a8b711b778a38d203b6b", "4db75303d815c2f7cc6ca935d1c5a046"),
/*
                new BlockCipherMonteCarloTest(14, 10000, new TnepresEngine(),
                        new KeyParameter(Hex.decode("31fba879ebc5e80df35e6fa33eaf92d6")),
                        "70a05e12f74589009692a337f53ff614", "afb5425426906db26b70bdf842ac5400"),
*/
                new BlockCipherMonteCarloTest(14, 100, new TnepresEngine(),
                        new KeyParameter(Hex.decode("31fba879ebc5e80df35e6fa33eaf92d6")),
                        "70a05e12f74589009692a337f53ff614", "fc53a50f4d3bc9836001893d2f41742d"),
/*
                new BlockCipherMonteCarloTest(15, 10000, new TnepresEngine(),
                        new KeyParameter(Hex.decode("bde6dd392307984695aee80e574f9977caae9aa78eda53e8")),
                        "9cc523d034a93740a0aa4e2054bb34d8", "1949d506ada7de1f1344986e8ea049b2"),
*/
                new BlockCipherMonteCarloTest(15, 100, new TnepresEngine(),
                        new KeyParameter(Hex.decode("bde6dd392307984695aee80e574f9977caae9aa78eda53e8")),
                        "9cc523d034a93740a0aa4e2054bb34d8", "77117e6a9e80f40b2a36b7d755573c2d"),
/*
                new BlockCipherMonteCarloTest(16, 10000, new TnepresEngine(),
                        new KeyParameter(Hex.decode("60f6f8ad4290699dc50921a1bbcca92da914e7d9cf01a9317c79c0af8f2487a1")),
                        "ee1a61106fae2d381d686cbf854bab65", "e57f45559027cb1f2ed9603d814e1c34"),
*/
                new BlockCipherMonteCarloTest(16, 100, new TnepresEngine(),
                        new KeyParameter(Hex.decode("60f6f8ad4290699dc50921a1bbcca92da914e7d9cf01a9317c79c0af8f2487a1")),
                        "ee1a61106fae2d381d686cbf854bab65", "dcd7f13ea0dcdfd0139d1a42e2ffb84b")
            };

    TnepresTest()
    {
        super(tests, new TnepresEngine(), new KeyParameter(new byte[32]));
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        doCbcMonte(new byte[16], new byte[16], new byte[16], Hex.decode("9ea101ecebaa41c712bcb0d9bab3e2e4"));
        doCbcMonte(Hex.decode("9ea101ecebaa41c712bcb0d9bab3e2e4"), Hex.decode("9ea101ecebaa41c712bcb0d9bab3e2e4"), Hex.decode("b4813d8a66244188b9e92c75913fa2f4"), Hex.decode("f86b2c265b9c75869f31e2c684c13e9f"));
    }

    private void doCbcMonte(byte[] key, byte[] iv, byte[] pt, byte[] expected)
    {
        BlockCipher c = new TnepresEngine();

        byte[] ct = new byte[16];

        System.arraycopy(iv, 0, ct, 0, 16);

        for (int i = 0; i < 10000; i++)
        {
            for (int k = 0; k != iv.length; k++)
            {
                iv[k] ^= pt[k];
            }
            System.arraycopy(ct, 0, pt, 0, 16);

            c.init(true, new KeyParameter(key));

            c.processBlock(iv, 0, ct, 0);

            System.arraycopy(ct, 0, iv, 0, 16);
        }

        if (!Arrays.areEqual(expected, ct))
        {
            fail("CBC monte test failed");
        }
    }

    public String getName()
    {
        return "Tnepres";
    }

    public static void main(
        String[]    args)
    {
        runTest(new TnepresTest());
    }
}
