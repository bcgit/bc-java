package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * RC6 Test - test vectors from AES Submitted RSA Reference implementation.
 * ftp://ftp.funet.fi/pub/crypt/cryptography/symmetric/aes/rc6-unix-refc.tar
 */
public class RC6Test
    extends CipherTest
{
    static SimpleTest[]  tests = 
            {
                new BlockCipherVectorTest(0, new RC6Engine(),
                        new KeyParameter(
                            Hex.decode("00000000000000000000000000000000")),
                        "80000000000000000000000000000000",
                        "f71f65e7b80c0c6966fee607984b5cdf"),
                new BlockCipherVectorTest(1, new RC6Engine(),
                        new KeyParameter(
                            Hex.decode("000000000000000000000000000000008000000000000000")),
                        "00000000000000000000000000000000",
                        "dd04c176440bbc6686c90aee775bd368"),
                new BlockCipherVectorTest(2, new RC6Engine(),
                        new KeyParameter(
                            Hex.decode("000000000000000000000000000000000000001000000000")),
                        "00000000000000000000000000000000",
                        "937fe02d20fcb72f0f57201012b88ba4"),
                new BlockCipherVectorTest(3, new RC6Engine(),
                        new KeyParameter(
                            Hex.decode("00000001000000000000000000000000")),
                        "00000000000000000000000000000000",
                        "8a380594d7396453771a1dfbe2914c8e"),
                new BlockCipherVectorTest(4, new RC6Engine(),
                        new KeyParameter(
                            Hex.decode("1000000000000000000000000000000000000000000000000000000000000000")),
                        "00000000000000000000000000000000",
                        "11395d4bfe4c8258979ee2bf2d24dff4"),
                new BlockCipherVectorTest(5, new RC6Engine(),
                        new KeyParameter(
                            Hex.decode("0000000000000000000000000000000000080000000000000000000000000000")),
                        "00000000000000000000000000000000",
                        "3d6f7e99f6512553bb983e8f75672b97")
            };

    RC6Test()
    {
        super(tests, new RC6Engine(), new KeyParameter(new byte[32]));
    }

    public String getName()
    {
        return "RC6";
    }

    public static void main(
        String[]    args)
    {
        runTest(new RC6Test());
    }
}
