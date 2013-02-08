package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * Camellia tester - vectors from https://www.cosic.esat.kuleuven.be/nessie/testvectors/ and RFC 3713
 */
public class CamelliaTest
    extends CipherTest
{
    static SimpleTest[]  tests = 
            {
                new BlockCipherVectorTest(0, new CamelliaEngine(),
                    new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                    "80000000000000000000000000000000", "07923A39EB0A817D1C4D87BDB82D1F1C"),
                new BlockCipherVectorTest(1, new CamelliaEngine(),
                    new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                    "00000000000000000000000000000000", "6C227F749319A3AA7DA235A9BBA05A2C"),
                new BlockCipherVectorTest(2, new CamelliaEngine(),
                        new KeyParameter(Hex.decode("0123456789abcdeffedcba9876543210")),
                        "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"),
                //
                // 192 bit
                //
                new BlockCipherVectorTest(3, new CamelliaEngine(),
                        new KeyParameter(Hex.decode("0123456789abcdeffedcba98765432100011223344556677")),
                        "0123456789abcdeffedcba9876543210", "b4993401b3e996f84ee5cee7d79b09b9"),
                new BlockCipherVectorTest(4, new CamelliaEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "00040000000000000000000000000000", "9BCA6C88B928C1B0F57F99866583A9BC"),
                new BlockCipherVectorTest(5, new CamelliaEngine(),
                        new KeyParameter(Hex.decode("949494949494949494949494949494949494949494949494")),
                        "636EB22D84B006381235641BCF0308D2", "94949494949494949494949494949494"),
                //
                // 256 bit
                //
                new BlockCipherVectorTest(6, new CamelliaEngine(),
                    new KeyParameter(Hex.decode("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")),
                    "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"),
                new BlockCipherVectorTest(7, new CamelliaEngine(),
                        new KeyParameter(Hex.decode("4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A")),
                        "057764FE3A500EDBD988C5C3B56CBA9A", "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A"),
                new BlockCipherVectorTest(8, new CamelliaEngine(),
                        new KeyParameter(Hex.decode("0303030303030303030303030303030303030303030303030303030303030303")),
                        "7968B08ABA92193F2295121EF8D75C8A", "03030303030303030303030303030303"),
            };

    CamelliaTest()
    {
        super(tests, new CamelliaEngine(), new KeyParameter(new byte[32]));
    }

    public String getName()
    {
        return "Camellia";
    }

    public static void main(
        String[]    args)
    {
        CamelliaTest    test = new CamelliaTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
