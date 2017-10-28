package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.GOST3412ParametersWithIV;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.SimpleTestResult;

/**
 * @author MikeSafonov
 */
public class GOST3412Test extends CipherTest {

    private byte[][] inputs = new byte[][]{
        Hex.decode("1122334455667700ffeeddccbbaa9988"),
        Hex.decode("00112233445566778899aabbcceeff0a"),
        Hex.decode("112233445566778899aabbcceeff0a00"),
        Hex.decode("2233445566778899aabbcceeff0a0011")
    };


    static SimpleTest[] tests = {

//         ECB
        new BlockCipherVectorTest(1, new GOST3412_2015Engine(),
            new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
            "1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"),

        // CFB
        new BlockCipherVectorTest(2, new G3412CFBStreamBlockCipher(new GOST3412_2015Engine()),
            new GOST3412ParametersWithIV(Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819"),
                new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                128, 256),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1"),
        // CFB STREAM
        new BlockCipherVectorTest(3, new G3412CFBBlockCipher(new GOST3412_2015Engine()),
            new GOST3412ParametersWithIV(Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819"),
                new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                128, 256),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1"),

        // OFB
        new BlockCipherVectorTest(4, new G3412OFBBlockCipher(new GOST3412_2015Engine()),
            new GOST3412ParametersWithIV(Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819"),
                new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                128, 256),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150"),

//CBC
        new BlockCipherVectorTest(5, new G3412CBCBlockCipher(new GOST3412_2015Engine()),
            new GOST3412ParametersWithIV(Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819"),
                new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")), 256),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970"),
//CTR
        new BlockCipherVectorTest(6, new G3412CTRBlockCipher(new GOST3412_2015Engine()),
            new GOST3412ParametersWithIV(Hex.decode("1234567890abcef0"),
                new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                128, 128),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73")


    };


    protected GOST3412Test() {
        super(tests, new GOST3412_2015Engine(), new KeyParameter(new byte[32]));
    }

    public String getName() {
        return "GOST 34.12 2015";
    }

    @Override
    public void performTest() throws Exception {
        super.performTest();

//        cfbTest();
//        ofbTest();
    }

    public static void main(
        String[] args) {
        runTest(new GOST3412Test());
    }
}
