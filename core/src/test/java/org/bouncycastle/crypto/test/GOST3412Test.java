package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.G3413CBCBlockCipher;
import org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
import org.bouncycastle.crypto.modes.G3413CTRBlockCipher;
import org.bouncycastle.crypto.modes.G3413OFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class GOST3412Test
    extends CipherTest
{

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
        new BlockCipherVectorTest(2, new G3413CFBBlockCipher(new GOST3412_2015Engine()),
            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1"),

        new BlockCipherVectorTest(3, new G3413CFBBlockCipher(new GOST3412_2015Engine(), 8),
            new ParametersWithIV(
                new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "819b19c5867e61f1cf1b16f664f66e46ed8fcb82b1110b1e7ec03bfa6611f2eabd7a32363691cbdc3bbe403bc80552d822c2cdf483981cd71d5595453d7f057d"),

        // OFB
        new BlockCipherVectorTest(4, new G3413OFBBlockCipher(new GOST3412_2015Engine()),
            new ParametersWithIV(
                new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150"),

//CBC
        new BlockCipherVectorTest(5, new G3413CBCBlockCipher(new GOST3412_2015Engine()),
            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")), Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970"),
//CTR
        new BlockCipherVectorTest(6, new G3413CTRBlockCipher(new GOST3412_2015Engine()),
            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0")),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73"),
        new BlockCipherVectorTest(7, new G3413CTRBlockCipher(new GOST3412_2015Engine(), 8),
            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0")),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "f1a787ad3a88f9a0bc735293f98c12c3eb31621b9b2e6461c7ef73a2e6a6b1793ddf722f7b1d22a722ec4d3edbc313bcd356b313d37af9e5ef934fa223c13fe2")


    };


    protected GOST3412Test()
    {
        super(tests, new GOST3412_2015Engine(), new KeyParameter(new byte[32]));
    }

    public String getName()
    {
        return "GOST 34.12 2015";
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

//        cfbTest();
//        ofbTest();
    }

    public static void main(
        String[] args)
    {
        runTest(new GOST3412Test());
    }
}
