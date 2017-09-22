package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.*;
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

//        new BlockCipherVectorTest(1, new GOST3412_2015Engine(),
//            new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
//            "1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"),
//
//
        new BlockCipherVectorTest(2, new G3412CFBBlockCipher(new GOST3412_2015Engine(), 128, 256),
            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1"),
//
//        new BlockCipherVectorTest(3, new OFBBlockCipher(new GOST3412_2015Engine(), 128),
//            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
//                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
//            "1122334455667700ffeeddccbbaa9988", "81800a59b1842b24ff1f795e897abd95"),
//
//        new BlockCipherVectorTest(3, new OFBBlockCipher(new GOST3412_2015Engine(), 128),
//            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
//                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
//            "00112233445566778899aabbcceeff0a", "ed4a659440d99cc3072c8b8d517dd9b5"),


//                new BlockCipherVectorTest(2, new GCTRBlockCipher2(new GOST3412_2015Engine(), 16),
//                    new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
//                        Hex.decode("1234567890abcef0")),
//                    "1122334455667700ffeeddccbbaa9988", "f195d8bec10ed1dbd57b5fa240bda1b8"),

//        new BlockCipherVectorTest(4, new GCTRBlockCipher2(new GOST3412_2015Engine(), 16),
//            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
//                Hex.decode("1234567890abcef0")),
//            "00112233445566778899aabbcceeff0a", "85eee733f6a13e5df33ce4b33c45dee4\n"),

        // ==============

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


    private void cfbTest() throws Exception {

        // encryption test
        byte[] output = Hex.decode("4ffebecd4e922de6c75bd9dd44fbf4d1");

        BufferedBlockCipher cipher = new BufferedBlockCipher(new G3412CFBBlockCipher(new GOST3412_2015Engine(), 128, 256));

        cipher.init(true, new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
            Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")));

        byte[] out = new byte[output.length];

        for (int i = 0; i < inputs.length; i++) {
            cipher.processBytes(inputs[i], 0, inputs[i].length, out, 0);
        }

        cipher.doFinal(out, 0);

        if (!Arrays.areEqual(out, output)) {
            fail(getName() + ": Failed test 1 - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        // decryption test


        byte[][] C = new byte[][]{

            Hex.decode("81800a59b1842b24ff1f795e897abd95"),
            Hex.decode("ed5b47a7048cfab48fb521369d9326bf"),
            Hex.decode("79f2a8eb5cc68d38842d264e97a238b5"),
            Hex.decode("4ffebecd4e922de6c75bd9dd44fbf4d1")

        };

        output = Hex.decode("2233445566778899aabbcceeff0a0011");

        cipher = new BufferedBlockCipher(new G3412CFBBlockCipher(new GOST3412_2015Engine(), 128, 256));

        cipher.init(true, new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
            Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")));

        out = new byte[output.length];
        for (int i = 0; i < C.length; i++) {
            cipher.processBytes(C[i], 0, C[i].length, out, 0);
            System.out.println(Hex.toHexString(C[i]) + " ||||| " + Hex.toHexString(out));
        }

        cipher.doFinal(out, 0);

        if (!Arrays.areEqual(out, output)) {
            fail(getName() + ": Failed test 2 - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }




    }


    private void ofbTest() throws Exception {

        byte[][] inputs = new byte[][]{
            Hex.decode("1122334455667700ffeeddccbbaa9988"),
            Hex.decode("00112233445566778899aabbcceeff0a"),
            Hex.decode("112233445566778899aabbcceeff0a00"),
            Hex.decode("2233445566778899aabbcceeff0a0011")
        };

        byte[] output = Hex.decode("203ebbc066138660a0292243f6903150");

        BufferedBlockCipher cipher = new BufferedBlockCipher(new OFBBlockCipher(new GOST3412_2015Engine(), 128));

        cipher.init(true, new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
            Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")));

        byte[] out = new byte[output.length];
//        cipher.processBytes(inputs[3], 0, inputs[3].length, out, 0);
//
        for (int i = 0; i < inputs.length; i++) {
            cipher.processBytes(inputs[i], 0, inputs[i].length, out, 0);
            System.out.println(Hex.toHexString(inputs[i]) + " ||||| " + Hex.toHexString(out));
        }

        cipher.doFinal(out, 0);

        if (!Arrays.areEqual(out, output)) {
            fail(getName() + ": Failed test 1 - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }


    }


    public static void main(
        String[] args) {
        runTest(new GOST3412Test());
    }
}
