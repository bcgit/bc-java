package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GCTRBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * @author MikeSafonov
 */
public class GOST3412Test extends CipherTest {

    static SimpleTest[] tests = {

        new BlockCipherVectorTest(1, new GOST3412_2015Engine(),
            new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
            "1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"),


        new BlockCipherVectorTest(2, new CFBBlockCipher(new GOST3412_2015Engine(), 128),
            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")), "1122334455667700ffeeddccbbaa9988", "81800a59b1842b24ff1f795e897abd95"),

        new BlockCipherVectorTest(3, new OFBBlockCipher(new GOST3412_2015Engine(), 128),
            new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
                Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819")),
            "1122334455667700ffeeddccbbaa9988", "81800a59b1842b24ff1f795e897abd95"),


//                new BlockCipherVectorTest(2, new GCTRBlockCipher(new GOST3412_2015Engine(), 16),
//                    new ParametersWithIV(new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")),
//                        Hex.decode("1234567890abcef0")),
//                    "1122334455667700ffeeddccbbaa9988", "f195d8bec10ed1dbd57b5fa240bda1b8"),

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

    }

    public static void main(
        String[] args) {
        runTest(new GOST3412Test());
    }
}
