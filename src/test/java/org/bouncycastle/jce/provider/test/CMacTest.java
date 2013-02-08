package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * CMAC tester - <a href="http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/tv/omac1-tv.txt">AES Official Test Vectors</a>.
 */
public class CMacTest
    extends SimpleTest
{
    private static final byte[] keyBytes128 = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    private static final byte[] keyBytes192 = Hex.decode(
              "8e73b0f7da0e6452c810f32b809079e5"
            + "62f8ead2522c6b7b");
    private static final byte[] keyBytes256 = Hex.decode(
              "603deb1015ca71be2b73aef0857d7781"
            + "1f352c073b6108d72d9810a30914dff4");

    private static final byte[] input0 = Hex.decode("");
    private static final byte[] input16 = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    private static final byte[] input40 = Hex.decode(
              "6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    private static final byte[] input64 = Hex.decode(
              "6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e51"
            + "30c81c46a35ce411e5fbc1191a0a52ef"
            + "f69f2445df4f9b17ad2b417be66c3710");

    private static final byte[] output_k128_m0 = Hex.decode("bb1d6929e95937287fa37d129b756746");
    private static final byte[] output_k128_m16 = Hex.decode("070a16b46b4d4144f79bdd9dd04a287c");
    private static final byte[] output_k128_m40 = Hex.decode("dfa66747de9ae63030ca32611497c827");
    private static final byte[] output_k128_m64 = Hex.decode("51f0bebf7e3b9d92fc49741779363cfe");

    private static final byte[] output_k192_m0 = Hex.decode("d17ddf46adaacde531cac483de7a9367");
    private static final byte[] output_k192_m16 = Hex.decode("9e99a7bf31e710900662f65e617c5184");
    private static final byte[] output_k192_m40 = Hex.decode("8a1de5be2eb31aad089a82e6ee908b0e");
    private static final byte[] output_k192_m64 = Hex.decode("a1d5df0eed790f794d77589659f39a11");

    private static final byte[] output_k256_m0 = Hex.decode("028962f61b7bf89efc6b551f4667d983");
    private static final byte[] output_k256_m16 = Hex.decode("28a7023f452e8f82bd4bf28d8c37c35c");
    private static final byte[] output_k256_m40 = Hex.decode("aaf3d8f1de5640c232f5b169b9c911e6");
    private static final byte[] output_k256_m64 = Hex.decode("e1992190549f6ed5696a2c056c315410");

    private final byte[] output_des_ede = Hex.decode("1ca670dea381d37c");

    public CMacTest()
    {
    }

    public void performTest()
        throws Exception
    {
        Mac mac = Mac.getInstance("AESCMAC", "BC");

        //128 bytes key

        SecretKeySpec key = new SecretKeySpec(keyBytes128, "AES");

        // 0 bytes message - 128 bytes key
        mac.init(key);

        mac.update(input0, 0, input0.length);

        byte[] out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k128_m0))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k128_m0))
                + " got " + new String(Hex.encode(out)));
        }

        // 16 bytes message - 128 bytes key
        mac.init(key);

        mac.update(input16, 0, input16.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k128_m16))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k128_m16))
                + " got " + new String(Hex.encode(out)));
        }

        // 40 bytes message - 128 bytes key
        mac.init(key);

        mac.update(input40, 0, input40.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k128_m40))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k128_m40))
                + " got " + new String(Hex.encode(out)));
        }

        // 64 bytes message - 128 bytes key
        mac.init(key);

        mac.update(input64, 0, input64.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k128_m64))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k128_m64))
                + " got " + new String(Hex.encode(out)));
        }

        //192 bytes key

        key = new SecretKeySpec(keyBytes192, "AES");

        // 0 bytes message - 192 bytes key
        mac.init(key);

        mac.update(input0, 0, input0.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k192_m0))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k192_m0))
                + " got " + new String(Hex.encode(out)));
        }

        // 16 bytes message - 192 bytes key
        mac.init(key);

        mac.update(input16, 0, input16.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k192_m16))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k192_m16))
                + " got " + new String(Hex.encode(out)));
        }

        // 40 bytes message - 192 bytes key
        mac.init(key);

        mac.update(input40, 0, input40.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k192_m40))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k192_m40))
                + " got " + new String(Hex.encode(out)));
        }

        // 64 bytes message - 192 bytes key
        mac.init(key);

        mac.update(input64, 0, input64.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k192_m64))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k192_m64))
                + " got " + new String(Hex.encode(out)));
        }

        //256 bytes key

        key = new SecretKeySpec(keyBytes256, "AES");

        // 0 bytes message - 256 bytes key
        mac.init(key);

        mac.update(input0, 0, input0.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k256_m0))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k256_m0))
                + " got " + new String(Hex.encode(out)));
        }

        // 16 bytes message - 256 bytes key
        mac.init(key);

        mac.update(input16, 0, input16.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k256_m16))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k256_m16))
                + " got " + new String(Hex.encode(out)));
        }

        // 40 bytes message - 256 bytes key
        mac.init(key);

        mac.update(input40, 0, input40.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k256_m40))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k256_m40))
                + " got " + new String(Hex.encode(out)));
        }

        // 64 bytes message - 256 bytes key
        mac.init(key);

        mac.update(input64, 0, input64.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_k256_m64))
        {
            fail("Failed - expected " + new String(Hex.encode(output_k256_m64))
                + " got " + new String(Hex.encode(out)));
        }

        mac = Mac.getInstance("DESedeCMAC", "BC");

        //DESede

        key = new SecretKeySpec(keyBytes128, "DESede");

        // 0 bytes message - 128 bytes key
        mac.init(key);

        mac.update(input0, 0, input0.length);

        out = new byte[mac.getMacLength()];

        mac.doFinal(out, 0);

        if (!areEqual(out, output_des_ede))
        {
            fail("Failed - expected " + new String(Hex.encode(output_des_ede))
                + " got " + new String(Hex.encode(out)));
        }
    }

    public String getName()
    {
        return "CMac";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CMacTest());
    }
}
