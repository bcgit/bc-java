package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * CMAC tester - <a href="https://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/tv/omac1-tv.txt">AES Official Test Vectors</a>.
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

    private static final byte[] general_input = Strings.toByteArray("The quick brown fox jumps over the lazy dog.");

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

        testCMac(Mac.getInstance("DESedeCMAC", "BC"), keyBytes128, "DESede", input0, output_des_ede);

        testCMac(Mac.getInstance("BlowfishCMAC", "BC"), "2b7e151628aed2a6abf7158809cf4f3c", "Blowfish", "875d73b9bc3de78a");
        testCMac(Mac.getInstance("SEED-CMAC", "BC"),  "2b7e151628aed2a6abf7158809cf4f3c", "SEED", "73624c03548a1aaeab9104e47fbd14b1");
        testCMac(Mac.getInstance("SM4-CMAC", "BC"),  "2b7e151628aed2a6abf7158809cf4f3c", "SM4", "25b84c0bb3f0cb0c285148a62a09940a");
        testCMac(Mac.getInstance("SHACAL-2CMAC", "BC"),  "2b7e151628aed2a6abf7158809cf4f3c", "SHACAL-2", "794b2766cd0d550877f1ded48ab74f9ddff20f32e6d69fae8a1ede4205e7d640");
        testCMac(Mac.getInstance("Threefish-256CMAC", "BC"),  "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c", "Threefish-256", "107a7afec4d17ba4a7bf6b80e5f34b39d066abf168d413ddd16d7ad97515bfff");
        testCMac(Mac.getInstance("Threefish-512CMAC", "BC"),  "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c", "Threefish-512", "b3499567f5846fa6de3bd3f8d885d726976026cd0b04ec2e95431d9aed7743b7c1629d5759b3bca48aeb0c76a905ddfed5cd45c598dfd41d3a9f5964b3a6c4cf");
        testCMac(Mac.getInstance("Threefish-1024CMAC", "BC"),  "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c",
            "Threefish-1024", "644009204fcf388e692f989c435a41b4218c6cb7ee3589170e3cf791d007f5c9fd0b389be769f144d36ea19b4c7489812a68c81ba7cc756c6d143a4bbe3175a415897b70f736cd4251b98cff3d357d0c2a1036d0df154bf6cf514c04ce01c1059002082c4792dbb4b7638aa04064d8b93c2c8fe5512f2e05d14ac9bf66397dea");
    }

    private void testCMac(Mac mac, String keyBytes, String algorithm, String expected)
        throws Exception
    {
        testCMac(mac, Hex.decode(keyBytes), algorithm, general_input, Hex.decode(expected));
    }

    private void testCMac(Mac mac, byte[] keyBytes, String algorithm, byte[] input, byte[] expected)
        throws Exception
    {
         Key key = new SecretKeySpec(keyBytes, algorithm);

         mac.init(key);

         mac.update(input, 0, input.length);

         byte[] out = new byte[mac.getMacLength()];

         mac.doFinal(out, 0);

         if (!areEqual(out, expected))
         {
             fail("Failed - expected " + new String(Hex.encode(expected))
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
