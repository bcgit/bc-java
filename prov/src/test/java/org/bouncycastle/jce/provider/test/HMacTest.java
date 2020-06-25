package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HMAC tester
 */
public class HMacTest
    extends SimpleTest
{
    static byte[] keyBytes = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    static byte[] message = Hex.decode("4869205468657265");
    static byte[] output1 = Hex.decode("b617318655057264e28bc0b6fb378c8ef146be00");
    static byte[] outputMD5 = Hex.decode("5ccec34ea9656392457fa1ac27f08fbc");
    static byte[] outputMD2 = Hex.decode("dc1923ef5f161d35bef839ca8c807808");
    static byte[] outputMD4 = Hex.decode("5570ce964ba8c11756cdc3970278ff5a");
    static byte[] output224 = Hex.decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
    static byte[] output256 = Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    static byte[] output384 = Hex.decode("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    static byte[] output512 = Hex.decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    static byte[] output512_224 = Hex.decode("b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039");
    static byte[] output512_256 = Hex.decode("9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab");
    static byte[] outputRipeMD128 = Hex.decode("fda5717fb7e20cf05d30bb286a44b05d");
    static byte[] outputRipeMD160 = Hex.decode("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668");
    static byte[] outputTiger = Hex.decode("1d7a658c75f8f004916e7b07e2a2e10aec7de2ae124d3647");
    static byte[] outputOld384 = Hex.decode("0a046aaa0255e432912228f8ccda437c8a8363fb160afb0570ab5b1fd5ddc20eb1888b9ed4e5b6cb5bc034cd9ef70e40");
    static byte[] outputOld512 = Hex.decode("9656975ee5de55e75f2976ecce9a04501060b9dc22a6eda2eaef638966280182477fe09f080b2bf564649cad42af8607a2bd8d02979df3a980f15e2326a0a22a");

    static byte[] outputKck224 = Hex.decode("b73d595a2ba9af815e9f2b4e53e78581ebd34a80b3bbaac4e702c4cc");
    static byte[] outputKck256 = Hex.decode("9663d10c73ee294054dc9faf95647cb99731d12210ff7075fb3d3395abfb9821");
    static byte[] outputKck288 = Hex.decode("36145df8742160a1811139494d708f9a12757c30dedc622a98aa6ecb69da32a34ea55441");
    static byte[] outputKck384 = Hex.decode("892dfdf5d51e4679bf320cd16d4c9dc6f749744608e003add7fba894acff87361efa4e5799be06b6461f43b60ae97048");
    static byte[] outputKck512 = Hex.decode("8852c63be8cfc21541a4ee5e5a9a852fc2f7a9adec2ff3a13718ab4ed81aaea0b87b7eb397323548e261a64e7fc75198f6663a11b22cd957f7c8ec858a1c7755");

    static byte[] outputSha3_224 = Hex.decode("3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7");
    static byte[] outputSha3_256 = Hex.decode("ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb");
    static byte[] outputSha3_384 = Hex.decode("68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd");
    static byte[] outputSha3_512 = Hex.decode("eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e");

    static byte[] outputGost2012_256 = Hex.decode("f03422dfa37a507ca126ce01b8eba6b7fdda8f8a60dd8f2703e3a372120b8294");
    static byte[] outputGost2012_512 = Hex.decode("86b6a06bfa9f1974aff6ccd7fa3f835f0bd850395d6084efc47b9dda861a2cdf0dcaf959160733d5269f6567966dd7a9f932a77cd6f080012cd476f1c2cc31bb");

    static byte[] outputDSTU7564_256 = Hex.decode("98ac67aa21eaf6e8666fb748d66cfc15d5d66f5194c87fffa647e406d3375cdb");
    static byte[] outputDSTU7564_384 = Hex.decode("4e46a87e70fcd2ccfb4433a8eaec68991a96b11085c5d5484db71af51bac469c03f76e1f721843c8e8667708fe41a48d");
    static byte[] outputDSTU7564_512 = Hex.decode("5b7acf633a7551b8410fa66a60c74a494e46a87e70fcd2ccfb4433a8eaec68991a96b11085c5d5484db71af51bac469c03f76e1f721843c8e8667708fe41a48d");
    static byte[] outputSM3 = Hex.decode("51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70");

    public HMacTest()
    {
    }

    public void testHMac(
        String hmacName,
        byte[] output)
        throws Exception
    {
        SecretKey key = new SecretKeySpec(keyBytes, hmacName);
        byte[] out;
        Mac mac;

        mac = Mac.getInstance(hmacName, "BC");

        mac.init(key);

        mac.reset();

        mac.update(message, 0, message.length);

        out = mac.doFinal();

        if (!areEqual(out, output))
        {
            fail("Failed - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        // no key generator for the old algorithms
        if (hmacName.startsWith("Old"))
        {
            return;
        }

        KeyGenerator kGen = KeyGenerator.getInstance(hmacName, "BC");

        mac.init(kGen.generateKey());

        mac.update(message);

        out = mac.doFinal();
    }

    public void testHMac(
        String hmacName,
        int defKeySize,
        byte[] output)
        throws Exception
    {
        SecretKey key = new SecretKeySpec(keyBytes, hmacName);
        byte[] out;
        Mac mac;

        mac = Mac.getInstance(hmacName, "BC");

        mac.init(key);

        mac.reset();

        mac.update(message, 0, message.length);

        out = mac.doFinal();

        if (!areEqual(out, output))
        {
            fail("Failed - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        KeyGenerator kGen = KeyGenerator.getInstance(hmacName, "BC");

        SecretKey secretKey = kGen.generateKey();

        mac.init(secretKey);

        mac.update(message);

        out = mac.doFinal();

        isTrue("default key wrong length", secretKey.getEncoded().length == defKeySize / 8);
    }


    private void testExceptions()
        throws Exception
    {
        Mac mac = null;

        mac = Mac.getInstance("HmacSHA1", "BC");

        byte[] b = {(byte)1, (byte)2, (byte)3, (byte)4, (byte)5};
        SecretKeySpec sks = new SecretKeySpec(b, "HmacSHA1");
        RC5ParameterSpec algPS = new RC5ParameterSpec(100, 100, 100);

        try
        {
            mac.init(sks, algPS);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // ignore okay
        }

        try
        {
            mac.init(null, null);
        }
        catch (InvalidKeyException e)
        {
            // ignore okay
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // ignore okay
        }

        try
        {
            mac.init(null);
        }
        catch (InvalidKeyException e)
        {
            // ignore okay
        }
    }

    public void performTest()
        throws Exception
    {
        testHMac("HMac-SHA1", 160, output1);
        testHMac("HMac-MD5", outputMD5);
        testHMac("HMac-MD4", outputMD4);
        testHMac("HMac-MD2", outputMD2);
        testHMac("HMac-SHA224", 224, output224);
        testHMac("HMac-SHA256", 256, output256);
        testHMac("HMac-SHA384", 384, output384);
        testHMac("HMac-SHA512", 512, output512);
        testHMac("HMac-SHA512/224", output512_224);
        testHMac("HMac-SHA512/256", output512_256);
        testHMac("HMac-RIPEMD128", 128, outputRipeMD128);
        testHMac("HMac-RIPEMD160", 160, outputRipeMD160);
        testHMac("HMac-TIGER", 192, outputTiger);
        testHMac("HMac-KECCAK224", 224, outputKck224);
        testHMac("HMac-KECCAK256", 256, outputKck256);
        testHMac("HMac-KECCAK288", 288, outputKck288);
        testHMac("HMac-KECCAK384", 384, outputKck384);
        testHMac("HMac-KECCAK512", 512, outputKck512);
        testHMac("HMac-SHA3-224", 224, outputSha3_224);
        testHMac("HMac-SHA3-256", 256, outputSha3_256);
        testHMac("HMac-SHA3-384", 384, outputSha3_384);
        testHMac("HMac-SHA3-512", 512, outputSha3_512);

        testHMac("HMac-GOST3411-2012-256", 256, outputGost2012_256);
        testHMac("HMac-GOST3411-2012-512", 512, outputGost2012_512);

        testHMac("HMac-DSTU7564-256", 256, outputDSTU7564_256);
        testHMac("HMac-DSTU7564-384", 384, outputDSTU7564_384);
        testHMac("HMac-DSTU7564-512", 512, outputDSTU7564_512);

        testHMac("HMac/SHA1", output1);
        testHMac("HMac/MD5", outputMD5);
        testHMac("HMac/MD4", outputMD4);
        testHMac("HMac/MD2", outputMD2);
        testHMac("HMac/SHA224", 224, output224);
        testHMac("HMac/SHA256", 256, output256);
        testHMac("HMac/SHA384", 384, output384);
        testHMac("HMac/SHA512", 512, output512);
        testHMac("HMac/RIPEMD128", 128, outputRipeMD128);
        testHMac("HMac/RIPEMD160", 160, outputRipeMD160);
        testHMac("HMac/TIGER", 192, outputTiger);
        testHMac("HMac/KECCAK224", 224, outputKck224);
        testHMac("HMac/KECCAK256", 256, outputKck256);
        testHMac("HMac/KECCAK288", 288, outputKck288);
        testHMac("HMac/KECCAK384", 384, outputKck384);
        testHMac("HMac/KECCAK512", 512, outputKck512);
        testHMac("HMac/SHA3-224", 224, outputSha3_224);
        testHMac("HMac/SHA3-256", 256, outputSha3_256);
        testHMac("HMac/SHA3-384", 384, outputSha3_384);
        testHMac("HMac/SHA3-512", 512, outputSha3_512);
        testHMac("HMac/GOST3411-2012-256", 256, outputGost2012_256);
        testHMac("HMac/GOST3411-2012-512", 512, outputGost2012_512);
        testHMac("HMac/SM3", 256, outputSM3);

        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), 160, output1);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA224.getId(), 224, output224);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), 256, output256);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), 384, output384);
        testHMac(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), 512, output512);
        testHMac(IANAObjectIdentifiers.hmacSHA1.getId(), 160, output1);
        testHMac(IANAObjectIdentifiers.hmacMD5.getId(), outputMD5);
        testHMac(IANAObjectIdentifiers.hmacRIPEMD160.getId(), 160, outputRipeMD160);
        testHMac(IANAObjectIdentifiers.hmacTIGER.getId(), 192, outputTiger);

        testHMac(NISTObjectIdentifiers.id_hmacWithSHA3_224.getId(), 224, outputSha3_224);
        testHMac(NISTObjectIdentifiers.id_hmacWithSHA3_256.getId(), 256, outputSha3_256);
        testHMac(NISTObjectIdentifiers.id_hmacWithSHA3_384.getId(), 384, outputSha3_384);
        testHMac(NISTObjectIdentifiers.id_hmacWithSHA3_512.getId(), 512, outputSha3_512);

        testHMac(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_256.getId(), 256, outputGost2012_256);
        testHMac(RosstandartObjectIdentifiers.id_tc26_hmac_gost_3411_12_512.getId(), 512, outputGost2012_512);

        testHMac(UAObjectIdentifiers.dstu7564mac_256.getId(), 256, outputDSTU7564_256);
        testHMac(UAObjectIdentifiers.dstu7564mac_384.getId(), 384, outputDSTU7564_384);
        testHMac(UAObjectIdentifiers.dstu7564mac_512.getId(), 512, outputDSTU7564_512);

        testHMac(GMObjectIdentifiers.hmac_sm3.getId(), 256, outputSM3);

        // test for compatibility with broken HMac.
        testHMac("OldHMacSHA384", outputOld384);
        testHMac("OldHMacSHA512", outputOld512);

        testExceptions();

        testPBEWITHHMACSHAVariants();
    }

    private static final int[] SUN_JCA_VARIANTS = {
        1, 224, 256, 384, 512
    };

    private static final byte[][] SUN_JCA_KNOWN_ANSWERS_FOR_SHA_VARIANTS = {
        Hex.decode("2cb29f938331443af79de5863a1b072d57a4b640"),
        Hex.decode("3bf31c354fb1817503e9b581d4d1d51c4c8e921a3b46a513cc24c0ca"),
        Hex.decode("583697860e49d8d534ebdf99205173356f4e209447b6ac7d500ddddc1b382068"),
        Hex.decode("ad3ca42cc656876872bd0e5054d0f2260ec2a07635c5dfa655926989af392bbe636a23f08d1dc8ccd966ffa66ecc30e0"),
        Hex.decode("eabbb30bf280870530126bea40d3123c18d6bd6f6e9ded0eebd51a44d8527b27732206bd1bb7c1c8d941b5f2fba2f87ed49f5f1f3d7bef0e7547d335b4a55b87")
    };

    /**
     * Test that BC has the same results as the SunJCA provider for PBEwithHMACSHA.
     * <p>
     * Test courtesy of the Android project.
     * </p>
     */
    public void testPBEWITHHMACSHAVariants()
        throws Exception
    {
        byte[] plaintext = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34};
        byte[] salt = "saltsalt".getBytes();
        char[] password = "password".toCharArray();
        int iterationCount = 100;

        for (int shaVariantIndex = 0; shaVariantIndex < SUN_JCA_VARIANTS.length; shaVariantIndex++)
        {
            int shaVariant = SUN_JCA_VARIANTS[shaVariantIndex];
            SecretKeyFactory secretKeyFactory =
                SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA" + shaVariant, "BC");
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password,
                salt,
                iterationCount,
                // Key depending on block size!
                (shaVariant < 384) ? 64 : 128);
            SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
            Mac mac = Mac.getInstance("PBEWITHHMACSHA" + shaVariant, "BC");
            mac.init(secretKey);

            byte[] bcResult = mac.doFinal(plaintext);

            isTrue("value mismatch", Arrays.equals(SUN_JCA_KNOWN_ANSWERS_FOR_SHA_VARIANTS[shaVariantIndex], bcResult));
        }
    }

    public String getName()
    {
        return "HMac";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new HMacTest());
    }
}
