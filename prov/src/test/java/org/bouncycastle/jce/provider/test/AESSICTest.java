package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.RepeatedSecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * test vectors based on NIST Special Publication 800-38A,
 * "Recommendation for Block Cipher Modes of Operation"
 */
public class AESSICTest
    extends SimpleTest
{
    private byte[][]    keys =
                        {
                            Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"),
                            Hex.decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
                            Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                        };

    private byte[][]    plain =
                        {
                            Hex.decode("6bc1bee22e409f96e93d7e117393172a"),
                            Hex.decode("ae2d8a571e03ac9c9eb76fac45af8e51"),
                            Hex.decode("30c81c46a35ce411e5fbc1191a0a52ef"),
                            Hex.decode("f69f2445df4f9b17ad2b417be66c3710")
                        };

    private byte[][][]  cipher =
                        {
                            {
                                Hex.decode("874d6191b620e3261bef6864990db6ce"),
                                Hex.decode("9806f66b7970fdff8617187bb9fffdff"),
                                Hex.decode("5ae4df3edbd5d35e5b4f09020db03eab"),
                                Hex.decode("1e031dda2fbe03d1792170a0f3009cee")
                            },
                            {
                                Hex.decode("1abc932417521ca24f2b0459fe7e6e0b"),
                                Hex.decode("090339ec0aa6faefd5ccc2c6f4ce8e94"),
                                Hex.decode("1e36b26bd1ebc670d1bd1d665620abf7"),
                                Hex.decode("4f78a7f6d29809585a97daec58c6b050")
                            },
                            {
                                Hex.decode("601ec313775789a5b7a7f504bbf3d228"),
                                Hex.decode("f443e3ca4d62b59aca84e990cacaf5c5"),
                                Hex.decode("2b0930daa23de94ce87017ba2d84988d"),
                                Hex.decode("dfc9c58db67aada613c2dd08457941a6")
                            }
                        };

    public String getName()
    {
        return "AESSIC";
    }

    public void performTest()
        throws Exception
    {
        Cipher c = Cipher.getInstance("AES/SIC/NoPadding", "BC");

        //
        // NIST vectors
        //
        for (int i = 0; i != keys.length; i++)
        {
            Key sk = new SecretKeySpec(keys[i], "AES");
            c.init(
                Cipher.ENCRYPT_MODE, sk,
            new IvParameterSpec(Hex.decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")));

            for (int j = 0; j != plain.length; j++)
            {
                byte[] crypt = c.update(plain[j]);
                if (!areEqual(crypt, cipher[i][j]))
                {
                    fail("AESSIC encrypt failed: key " + i + " block " + j);
                }
            }

            c.init(
                Cipher.DECRYPT_MODE, sk,
            new IvParameterSpec(Hex.decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")));

            for (int j = 0; j != plain.length; j++)
            {
                byte[] crypt = c.update(cipher[i][j]);
                if (!areEqual(crypt, plain[j]))
                {
                    fail("AESSIC decrypt failed: key " + i + " block " + j);
                }
            }
        }

        //
        // check CTR also recognised.
        //
        c = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        Key sk = new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES");

        c.init(
            Cipher.ENCRYPT_MODE, sk,
            new IvParameterSpec(Hex.decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001")));

        byte[] crypt = c.doFinal(Hex.decode("00000000000000000000000000000000"));

        if (!areEqual(crypt, Hex.decode("D23513162B02D0F72A43A2FE4A5F97AB")))
        {
            fail("AESSIC failed test 2");
        }
        
        //
        // check partial block processing
        //
        c = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        sk = new SecretKeySpec(Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), "AES");

        c.init(
            Cipher.ENCRYPT_MODE, sk,
            new IvParameterSpec(Hex.decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001")));

        crypt = c.doFinal(Hex.decode("12345678"));

        c.init(
                Cipher.DECRYPT_MODE, sk,
                new IvParameterSpec(Hex.decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001")));
        
        crypt = c.doFinal(crypt);
        
        if (!areEqual(crypt, Hex.decode("12345678")))
        {
            fail("AESSIC failed partial test");
        }

        // null key test
        sk = new RepeatedSecretKeySpec("AES");

        c.init(
                Cipher.ENCRYPT_MODE, sk,
        new IvParameterSpec(Hex.decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")));

        for (int j = 0; j != plain.length; j++)
        {
            crypt = c.update(plain[j]);
            if (!areEqual(crypt, cipher[0][j]))
            {
                fail("AESSIC encrypt failed: key " + 0 + " block " + j);
            }
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AESSICTest());
    }
}
