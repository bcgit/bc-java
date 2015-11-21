package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class OCBTest
    extends SimpleTest
{
    public String getName()
    {
        return "OCB";
    }

    public void performTest()
        throws Exception
    {
        checkRegistrations();
    }

    private void checkRegistrations()
        throws Exception
    {
        String[] ciphers = new String[] { "AES", "NOEKEON", "Twofish", "CAST6", "SEED", "Tnepres", "Serpent", "RC6", "CAMELLIA" };
        String[] cipherText = new String[]
            {
                "BEA5E8798DBE7110031C144DA0B2612213CC8B747807121A4CBB3E4BD6B456AF",
                "a2545b927e0f2e6db2998e20b17d5fc0564dcab63b748327e2ef4eaed88cb059",
                "1cfafe72f7181cae331610c116345e51fc356b379aca04da2a53337c5428d8e4",
                "5b9b738b2ac7000b33b89dd4eec18dd853f4f7c1d9e17b565405f17a0a8c8b63",
                "fcdbcee69d02c69858ed4569f78b81920b3027cdb7f1f154634aa5ace9e6ba29",
                "4f7154cb34558940e85db7d3e96ac6c9cb0d9c1b00b18e82e15d1be83deef9df",
                "3dd3477801e71807ea1f1f690d8428ed6b1002831428a64f88c36b6d5610022f",
                "23f3e450c4c7199563a0ed601a5c60d75eb88db2a0d090ae5e84d98438a146aa",
                "ac13ce9db4af148e910a813fc728e5785e23b1bf1d04a961a3f95f356b9417ab"
            };

        for (int i = 0; i < ciphers.length; i++)
        {
            ocbTest(ciphers[i], cipherText[i]);
        }
    }

    private void ocbTest(String cipher, String cText)
        throws Exception
    {
        byte[] K = Hex.decode(
              "000102030405060708090A0B0C0D0E0F");
        byte[] P = Hex.decode(
              "000102030405060708090A0B0C0D0E0F");
        byte[] N = Hex.decode("000102030405060708090A0B");
        String T = "4CBB3E4BD6B456AF";
        byte[] C = Hex.decode(cText);

        Key key;
        Cipher                  in, out;

        key = new SecretKeySpec(K, cipher);

        in = Cipher.getInstance(cipher + "/OCB/NoPadding", "BC");
        out = Cipher.getInstance(cipher + "/OCB/NoPadding", "BC");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        byte[] enc = in.doFinal(P);
        if (!areEqual(enc, C))
        {
            fail("ciphertext doesn't match in OCB got " + new String(Hex.encode(enc)));
        }

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

        byte[] dec = out.doFinal(C);
        if (!areEqual(dec, P))
        {
            fail("plaintext doesn't match in OCB");
        }

        try
        {
            in = Cipher.getInstance(cipher + "/OCB/PKCS5Padding", "BC");

            fail("bad padding missed in OCB");
        }
        catch (NoSuchPaddingException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OCBTest());
    }
}