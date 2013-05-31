package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RSATest
    implements Test
{
    /**
     * a fake random number generator - we just want to make sure the random numbers
     * aren't random so that we get the same output, while still getting to test the
     * key generation facilities.
     */
    private class FixedSecureRandom
        extends SecureRandom
    {
        byte[]  seed = {
                (byte)0xaa, (byte)0xfd, (byte)0x12, (byte)0xf6, (byte)0x59,
                (byte)0xca, (byte)0xe6, (byte)0x34, (byte)0x89, (byte)0xb4,
                (byte)0x79, (byte)0xe5, (byte)0x07, (byte)0x6d, (byte)0xde,
                (byte)0xc2, (byte)0xf0, (byte)0x6c, (byte)0xb5, (byte)0x8f
        };

        public void nextBytes(
            byte[]  bytes)
        {
            int offset = 0;

            while ((offset + seed.length) < bytes.length)
            {
                System.arraycopy(seed, 0, bytes, offset, seed.length);
                offset += seed.length;
            }

            System.arraycopy(seed, 0, bytes, offset, bytes.length - offset);
        }
    }

    private boolean arrayEquals(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }


    private RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16));

    private RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    public TestResult perform()
    {
        try
        {
            KeyFactory          fact;
            byte[]              input = new byte[]
                                    { (byte)0x54, (byte)0x85, (byte)0x9b, (byte)0x34, (byte)0x2c, (byte)0x49, (byte)0xea, (byte)0x2a };
            byte[][]            output = new byte[][]
                                    {
                                        Hex.decode("8b427f781a2e59dd9def386f1956b996ee07f48c96880e65a368055ed8c0a8831669ef7250b40918b2b1d488547e72c84540e42bd07b03f14e226f04fbc2d929"),
                                        Hex.decode("2ec6e1a1711b6c7b8cd3f6a25db21ab8bb0a5f1d6df2ef375fa708a43997730ffc7c98856dbbe36edddcdd1b2d2a53867d8355af94fea3aeec128da908e08f4c"),
                                        Hex.decode("0850ac4e5a8118323200c8ed1e5aaa3d5e635172553ccac66a8e4153d35c79305c4440f11034ab147fccce21f18a50cf1c0099c08a577eb68237a91042278965")
                                    };
            SecureRandom        rand = new FixedSecureRandom();


            fact = KeyFactory.getInstance("RSA", "BC");

            PrivateKey  privKey = fact.generatePrivate(privKeySpec);
            PublicKey   pubKey = fact.generatePublic(pubKeySpec);

            //
            // No Padding
            //
            Cipher c = Cipher.getInstance("RSA//NoPadding", "BC");

            c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

            byte[]  out = c.doFinal(input);

            if (!arrayEquals(out, output[0]))
            {
                return new SimpleTestResult(false, "NoPadding test failed on encrypt expected " + new String(Hex.encode(output[0])) + " got " + new String(Hex.encode(out)));
            }

            c.init(Cipher.DECRYPT_MODE, privKey);

            out = c.doFinal(out);

            if (!arrayEquals(out, input))
            {
                return new SimpleTestResult(false, "NoPadding test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
            }

            //
            // PKCS1 V 1.5
            //
            c = Cipher.getInstance("RSA//PKCS1Padding", "BC");

            c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

            out = c.doFinal(input);

            if (!arrayEquals(out, output[1]))
            {
                return new SimpleTestResult(false, "PKCS1 test failed on encrypt expected " + new String(Hex.encode(output[1])) + " got " + new String(Hex.encode(out)));
            }

            c.init(Cipher.DECRYPT_MODE, privKey);

            out = c.doFinal(out);

            if (!arrayEquals(out, input))
            {
                return new SimpleTestResult(false, "PKCS1 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
            }

            //
            // OAEP
            //
            c = Cipher.getInstance("RSA//OAEPPadding", "BC");

            c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

            out = c.doFinal(input);

            if (!arrayEquals(out, output[2]))
            {
                return new SimpleTestResult(false, "OAEP test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
            }

            c.init(Cipher.DECRYPT_MODE, privKey);

            out = c.doFinal(out);

            if (!arrayEquals(out, input))
            {
                return new SimpleTestResult(false, "OAEP test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "RSATest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new RSATest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
