package org.bouncycastle.jce.provider.test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SipHash128Test
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        testMac();
        testKeyGenerator();
    }

    private void testKeyGenerator()
        throws NoSuchAlgorithmException,
        NoSuchProviderException
    {
        testKeyGen("SipHash128");
        testKeyGen("SipHash128-2-4");
        testKeyGen("SipHash128-4-8");
    }

    private void testKeyGen(String algorithm)
        throws NoSuchAlgorithmException,
        NoSuchProviderException
    {
        KeyGenerator kg = KeyGenerator.getInstance(algorithm, "BC");

        SecretKey key = kg.generateKey();

        if (!key.getAlgorithm().equalsIgnoreCase("SipHash128"))
        {
            fail("Unexpected algorithm name in key", "SipHash128", key.getAlgorithm());
        }
        if (key.getEncoded().length != 16)
        {
            fail("Expected 128 bit key");
        }
    }

    private void testMac()
        throws NoSuchAlgorithmException,
        NoSuchProviderException,
        InvalidKeyException
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] input = Hex.decode("000102030405060708090a0b0c0d0e");

        byte[] expected = Hex.decode("5493e99933b0a8117e08ec0f97cfc3d9");

        Mac mac = Mac.getInstance("SipHash128", "BC");

        mac.init(new SecretKeySpec(key, "SipHash128"));

        mac.update(input, 0, input.length);

        byte[] result = mac.doFinal();

        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for doFinal()");
        }

        mac.init(new SecretKeySpec(key, "SipHash128-2-4"));

        mac.update(input, 0, input.length);

        result = mac.doFinal();
        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for second doFinal()");
        }

        mac = Mac.getInstance("SipHash128-2-4", "BC");

        mac.init(new SecretKeySpec(key, "SipHash128-2-4"));

        mac.update(input, 0, input.length);

        result = mac.doFinal();
        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for alias");
        }

        // SipHash128 4-8
        expected = Hex.decode("284d03303a453a593d78f7fadc9062cb");

        mac = Mac.getInstance("SipHash128-4-8", "BC");

        mac.init(new SecretKeySpec(key, "SipHash128"));

        mac.update(input, 0, input.length);

        result = mac.doFinal();

        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for SipHash128 4-8");
        }
    }

    public String getName()
    {
        return "SipHash128";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SipHash128Test());
    }
}
