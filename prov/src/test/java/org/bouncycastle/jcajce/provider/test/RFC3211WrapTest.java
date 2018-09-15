package org.bouncycastle.jcajce.provider.test;


import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class RFC3211WrapTest
    extends TestCase
{
    private static final String BC = "BC";

    private static final Key KEY_AES128 = new SecretKeySpec(Hex.decode("c794a7735f469c59cf9d7ddd8c65201d"), "AES");
    private static final Key KEY_DES = new SecretKeySpec(Hex.decode("8ccbbc15340b46c7cee6e5b6d6b6bc3e08ea38b55d3e08d9"), "DES");

    private static final byte[] PLAIN = "abcdefgh".getBytes();

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testAESRFC3211()
        throws Exception
    {
        byte[][] res = wrap("AESRFC3211WRAP", KEY_AES128, PLAIN);
        byte[] rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

        assertTrue(Arrays.areEqual(PLAIN, rv));

        byte[] iv = Hex.decode("0f0e0d0c0b0a00010203040506070809");

        res = wrapWithIV("AESRFC3211WRAP", KEY_AES128, PLAIN, iv);

        assertTrue(Arrays.areEqual(iv, res[0]));

        rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

        assertTrue(Arrays.areEqual(PLAIN, rv));

        assertTrue(Arrays.areEqual(PLAIN, doWithAlgParams("AESRFC3211WRAP", KEY_AES128, PLAIN)));
    }

    public void testAESRFC3211Bounds()
        throws Exception
    {
        byte[] plain = genInput(255);
        byte[][] res = wrap("AESRFC3211WRAP", KEY_AES128, plain);
        byte[] rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

        assertTrue(Arrays.areEqual(plain, rv));

        plain = new byte[0];
        res = wrap("AESRFC3211WRAP", KEY_AES128, plain);
        rv = unwrap("AESRFC3211WRAP", KEY_AES128, res);

        assertTrue(Arrays.areEqual(plain, rv));
    }

    public void testAESRFC3211Exception()
        throws Exception
    {
        doExceptionTests("AESRFC3211WRAP", KEY_AES128);
    }

    public void testTDESRFC3211()
        throws Exception
    {
        byte[][] res = wrap("DESEDERFC3211WRAP", KEY_DES, PLAIN);
        byte[] rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

        assertTrue(Arrays.areEqual(PLAIN, rv));

        byte[] iv = Hex.decode("0102030405060708");

        res = wrapWithIV("DESEDERFC3211WRAP", KEY_DES, PLAIN, iv);

        assertTrue(Arrays.areEqual(iv, res[0]));

        rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

        assertTrue(Arrays.areEqual(PLAIN, rv));

        assertTrue(Arrays.areEqual(PLAIN, doWithAlgParams("DESEDERFC3211WRAP", KEY_DES, PLAIN)));
    }

    public void testTDESRFC3211Bounds()
        throws Exception
    {
        byte[] plain = genInput(255);
        byte[][] res = wrap("DESEDERFC3211WRAP", KEY_DES, plain);
        byte[] rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

        assertTrue(Arrays.areEqual(plain, rv));

        plain = new byte[0];
        res = wrap("DESEDERFC3211WRAP", KEY_DES, plain);
        rv = unwrap("DESEDERFC3211WRAP", KEY_DES, res);

        assertTrue(Arrays.areEqual(plain, rv));
    }

    public void testTDESRFC3211Exception()
        throws Exception
    {
        doExceptionTests("DESEDERFC3211WRAP", KEY_DES);
    }

    private static void doExceptionTests(String alg, Key key)
        throws Exception
    {
        byte[] plain = genInput(256);
        try
        {
            wrap(alg, key, plain);

            fail("no exception");
        }
        catch (IllegalBlockSizeException e)
        {
            assertEquals("input must be from 0 to 255 bytes", e.getMessage());
        }

        try
        {
            Cipher engine = Cipher.getInstance(alg, "BC");
            engine.init(Cipher.ENCRYPT_MODE, key);
            engine.doFinal(plain, 0, plain.length, new byte[500]);
            fail("no exception");
        }
        catch (IllegalBlockSizeException e)
        {
            assertEquals("input must be from 0 to 255 bytes", e.getMessage());
        }

        try
        {
            Cipher engine = Cipher.getInstance(alg, "BC");
            engine.init(Cipher.DECRYPT_MODE, key);
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("RFC3211Wrap requires an IV", e.getMessage());
        }
    }

    private static byte[] genInput(int len)
    {
        byte[] rv = new byte[len];

        for (int i = 0; i != len; i++)
        {
            rv[i] = (byte)i;
        }

        return rv;
    }

    private static byte[] doWithAlgParams(String algo, Key privKey, byte[] data)
        throws Exception
    {
        Cipher engine = Cipher.getInstance(algo, BC);
        engine.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] res = engine.doFinal(data);
        AlgorithmParameters algParams = engine.getParameters();
        engine = Cipher.getInstance(algo, BC);
        engine.init(Cipher.DECRYPT_MODE, privKey, algParams);

        return engine.doFinal(res);
    }

    private static byte[][] wrap(String algo, Key privKey, byte[] data)
        throws Exception
    {
        Cipher engine = Cipher.getInstance(algo, "BC");
        engine.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] res = engine.doFinal(data);
        return new byte[][]{engine.getIV(), res};
    }

    private static byte[][] wrapWithIV(String algo, Key privKey, byte[] data, byte[] iv)
        throws Exception
    {
        Cipher engine = Cipher.getInstance(algo, "BC");
        engine.init(Cipher.ENCRYPT_MODE, privKey, new IvParameterSpec(iv));
        byte[] res = engine.doFinal(data);
        return new byte[][]{engine.getIV(), res};
    }

    private static byte[] unwrap(String algo, Key privKey, byte[][] data)
        throws Exception
    {
        Cipher engine = Cipher.getInstance(algo, "BC");
        engine.init(Cipher.DECRYPT_MODE, privKey, new IvParameterSpec(data[0]));
        return engine.doFinal(data[1]);
    }
}