package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * basic test class for the Shacal2 cipher, vector from NESSIE (Test vectors set 8, vector# 0)
 */
public class Shacal2Test
    extends SimpleTest
{
    static String[] cipherTests =
        {
            "512",
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "98BCC10405AB0BFC686BECECAAD01AC19B452511BCEB9CB094F905C51CA45430",
            "00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F",

        };

    public String getName()
    {
        return "Shacal2";
    }

    private static final int KEY_SIZE_BITS = 512;

    private static final byte[] TEST_BYTES = new byte[1536];

    private static final char[] TEST_PASSWORD = new char[1536];

    static
    {
        new SecureRandom().nextBytes(TEST_BYTES);
        int total = TEST_PASSWORD.length;
        for (char c = 'A'; c <= 'Z' && total > 0; TEST_PASSWORD[TEST_PASSWORD.length - total] = c, c++, total--)
        {
            ;
        }
    }

    private void blockTest()
        throws Exception
    {
        final byte[] salt = new byte[KEY_SIZE_BITS / 8];
        new SecureRandom().nextBytes(salt);

        final KeySpec keySpec = new PBEKeySpec(TEST_PASSWORD, salt, 262144, KEY_SIZE_BITS);
        final SecretKey secretKey = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2", "BC").
            generateSecret(keySpec).getEncoded(), "Shacal2");

        final Cipher cipher = Cipher.getInstance("Shacal2/CBC/ISO10126Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        final byte[] iv = cipher.getIV();
        final byte[] ciphertext = cipher.doFinal(TEST_BYTES);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        final byte[] cleartext = cipher.doFinal(ciphertext);

        if (!Arrays.areEqual(TEST_BYTES, cleartext))
        {
            fail("Invalid cleartext.");
        }
    }

    public void testECB(
        int strength,
        byte[] keyBytes,
        byte[] input,
        byte[] output)
        throws Exception
    {
        Key key;
        Cipher in, out;
        CipherInputStream cIn;
        CipherOutputStream cOut;
        ByteArrayInputStream bIn;
        ByteArrayOutputStream bOut;

        key = new SecretKeySpec(keyBytes, "Shacal2");

        in = Cipher.getInstance("Shacal2/ECB/NoPadding", "BC");
        out = Cipher.getInstance("Shacal2/ECB/NoPadding", "BC");
        try
        {
            out.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("Shacal2 failed initialisation - " + e.toString(), e);
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("Shacal2 failed initialisation - " + e.toString(), e);
        }

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        try
        {
            for (int i = 0; i != input.length / 2; i++)
            {
                cOut.write(input[i]);
            }
            cOut.write(input, input.length / 2, input.length - input.length / 2);
            cOut.close();
        }
        catch (IOException e)
        {
            fail("Shacal2 failed encryption - " + e.toString(), e);
        }

        byte[] bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("Shacal2 failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        try
        {
            DataInputStream dIn = new DataInputStream(cIn);

            bytes = new byte[input.length];

            for (int i = 0; i != input.length / 2; i++)
            {
                bytes[i] = (byte)dIn.read();
            }
            dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);
        }
        catch (Exception e)
        {
            fail("Shacal2 failed encryption - " + e.toString(), e);
        }

        if (!areEqual(bytes, input))
        {
            fail("Shacal2 failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != cipherTests.length; i += 4)
        {
            testECB(Integer.parseInt(cipherTests[i]),
                Hex.decode(cipherTests[i + 1]),
                Hex.decode(cipherTests[i + 2]),
                Hex.decode(cipherTests[i + 3]));
        }

        blockTest();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new Shacal2Test());
    }
}
