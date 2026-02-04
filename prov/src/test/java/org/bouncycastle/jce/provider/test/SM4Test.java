package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.TestFailedException;

/**
 * basic test class for SM4
 */
public class SM4Test
    extends BaseBlockCipherTest
{
    static String[] cipherTests =
    {
        "128",
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246"
    };

    public SM4Test()
    {
        super("SM4");
    }

    public void test(
        int         strength,
        byte[]      keyBytes,
        byte[]      input,
        byte[]      output)
        throws Exception
    {
        Key key;
        Cipher in, out;
        CipherInputStream cIn;
        CipherOutputStream cOut;
        ByteArrayInputStream bIn;
        ByteArrayOutputStream bOut;

        key = new SecretKeySpec(keyBytes, "SM4");

        in = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
        out = Cipher.getInstance("SM4/ECB/NoPadding", "BC");

        try
        {
            out.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("SM4 failed initialisation - " + e.toString(), e);
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("SM4 failed initialisation - " + e.toString(), e);
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
            fail("SM4 failed encryption - " + e.toString(), e);
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("SM4 failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
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
            fail("SM4 failed encryption - " + e.toString(), e);
        }

        if (!areEqual(bytes, input))
        {
            fail("SM4 failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    public void performTest()
        throws Exception
    {
        wrapTest(1, "SM4WRAP", Hex.decode("0123456789abcdeffedcba9876543210"), null,
            null, Hex.decode("0123456789abcdeffedcba9876543210"), Hex.decode("5d9c31d2f37a186c13943c7e650fbcf895a91f670b7b92bd"));
        wrapTest(2, "SM4WRAPPAD", Hex.decode("0123456789abcdeffedcba9876543210"), null,
            null, Hex.decode("0123456789abcdeffedcba9876543210"), Hex.decode("7d7110bfbdad2f7b453499338fd40f27014be97c0c69867a"));
        for (int i = 0; i != cipherTests.length; i += 4)
        {
            test(Integer.parseInt(cipherTests[i]),
                            Hex.decode(cipherTests[i + 1]),
                            Hex.decode(cipherTests[i + 2]),
                            Hex.decode(cipherTests[i + 3]));
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SM4Test());
    }
}
