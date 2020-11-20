package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * basic FIPS test class for a block cipher, just to make sure ECB/CBC/OFB/CFB are behaving
 * correctly. Tests from <a href=https://www.itl.nist.gov/fipspubs/fip81.htm>FIPS 81</a>.
 */
public class FIPSDESTest
    implements Test
{
    static String[] fips1Tests =
    {
        "DES/ECB/NoPadding",
        "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53",
        "DES/CBC/NoPadding",
        "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6",
        "DES/CFB/NoPadding",
        "f3096249c7f46e51a69e839b1a92f78403467133898ea622"
    };

    static String[] fips2Tests =
    {
        "DES/CFB8/NoPadding",
        "f31fda07011462ee187f",
        "DES/OFB8/NoPadding",
        "f34a2850c9c64985d684"
    };

    static byte[]   input1 = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");
    static byte[]   input2 = Hex.decode("4e6f7720697320746865");

    public String getName()
    {
        return "FIPSDESTest";
    }

    private boolean equalArray(
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

    public TestResult test(
        String      algorithm,
        byte[]      input,
        byte[]      output)
    {
        Key                     key;
        Cipher                  in, out;
        CipherInputStream       cIn;
        CipherOutputStream      cOut;
        ByteArrayInputStream    bIn;
        ByteArrayOutputStream   bOut;
        IvParameterSpec         spec = new IvParameterSpec(Hex.decode("1234567890abcdef"));

        try
        {
            String  baseAlgorithm;

            key = new SecretKeySpec(Hex.decode("0123456789abcdef"), "DES");

            in = Cipher.getInstance(algorithm, "BC");
            out = Cipher.getInstance(algorithm, "BC");

            if (algorithm.startsWith("DES/ECB"))
            {
                out.init(Cipher.ENCRYPT_MODE, key);
            }
            else
            {
                out.init(Cipher.ENCRYPT_MODE, key, spec);
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": " + algorithm + " failed initialisation - " + e.toString(), e);
        }

        try
        {
            if (algorithm.startsWith("DES/ECB"))
            {
                in.init(Cipher.DECRYPT_MODE, key);
            }
            else
            {
                in.init(Cipher.DECRYPT_MODE, key, spec);
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": " + algorithm + " failed initialisation - " + e.toString(), e);
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
            return new SimpleTestResult(false, getName() + ": " + algorithm + " failed encryption - " + e.toString());
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!equalArray(bytes, output))
        {
            return new SimpleTestResult(false, getName() + ": " + algorithm + " failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
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
            return new SimpleTestResult(false, getName() + ": " + algorithm + " failed encryption - " + e.toString());
        }

        if (!equalArray(bytes, input))
        {
            return new SimpleTestResult(false, getName() + ": " + algorithm + " failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }

        return new SimpleTestResult(true, getName() + ": " + algorithm + " Okay");
    }

    public TestResult perform()
    {
        for (int i = 0; i != fips1Tests.length; i += 2)
        {
            TestResult  result;

            result = test(fips1Tests[i], input1, Hex.decode(fips1Tests[i + 1]));
            if (!result.isSuccessful())
            {
                return result;
            }
        }

        for (int i = 0; i != fips2Tests.length; i += 2)
        {
            TestResult  result;

            result = test(fips2Tests[i], input2, Hex.decode(fips2Tests[i + 1]));
            if (!result.isSuccessful())
            {
                return result;
            }
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
        throws KeyException, InvalidAlgorithmParameterException
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new FIPSDESTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
