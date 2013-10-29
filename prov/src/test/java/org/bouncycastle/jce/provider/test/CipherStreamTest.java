package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * check that cipher input/output streams are working correctly
 */
public class CipherStreamTest
    extends SimpleTest
{

    private static byte[] RK = Hex.decode("0123456789ABCDEF");
    private static byte[] RIN = Hex.decode("4e6f772069732074");
    private static byte[] ROUT = Hex.decode("3afbb5c77938280d");

    private static byte[] SIN = Hex.decode(
                    "00000000000000000000000000000000"
                  + "00000000000000000000000000000000"
                  + "00000000000000000000000000000000"
                  + "00000000000000000000000000000000");
    private static final byte[] SK = Hex.decode("80000000000000000000000000000000");
    private static final byte[] SIV = Hex.decode("0000000000000000");
    private static final byte[] SOUT = Hex.decode(
          "4DFA5E481DA23EA09A31022050859936"
        + "DA52FCEE218005164F267CB65F5CFD7F"
        + "2B4F97E0FF16924A52DF269515110A07"
        + "F9E460BC65EF95DA58F740B7D1DBB0AA");

    private static final byte[] HCIN = new byte[64];
    private static final byte[] HCIV = new byte[32];

    private static final byte[] HCK256A = new byte[32];
    private static final byte[] HC256A = Hex.decode(
          "5B078985D8F6F30D42C5C02FA6B67951"
        + "53F06534801F89F24E74248B720B4818"
        + "CD9227ECEBCF4DBF8DBF6977E4AE14FA"
        + "E8504C7BC8A9F3EA6C0106F5327E6981");

    private static final byte[] HCK128A = new byte[16];
    private static final byte[] HC128A = Hex.decode(
          "82001573A003FD3B7FD72FFB0EAF63AA"
        + "C62F12DEB629DCA72785A66268EC758B"
        + "1EDB36900560898178E0AD009ABF1F49"
        + "1330DC1C246E3D6CB264F6900271D59C");

    private static final byte[] GRAIN_V1 = Hex.decode("0123456789abcdef1234");
    private static final byte[] GRAIN_V1_IV = Hex.decode("0123456789abcdef");
    private static final byte[] GRAIN_V1_IN = new byte[10];
    private static final byte[] GRAIN_V1_OUT = Hex.decode("7f362bd3f7abae203664");

    private static final byte[] GRAIN_128 = Hex.decode("0123456789abcdef123456789abcdef0");
    private static final byte[] GRAIN_128_IV = Hex.decode("0123456789abcdef12345678");
    private static final byte[] GRAIN_128_IN = new byte[16];
    private static final byte[] GRAIN_128_OUT = Hex.decode("afb5babfa8de896b4b9c6acaf7c4fbfd");

    public CipherStreamTest()
    {
    }

    private void runTest(
        String  name)
        throws Exception
    {
        String lCode = "ABCDEFGHIJKLMNOPQRSTUVWXY0123456789";
        KeyGenerator            kGen;

        if (name.indexOf('/') < 0)
        {
            kGen = KeyGenerator.getInstance(name, "BC");
        }
        else
        {
            kGen = KeyGenerator.getInstance(name.substring(0, name.indexOf('/')), "BC");
        }

        Cipher                  in = Cipher.getInstance(name, "BC");
        Cipher                  out = Cipher.getInstance(name, "BC");
        Key                     key = kGen.generateKey();
        ByteArrayInputStream    bIn = new ByteArrayInputStream(lCode.getBytes());
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        in.init(Cipher.ENCRYPT_MODE, key);
        if (in.getIV() != null)
        {
            out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(in.getIV()));
        }
        else
        {
            out.init(Cipher.DECRYPT_MODE, key);
        }

        CipherInputStream       cIn = new CipherInputStream(bIn, in);
        CipherOutputStream      cOut = new CipherOutputStream(bOut, out);

        int c;

        while ((c = cIn.read()) >= 0)
        {
            cOut.write(c);
        }

        cIn.close();

        cOut.flush();
        cOut.close();

        String  res = new String(bOut.toByteArray());

        if (!res.equals(lCode))
        {
            fail("Failed - decrypted data doesn't match.");
        }
    }

    private void testAlgorithm(String name, byte[] keyBytes, byte[] iv, byte[] plainText, byte[] cipherText)
        throws Exception
    {
        SecretKey key = new SecretKeySpec(keyBytes, name);
        Cipher    in = Cipher.getInstance(name, "BC");
        Cipher    out = Cipher.getInstance(name, "BC");

        if (iv != null)
        {
            in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }
        else
        {
            in.init(Cipher.ENCRYPT_MODE, key);
            out.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] enc = in.doFinal(plainText);
        if (!areEqual(enc, cipherText))
        {
            fail(name + ": cipher text doesn't match");
        }

        byte[] dec = out.doFinal(enc);

        if (!areEqual(dec, plainText))
        {
            fail(name + ": plain text doesn't match");
        }
    }

    private void testException(
        String  name)
    {
        try
        {
            byte[] key128 = {
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143,
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143 };

            byte[] key256 = {
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143,
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143,
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143,
                    (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143 };

            byte[] keyBytes;
            if (name.equals("HC256"))
            {
                keyBytes = key256;
            }
            else
            {
                keyBytes = key128;
            }

            SecretKeySpec cipherKey = new SecretKeySpec(keyBytes, name);
            Cipher ecipher = Cipher.getInstance(name, "BC");
            ecipher.init(Cipher.ENCRYPT_MODE, cipherKey);

            byte[] cipherText = new byte[0];
            try
            {
                // According specification Method engineUpdate(byte[] input,
                // int inputOffset, int inputLen, byte[] output, int
                // outputOffset)
                // throws ShortBufferException - if the given output buffer is
                // too
                // small to hold the result
                ecipher.update(new byte[20], 0, 20, cipherText);

                fail("failed exception test - no ShortBufferException thrown");
            }
            catch (ShortBufferException e)
            {
                // ignore
            }

            try
            {
                Cipher c = Cipher.getInstance(name, "BC");

                Key k = new PublicKey()
                {

                    public String getAlgorithm()
                    {
                        return "STUB";
                    }

                    public String getFormat()
                    {
                        return null;
                    }

                    public byte[] getEncoded()
                    {
                        return null;
                    }

                };

                c.init(Cipher.ENCRYPT_MODE, k);

                fail("failed exception test - no InvalidKeyException thrown for public key");
            }
            catch (InvalidKeyException e)
            {
                // okay
            }

            try
            {
                Cipher c = Cipher.getInstance(name, "BC");

                Key k = new PrivateKey()
                {

                    public String getAlgorithm()
                    {
                        return "STUB";
                    }

                    public String getFormat()
                    {
                        return null;
                    }

                    public byte[] getEncoded()
                    {
                        return null;
                    }

                };

                c.init(Cipher.DECRYPT_MODE, k);

                fail("failed exception test - no InvalidKeyException thrown for private key");
            }
            catch (InvalidKeyException e)
            {
                // okay
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }
    }

    public void performTest()
        throws Exception
    {
        runTest("RC4");
        testException("RC4");
        testAlgorithm("RC4", RK, null, RIN, ROUT);
        runTest("Salsa20");
        testException("Salsa20");
        testAlgorithm("Salsa20", SK, SIV, SIN, SOUT);
        runTest("XSalsa20");
        testException("XSalsa20");
        testAlgorithm("XSalsa20", SK, SIV, SIN, SOUT);
        runTest("ChaCha");
        testException("ChaCha");
        testAlgorithm("ChaCha", SK, SIV, SIN, SOUT);
        runTest("HC128");
        testException("HC128");
        testAlgorithm("HC128", HCK128A, HCIV, HCIN, HC128A);
        runTest("HC256");
        testException("HC256");
        testAlgorithm("HC256", HCK256A, HCIV, HCIN, HC256A);
        runTest("VMPC");
        testException("VMPC");
        //testAlgorithm("VMPC", a, iv, in, a);
        runTest("VMPC-KSA3");
        testException("VMPC-KSA3");
        //testAlgorithm("VMPC-KSA3", a, iv, in, a);
        testAlgorithm("Grainv1", GRAIN_V1, GRAIN_V1_IV, GRAIN_V1_IN, GRAIN_V1_OUT);
        testAlgorithm("Grain128", GRAIN_128, GRAIN_128_IV, GRAIN_128_IN, GRAIN_128_OUT);
        runTest("DES/ECB/PKCS7Padding");
        runTest("DES/CFB8/NoPadding");
    }

    public String getName()
    {
        return "CipherStreamTest";
    }


    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CipherStreamTest());
    }
}
