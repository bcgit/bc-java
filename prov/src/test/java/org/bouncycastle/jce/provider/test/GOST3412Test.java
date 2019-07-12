package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * basic test class for the GOST28147 cipher
 */
public class GOST3412Test
    extends SimpleTest
{
    public String getName()
    {
        return "GOST3412";
    }

    public void testECB(
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

        key = new SecretKeySpec(keyBytes, "GOST3412-2015");

        in = Cipher.getInstance("GOST3412-2015/ECB/NoPadding", "BC");
        out = Cipher.getInstance("GOST3412-2015/ECB/NoPadding", "BC");
        out.init(Cipher.ENCRYPT_MODE, key);
        in.init(Cipher.DECRYPT_MODE, key);

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        for (int i = 0; i != input.length / 2; i++)
        {
            cOut.write(input[i]);
        }
        cOut.write(input, input.length / 2, input.length - input.length / 2);
        cOut.close();

        byte[] bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("GOST3412-2015 failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        DataInputStream dIn = new DataInputStream(cIn);

        bytes = new byte[input.length];

        for (int i = 0; i != input.length / 2; i++)
        {
            bytes[i] = (byte)dIn.read();
        }
        dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);

        if (!areEqual(bytes, input))
        {
            fail("GOST3412-2015 failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    public void testCFB(
        byte[] keyBytes,
        byte[] iv,
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

        key = new SecretKeySpec(keyBytes, "GOST3412-2015");

        in = Cipher.getInstance("GOST3412-2015/CFB8/NoPadding", "BC");
        out = Cipher.getInstance("GOST3412-2015/CFB8/NoPadding", "BC");

        out.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        in.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        for (int i = 0; i != input.length / 2; i++)
        {
            cOut.write(input[i]);
        }
        cOut.write(input, input.length / 2, input.length - input.length / 2);
        cOut.close();

        byte[] bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("GOST3412-2015 failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        DataInputStream dIn = new DataInputStream(cIn);

        bytes = new byte[input.length];

        for (int i = 0; i != input.length / 2; i++)
        {
            bytes[i] = (byte)dIn.read();
        }
        dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);

        if (!areEqual(bytes, input))
        {
            fail("GOST3412-2015 failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    private void testCTR()
        throws Exception
    {
        testG3413CTRInit(8);

        try
        {
            testG3413CTRInit(16);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue(e.getMessage().endsWith("IV must be 8 bytes long."));
        }
    }

    private void testG3413CTRInit(final int pIVLen)
        throws Exception
    {
        /* Create the generator and generate a key */
        KeyGenerator myGenerator = KeyGenerator.getInstance("GOST3412-2015", "BC");

        /* Initialise the generator */
        myGenerator.init(256);
        SecretKey myKey = myGenerator.generateKey();

        /* Create IV */
        byte[] myIV = new byte[pIVLen];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(myIV);

        /* Create a G3413CTR Cipher */
        Cipher myCipher = Cipher.getInstance("GOST3412-2015" + "/CTR/NoPadding", "BC");
        myCipher.init(Cipher.ENCRYPT_MODE, myKey, new IvParameterSpec(myIV));

        byte[] msg = Strings.toByteArray("G3413CTR JCA init Bug fixed");

        byte[] enc = myCipher.doFinal(msg);
        
        myCipher.init(Cipher.DECRYPT_MODE, myKey, new IvParameterSpec(myIV));

        byte[] dec = myCipher.doFinal(enc);

        isTrue(areEqual(msg, dec));
    }

    public void performTest()
        throws Exception
    {
        testECB(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
            Hex.decode("1122334455667700ffeeddccbbaa9988"), Hex.decode("7f679d90bebc24305a468d42b9d4edcd"));

        testCFB(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
             Hex.decode("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819"),
             Hex.decode("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011"), Hex.decode("819b19c5867e61f1cf1b16f664f66e46ed8fcb82b1110b1e7ec03bfa6611f2eabd7a32363691cbdc3bbe403bc80552d822c2cdf483981cd71d5595453d7f057d"));

        byte[][] inputs = new byte[][]{
            Hex.decode("1122334455667700ffeeddccbbaa9988"),
            Hex.decode("00112233445566778899aabbcceeff0a"),
            Hex.decode("112233445566778899aabbcceeff0a00"),
            Hex.decode("2233445566778899aabbcceeff0a0011"),
        };

        Mac mac = Mac.getInstance("GOST3412MAC", "BC");

        mac.init(new SecretKeySpec(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"), "GOST3412MAC"));

        for (int i = 0; i != inputs.length; i++)
        {
            mac.update(inputs[i]);
        }

        if (!Arrays.areEqual(Hex.decode("336f4d296059fbe34ddeb35b37749c67"), mac.doFinal()))
        {
            fail("mac test failed.");
        }

        testCTR();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new GOST3412Test());
    }
}
