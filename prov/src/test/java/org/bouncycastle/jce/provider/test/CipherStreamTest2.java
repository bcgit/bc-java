package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class CipherStreamTest2
    extends SimpleTest
{
    private int streamSize;

    public String getName()
    {
        return "CipherStreamTest2";
    }

    private void testModes(String algo, String[] transforms, boolean authenticated)
        throws Exception
    {
        Key key = generateKey(algo);
        for (int i = 0; i != transforms.length; i++)
        {
            String transform = transforms[i];
            String cipherName = algo + transform;

            boolean cts = transform.indexOf("CTS") > -1;
            if (cts && streamSize < Cipher.getInstance(cipherName, "BC").getBlockSize())
            {
                continue;
            }
            testWriteRead(cipherName, key, authenticated, true, false);
            testWriteRead(cipherName, key, authenticated, true, true);
            testWriteRead(cipherName, key, authenticated, false, false);
            testWriteRead(cipherName, key, authenticated, false, true);
            testReadWrite(cipherName, key, authenticated, true, false);
            testReadWrite(cipherName, key, authenticated, true, true);
            testReadWrite(cipherName, key, authenticated, false, false);
            testReadWrite(cipherName, key, authenticated, false, true);

            if (!cts)
            {
                testWriteReadEmpty(cipherName, key, authenticated, true, false);
                testWriteReadEmpty(cipherName, key, authenticated, true, true);
                testWriteReadEmpty(cipherName, key, authenticated, false, false);
                testWriteReadEmpty(cipherName, key, authenticated, false, true);
            }



            if (authenticated)
            {
                boolean aeadAvailable = false;
                try
                {
                    this.getClass().getClassLoader().loadClass("javax.crypto.spec.GCMParameterSpec");
                    aeadAvailable = true;
                }
                catch (ClassNotFoundException e)
                {
                }

                testTamperedRead(cipherName, key, true, true);
                testTruncatedRead(cipherName, key, true, true);
                testTamperedWrite(cipherName, key, true, true);
                if (aeadAvailable)
                {
                    testTamperedRead(cipherName, key, true, false);
                    testTruncatedRead(cipherName, key, true, false);
                    testTamperedWrite(cipherName, key, true, false);
                }
            }
        }
    }

    private InputStream createInputStream(byte[] data, Cipher cipher, boolean useBc)
    {
        ByteArrayInputStream bytes = new ByteArrayInputStream(data);
        // cast required for earlier JDK
        return useBc ? (InputStream)new CipherInputStream(bytes, cipher) : (InputStream)new javax.crypto.CipherInputStream(bytes, cipher);
    }

    private OutputStream createOutputStream(ByteArrayOutputStream bytes, Cipher cipher, boolean useBc)
    {
        // cast required for earlier JDK
        return useBc ? (OutputStream)new CipherOutputStream(bytes, cipher) : (OutputStream)new javax.crypto.CipherOutputStream(bytes, cipher);
    }

    /**
     * Test tampering of ciphertext followed by read from decrypting CipherInputStream
     */
    private void testTamperedRead(String name, Key key, boolean authenticated, boolean useBc)
        throws Exception
    {
        Cipher encrypt = Cipher.getInstance(name, "BC");
        Cipher decrypt = Cipher.getInstance(name, "BC");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        if (encrypt.getIV() != null)
        {
            decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
        }
        else
        {
            decrypt.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] ciphertext = encrypt.doFinal(new byte[streamSize]);

        // Tamper
        ciphertext[0] += 1;

        InputStream input = createInputStream(ciphertext, decrypt, useBc);
        try
        {
            while (input.read() >= 0)
            {
            }
            fail("Expected invalid ciphertext after tamper and read : " + name, authenticated, useBc);
        }
        catch (InvalidCipherTextIOException e)
        {
            // Expected
        }
        catch (IOException e)       //     cause will be AEADBadTagException
        {
            // Expected
        }
        try
        {
            input.close();
        }
        catch (Exception e)
        {
            fail("Unexpected exception : " + name, e, authenticated, useBc);
        }
    }

    /**
     * Test truncation of ciphertext to make tag calculation impossible, followed by read from
     * decrypting CipherInputStream
     */
    private void testTruncatedRead(String name, Key key, boolean authenticated, boolean useBc)
        throws Exception
    {
        Cipher encrypt = Cipher.getInstance(name, "BC");
        Cipher decrypt = Cipher.getInstance(name, "BC");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        if (encrypt.getIV() != null)
        {
            decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
        }
        else
        {
            decrypt.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] ciphertext = encrypt.doFinal(new byte[streamSize]);

        // Truncate to just smaller than complete tag
        byte[] truncated = new byte[ciphertext.length - streamSize - 1];
        System.arraycopy(ciphertext, 0, truncated, 0, truncated.length);

        // Tamper
        ciphertext[0] += 1;

        InputStream input = createInputStream(truncated, decrypt, useBc);
        while (true)
        {
            int read = 0;
            try
            {
                read = input.read();
            }
            catch (InvalidCipherTextIOException e)
            {
                // Expected
                break;
            }
            catch (IOException e)
            {
                // Expected from JDK 1.7 on
                break;
            }
            catch (Exception e)
            {
                fail("Unexpected exception : " + name, e, authenticated, useBc);
                break;
            }
            if (read < 0)
            {
                fail("Expected invalid ciphertext after truncate and read : " + name, authenticated, useBc);
                break;
            }
        }
        try
        {
            input.close();
        }
        catch (Exception e)
        {
            fail("Unexpected exception : " + name, e, authenticated, useBc);
        }
    }

    /**
     * Test tampering of ciphertext followed by write to decrypting CipherOutputStream
     */
    private void testTamperedWrite(String name, Key key, boolean authenticated, boolean useBc)
        throws Exception
    {
        Cipher encrypt = Cipher.getInstance(name, "BC");
        Cipher decrypt = Cipher.getInstance(name, "BC");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        if (encrypt.getIV() != null)
        {
            decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
        }
        else
        {
            decrypt.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] ciphertext = encrypt.doFinal(new byte[streamSize]);

        // Tamper
        ciphertext[0] += 1;

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        OutputStream output = createOutputStream(plaintext, decrypt, useBc);

        for (int i = 0; i < ciphertext.length; i++)
        {
            output.write(ciphertext[i]);
        }
        try
        {
            output.close();
            fail("Expected invalid ciphertext after tamper and write : " + name, authenticated, useBc);
        }
        catch (InvalidCipherTextIOException e)
        {
            // Expected
        }
    }

    /**
     * Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
     */
    private void testWriteRead(String name, Key key, boolean authenticated, boolean useBc, boolean blocks)
        throws Exception
    {
        byte[] data = new byte[streamSize];
        for (int i = 0; i < data.length; i++)
        {
            data[i] = (byte)(i % 255);
        }

        testWriteRead(name, key, authenticated, useBc, blocks, data);
    }

    /**
     * Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
     */
    private void testWriteReadEmpty(String name, Key key, boolean authenticated, boolean useBc, boolean blocks)
        throws Exception
    {
        byte[] data = new byte[0];

        testWriteRead(name, key, authenticated, useBc, blocks, data);
    }

    private void testWriteRead(String name, Key key, boolean authenticated, boolean useBc, boolean blocks, byte[] data)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            Cipher encrypt = Cipher.getInstance(name, "BC");
            Cipher decrypt = Cipher.getInstance(name, "BC");
            encrypt.init(Cipher.ENCRYPT_MODE, key);
            if (encrypt.getIV() != null)
            {
                decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
            }
            else
            {
                decrypt.init(Cipher.DECRYPT_MODE, key);
            }

            OutputStream cOut = createOutputStream(bOut, encrypt, useBc);
            if (blocks)
            {
                int chunkSize = Math.max(1, data.length / 8);
                for (int i = 0; i < data.length; i += chunkSize)
                {
                    cOut.write(data, i, Math.min(chunkSize, data.length - i));
                }
            }
            else
            {
                for (int i = 0; i < data.length; i++)
                {
                    cOut.write(data[i]);
                }
            }
            cOut.close();

            byte[] cipherText = bOut.toByteArray();
            bOut.reset();
            InputStream cIn = createInputStream(cipherText, decrypt, useBc);

            if (blocks)
            {
                byte[] block = new byte[encrypt.getBlockSize() + 1];
                int c;
                while ((c = cIn.read(block)) >= 0)
                {
                    bOut.write(block, 0, c);
                }
            }
            else
            {
                int c;
                while ((c = cIn.read()) >= 0)
                {
                    bOut.write(c);
                }

            }
            cIn.close();

        }
        catch (Exception e)
        {
            fail("Unexpected exception " + name, e, authenticated, useBc);
        }

        byte[] decrypted = bOut.toByteArray();
        if (!Arrays.areEqual(data, decrypted))
        {
            fail("Failed - decrypted data doesn't match: " + name, authenticated, useBc);
        }
    }

    protected void fail(String message, boolean authenticated, boolean bc)
    {
        if (bc || !authenticated)
        {
            super.fail(message);
        }
        else
        {
            // javax.crypto.CipherInputStream/CipherOutputStream
            // are broken wrt handling AEAD failures
            // System.err.println("Broken JCE Streams: " + message);
        }
    }

    protected void fail(String message, Throwable throwable, boolean authenticated, boolean bc)
    {
        if (bc || !authenticated)
        {
            super.fail(message, throwable);
        }
        else
        {
            // javax.crypto.CipherInputStream/CipherOutputStream
            // are broken wrt handling AEAD failures
            //System.err.println("Broken JCE Streams: " + message + " : " + throwable);
            throwable.printStackTrace();
        }
    }

    /**
     * Test CipherInputStream in ENCRYPT_MODE, CipherOutputStream in DECRYPT_MODE
     */
    private void testReadWrite(String name, Key key, boolean authenticated, boolean useBc, boolean blocks)
        throws Exception
    {
        String lCode = "ABCDEFGHIJKLMNOPQRSTU";

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            Cipher in = Cipher.getInstance(name, "BC");
            Cipher out = Cipher.getInstance(name, "BC");
            in.init(Cipher.ENCRYPT_MODE, key);
            if (in.getIV() != null)
            {
                out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(in.getIV()));
            }
            else
            {
                out.init(Cipher.DECRYPT_MODE, key);
            }

            InputStream cIn = createInputStream(lCode.getBytes(), in, useBc);
            OutputStream cOut = createOutputStream(bOut, out, useBc);

            if (blocks)
            {
                byte[] block = new byte[in.getBlockSize() + 1];
                int c;
                while ((c = cIn.read(block)) >= 0)
                {
                    cOut.write(block, 0, c);
                }
            }
            else
            {
                int c;
                while ((c = cIn.read()) >= 0)
                {
                    cOut.write(c);
                }
            }

            cIn.close();

            cOut.flush();
            cOut.close();

        }
        catch (Exception e)
        {
            fail("Unexpected exception " + name, e, authenticated, useBc);
        }

        String res = new String(bOut.toByteArray());
        if (!res.equals(lCode))
        {
            fail("Failed - decrypted data doesn't match: " + name, authenticated, useBc);
        }
    }

    private static Key generateKey(String name)
        throws Exception
    {
        KeyGenerator kGen;

        if (name.indexOf('/') < 0)
        {
            kGen = KeyGenerator.getInstance(name, "BC");
        }
        else
        {
            kGen = KeyGenerator.getInstance(name.substring(0, name.indexOf('/')), "BC");
        }
        return kGen.generateKey();
    }

    public void performTest()
        throws Exception
    {
        int[] testSizes = new int[]{0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097};
        for (int i = 0; i < testSizes.length; i++)
        {
            this.streamSize = testSizes[i];
            performTests();
        }
    }

    private void performTests()
        throws Exception
    {
        final String[] blockCiphers64 = new String[]{"BLOWFISH", "DES", "DESEDE", "TEA", "CAST5", "RC2", "XTEA"};

        for (int i = 0; i != blockCiphers64.length; i++)
        {
            testModes(blockCiphers64[i], new String[]{
                "/ECB/PKCS5Padding",
                "/CBC/PKCS5Padding",
                "/OFB/NoPadding",
                "/CFB/NoPadding",
                "/CTS/NoPadding",}, false);
            testModes(blockCiphers64[i], new String[]{"/EAX/NoPadding"}, true);
        }

        final String[] blockCiphers128 = new String[]{
            "AES",
            "NOEKEON",
            "Twofish",
            "CAST6",
            "SEED",
            "Serpent",
            "RC6",
            "CAMELLIA"};

        for (int i = 0; i != blockCiphers128.length; i++)
        {
            testModes(blockCiphers128[i], new String[]{
                "/ECB/PKCS5Padding",
                "/CBC/PKCS5Padding",
                "/OFB/NoPadding",
                "/CFB/NoPadding",
                "/CTS/NoPadding",
                "/CTR/NoPadding",
                "/SIC/NoPadding"}, false);
            testModes(blockCiphers128[i], new String[]{"/CCM/NoPadding", "/EAX/NoPadding", "/GCM/NoPadding", "/OCB/NoPadding"}, true);
        }

        final String[] streamCiphers = new String[]{
            "ARC4",
            "SALSA20",
            "XSalsa20",
            "ChaCha",
            "ChaCha7539",
            "Grainv1",
            "Grain128",
            "HC128",
            "HC256"};

        for (int i = 0; i != streamCiphers.length; i++)
        {
            testModes(streamCiphers[i], new String[]{""}, false);
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new CipherStreamTest2());
    }

}
