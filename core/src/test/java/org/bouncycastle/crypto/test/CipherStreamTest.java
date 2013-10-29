package org.bouncycastle.crypto.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.Grain128Engine;
import org.bouncycastle.crypto.engines.Grainv1Engine;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.NoekeonEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.TEAEngine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.engines.XTEAEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class CipherStreamTest
    extends SimpleTest
{

    @Override
    public String getName()
    {
        return "CipherStreamTest";
    }

    private void testMode(Object cipher, CipherParameters params)
        throws Exception
    {
        testWriteRead(cipher, params, false);
        testWriteRead(cipher, params, true);
        testReadWrite(cipher, params, false);
        testReadWrite(cipher, params, true);

        if (!(cipher instanceof CTSBlockCipher))
        {
            testWriteReadEmpty(cipher, params, false);
            testWriteReadEmpty(cipher, params, true);
        }

        if (cipher instanceof AEADBlockCipher)
        {
            testTamperedRead((AEADBlockCipher)cipher, params);
            testTruncatedRead((AEADBlockCipher)cipher, params);
            testTamperedWrite((AEADBlockCipher)cipher, params);
        }
    }

    private OutputStream createCipherOutputStream(OutputStream output, Object cipher)
    {
        if (cipher instanceof BufferedBlockCipher)
        {
            return new CipherOutputStream(output, (BufferedBlockCipher)cipher);
        }
        else if (cipher instanceof AEADBlockCipher)
        {
            return new CipherOutputStream(output, (AEADBlockCipher)cipher);
        }
        else
        {
            return new CipherOutputStream(output, (StreamCipher)cipher);
        }
    }

    private InputStream createCipherInputStream(byte[] data, Object cipher)
    {
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        if (cipher instanceof BufferedBlockCipher)
        {
            return new CipherInputStream(input, (BufferedBlockCipher)cipher);
        }
        else if (cipher instanceof AEADBlockCipher)
        {
            return new CipherInputStream(input, (AEADBlockCipher)cipher);
        }
        else
        {
            return new CipherInputStream(input, (StreamCipher)cipher);
        }
    }

    /**
     * Test tampering of ciphertext followed by read from decrypting CipherInputStream
     */
    private void testTamperedRead(AEADBlockCipher cipher, CipherParameters params)
        throws Exception
    {
        cipher.init(true, params);

        byte[] ciphertext = new byte[cipher.getOutputSize(1000)];
        cipher.doFinal(ciphertext, cipher.processBytes(new byte[1000], 0, 1000, ciphertext, 0));

        // Tamper
        ciphertext[0] += 1;

        cipher.init(false, params);
        InputStream input = createCipherInputStream(ciphertext, cipher);
        try
        {
            while (input.read() >= 0)
            {
            }
            fail("Expected invalid ciphertext after tamper and read : " + cipher.getAlgorithmName());
        } catch (InvalidCipherTextIOException e)
        {
            // Expected
        }
        try
        {
            input.close();
        } catch (Exception e)
        {
            fail("Unexpected exception after tamper and read : " + cipher.getAlgorithmName());
        }
    }

    /**
     * Test truncation of ciphertext to make tag calculation impossible, followed by read from
     * decrypting CipherInputStream
     */
    private void testTruncatedRead(AEADBlockCipher cipher, CipherParameters params)
        throws Exception
    {
        cipher.init(true, params);

        byte[] ciphertext = new byte[cipher.getOutputSize(1000)];
        cipher.doFinal(ciphertext, cipher.processBytes(new byte[1000], 0, 1000, ciphertext, 0));

        // Truncate to just smaller than complete tag
        byte[] truncated = new byte[ciphertext.length - 1000 - 1];
        System.arraycopy(ciphertext, 0, truncated, 0, truncated.length);

        cipher.init(false, params);
        InputStream input = createCipherInputStream(truncated, cipher);
        while (true)
        {
            int read = 0;
            try
            {
                read = input.read();
            } catch (InvalidCipherTextIOException e)
            {
                // Expected
                break;
            } catch (Exception e)
            {
                fail("Unexpected exception  on truncated read : " + cipher.getAlgorithmName());
                break;
            }
            if (read < 0)
            {
                fail("Expected invalid ciphertext after truncate and read : " + cipher.getAlgorithmName());
                break;
            }
        }
        try
        {
            input.close();
        } catch (Exception e)
        {
            fail("Unexpected exception after truncate and read : " + cipher.getAlgorithmName());
        }
    }

    /**
     * Test tampering of ciphertext followed by write to decrypting CipherOutputStream
     */
    private void testTamperedWrite(AEADBlockCipher cipher, CipherParameters params)
        throws Exception
    {
        cipher.init(true, params);

        byte[] ciphertext = new byte[cipher.getOutputSize(1000)];
        cipher.doFinal(ciphertext, cipher.processBytes(new byte[1000], 0, 1000, ciphertext, 0));

        // Tamper
        ciphertext[0] += 1;

        cipher.init(false, params);
        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        OutputStream output = createCipherOutputStream(plaintext, cipher);

        for (int i = 0; i < ciphertext.length; i++)
        {
            output.write(ciphertext[i]);
        }
        try
        {
            output.close();
            fail("Expected invalid ciphertext after tamper and write : " + cipher.getAlgorithmName());
        } catch (InvalidCipherTextIOException e)
        {
            // Expected
        }
    }

    /**
     * Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
     */
    private void testWriteRead(Object cipher, CipherParameters params, boolean blocks)
        throws Exception
    {
        byte[] data = new byte[1000];
        for (int i = 0; i < data.length; i++)
        {
            data[i] = (byte)(i % 255);
        }

        testWriteRead(cipher, params, blocks, data);
    }

    /**
     * Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
     */
    private void testWriteReadEmpty(Object cipher, CipherParameters params, boolean blocks)
        throws Exception
    {
        byte[] data = new byte[0];

        testWriteRead(cipher, params, blocks, data);
    }

    private void testWriteRead(Object cipher, CipherParameters params, boolean blocks, byte[] data)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            init(cipher, true, params);

            OutputStream cOut = createCipherOutputStream(bOut, cipher);
            if (blocks)
            {
                int chunkSize = data.length / 8;
                for (int i = 0; i < data.length; i += chunkSize)
                {
                    cOut.write(data, i, chunkSize);
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
            init(cipher, false, params);
            InputStream cIn = createCipherInputStream(cipherText, cipher);

            if (blocks)
            {
                byte[] block = new byte[getBlockSize(cipher) + 1];
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

        } catch (Exception e)
        {
            fail("Unexpected exception " + getName(cipher), e);
        }

        byte[] decrypted = bOut.toByteArray();
        if (!Arrays.areEqual(data, decrypted))
        {
            fail("Failed - decrypted data doesn't match: " + getName(cipher));
        }
    }

    private String getName(Object cipher)
    {
        if (cipher instanceof BufferedBlockCipher)
        {
            return ((BufferedBlockCipher)cipher).getUnderlyingCipher().getAlgorithmName();
        }
        else if (cipher instanceof AEADBlockCipher)
        {
            return ((AEADBlockCipher)cipher).getUnderlyingCipher().getAlgorithmName();
        }
        else if (cipher instanceof StreamCipher)
        {
            return ((StreamCipher)cipher).getAlgorithmName();
        }
        return null;
    }

    private int getBlockSize(Object cipher)
    {
        if (cipher instanceof BlockCipher)
        {
            return ((BlockCipher)cipher).getBlockSize();
        }
        else if (cipher instanceof BufferedBlockCipher)
        {
            return ((BufferedBlockCipher)cipher).getBlockSize();
        }
        else if (cipher instanceof AEADBlockCipher)
        {
            return ((AEADBlockCipher)cipher).getUnderlyingCipher().getBlockSize();
        }
        else if (cipher instanceof StreamCipher)
        {
            return 1;
        }
        return 0;
    }

    private void init(Object cipher, boolean forEncrypt, CipherParameters params)
    {
        if (cipher instanceof BufferedBlockCipher)
        {
            ((BufferedBlockCipher)cipher).init(forEncrypt, params);
        }
        else if (cipher instanceof AEADBlockCipher)
        {
            ((AEADBlockCipher)cipher).init(forEncrypt, params);
        }
        else if (cipher instanceof StreamCipher)
        {
            ((StreamCipher)cipher).init(forEncrypt, params);
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
            System.err.println("Broken JCE Streams: " + message);
        }
    }

    /**
     * Test CipherInputStream in ENCRYPT_MODE, CipherOutputStream in DECRYPT_MODE
     */
    private void testReadWrite(Object cipher, CipherParameters params, boolean blocks)
        throws Exception
    {
        String lCode = "ABCDEFGHIJKLMNOPQRSTU";

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            init(cipher, true, params);

            InputStream cIn = createCipherInputStream(lCode.getBytes(), cipher);
            ByteArrayOutputStream ct = new ByteArrayOutputStream();

            if (blocks)
            {
                byte[] block = new byte[getBlockSize(cipher) + 1];
                int c;
                while ((c = cIn.read(block)) >= 0)
                {
                    ct.write(block, 0, c);
                }
            }
            else
            {
                int c;
                while ((c = cIn.read()) >= 0)
                {
                    ct.write(c);
                }
            }
            cIn.close();

            init(cipher, false, params);
            ByteArrayInputStream dataIn = new ByteArrayInputStream(ct.toByteArray());
            OutputStream cOut = createCipherOutputStream(bOut, cipher);

            if (blocks)
            {
                byte[] block = new byte[getBlockSize(cipher) + 1];
                int c;
                while ((c = dataIn.read(block)) >= 0)
                {
                    cOut.write(block, 0, c);
                }
            }
            else
            {
                int c;
                while ((c = dataIn.read()) >= 0)
                {
                    cOut.write(c);
                }
            }
            cOut.flush();
            cOut.close();

        } catch (Exception e)
        {
            fail("Unexpected exception " + getName(cipher), e);
        }

        String res = new String(bOut.toByteArray());
        if (!res.equals(lCode))
        {
            fail("Failed read/write - decrypted data doesn't match: " + getName(cipher), lCode, res);
        }
    }

    @Override
    public void performTest()
        throws Exception
    {
        testModes(new BlowfishEngine(), new BlowfishEngine(), 16);
        testModes(new DESEngine(), new DESEngine(), 8);
        testModes(new DESedeEngine(), new DESedeEngine(), 24);
        testModes(new TEAEngine(), new TEAEngine(), 16);
        testModes(new CAST5Engine(), new CAST5Engine(), 16);
        testModes(new RC2Engine(), new RC2Engine(), 16);
        testModes(new XTEAEngine(), new XTEAEngine(), 16);

        testModes(new AESEngine(), new AESEngine(), 16);
        testModes(new NoekeonEngine(), new NoekeonEngine(), 16);
        testModes(new TwofishEngine(), new TwofishEngine(), 16);
        testModes(new CAST6Engine(), new CAST6Engine(), 16);
        testModes(new SEEDEngine(), new SEEDEngine(), 16);
        testModes(new SerpentEngine(), new SerpentEngine(), 16);
        testModes(new RC6Engine(), new RC6Engine(), 16);
        testModes(new CamelliaEngine(), new CamelliaEngine(), 16);
        testModes(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512),
                new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512), 64);

        testMode(new RC4Engine(), new KeyParameter(new byte[16]));
        testMode(new Salsa20Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
        testMode(new XSalsa20Engine(), new ParametersWithIV(new KeyParameter(new byte[32]), new byte[24]));
        testMode(new ChaChaEngine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
        testMode(new Grainv1Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
        testMode(new Grain128Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
        testMode(new HC128Engine(), new KeyParameter(new byte[16]));
        testMode(new HC256Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

    }

    private void testModes(BlockCipher cipher1, BlockCipher cipher2, int keySize)
        throws Exception
    {
        final KeyParameter key = new KeyParameter(new byte[keySize]);
        final int blockSize = getBlockSize(cipher1);
        final CipherParameters withIv = new ParametersWithIV(key, new byte[blockSize]);

        if (blockSize > 1)
        {
            testMode(new PaddedBufferedBlockCipher(cipher1, new PKCS7Padding()), key);

            testMode(new PaddedBufferedBlockCipher(new CBCBlockCipher(cipher1), new PKCS7Padding()), withIv);

            testMode(new BufferedBlockCipher(new OFBBlockCipher(cipher1, blockSize)), withIv);
            testMode(new BufferedBlockCipher(new CFBBlockCipher(cipher1, blockSize)), withIv);
            testMode(new BufferedBlockCipher(new SICBlockCipher(cipher1)), withIv);
        }
        if (blockSize <= 16)
        {
            testMode(new CTSBlockCipher(cipher1), key);
        }
        if (blockSize == 8 || blockSize == 16)
        {
            testMode(new EAXBlockCipher(cipher1), withIv);
        }
        if (blockSize == 16)
        {
            testMode(new CCMBlockCipher(cipher1), new ParametersWithIV(key, new byte[7]));
            testMode(new GCMBlockCipher(cipher1), withIv);
            testMode(new OCBBlockCipher(cipher1, cipher2), new ParametersWithIV(key, new byte[15]));
        }
    }

    public static void main(String[] args)
    {
        runTest(new CipherStreamTest());
    }

}
