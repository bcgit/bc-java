package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.TestFailedException;

public abstract class CipherTest
    extends SimpleTest
{
    private SimpleTest[] _tests;
    private BlockCipher _engine;
    private KeyParameter _validKey;

//    protected CipherTest(
//        SimpleTest[]  tests)
//    {
//        _tests = tests;
//    }

    protected CipherTest(
        SimpleTest[] tests,
        BlockCipher engine,
        KeyParameter validKey)
    {
        _tests = tests;
        _engine = engine;
        _validKey = validKey;
    }

    public abstract String getName();

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != _tests.length; i++)
        {
            _tests[i].performTest();
        }

        if (_engine != null)
        {
            //
            // state tests
            //
            byte[] buf = new byte[128];

            try
            {
                _engine.processBlock(buf, 0, buf, 0);

                fail("failed initialisation check");
            }
            catch (IllegalStateException e)
            {
                // expected 
            }

            bufferSizeCheck((_engine));
        }
    }

    private void bufferSizeCheck(
        BlockCipher engine)
    {
        byte[] correctBuf = new byte[engine.getBlockSize()];
        byte[] shortBuf = new byte[correctBuf.length / 2];

        engine.init(true, _validKey);

        try
        {
            engine.processBlock(shortBuf, 0, correctBuf, 0);

            fail("failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }

        try
        {
            engine.processBlock(correctBuf, 0, shortBuf, 0);

            fail("failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }

        engine.init(false, _validKey);

        try
        {
            engine.processBlock(shortBuf, 0, correctBuf, 0);

            fail("failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }

        try
        {
            engine.processBlock(correctBuf, 0, shortBuf, 0);

            fail("failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
    }

    interface Instance
    {
        AEADCipher createInstance();
    }

    static void checkCipher(int aeadLen, int ivLen, int msgLen, int strength, Instance instance)
    {
        AEADCipher pCipher = instance.createInstance();

        try
        {
            /* Obtain some random data */
            final byte[] myData = new byte[msgLen];
            final SecureRandom myRandom = new SecureRandom();
            myRandom.nextBytes(myData);

            /* Obtain some random AEAD */
            final byte[] myAEAD = new byte[aeadLen];
            myRandom.nextBytes(myAEAD);

            /* Create the Key parameters */
            final CipherKeyGenerator myGenerator = new CipherKeyGenerator();
            final KeyGenerationParameters myGenParams = new KeyGenerationParameters(myRandom, strength);
            myGenerator.init(myGenParams);
            final byte[] myKey = myGenerator.generateKey();
            final KeyParameter myKeyParams = new KeyParameter(myKey);

            /* Create the nonce */
            final byte[] myNonce = new byte[ivLen];
            myRandom.nextBytes(myNonce);
            final ParametersWithIV myParams = new ParametersWithIV(myKeyParams, myNonce);

            /* Initialise the cipher for encryption */
            pCipher.init(true, myParams);
            final int myMaxOutLen = pCipher.getOutputSize(msgLen);
            final byte[] myEncrypted = new byte[myMaxOutLen];
            pCipher.processAADBytes(myAEAD, 0, aeadLen);
            int myOutLen = pCipher.processBytes(myData, 0, msgLen, myEncrypted, 0);
            myOutLen += pCipher.doFinal(myEncrypted, myOutLen);

            /* Note that myOutLen is too large by DATALEN  */
            pCipher = instance.createInstance();
            /* Initialise the cipher for decryption */
            pCipher.init(false, myParams);
            final int myMaxClearLen = pCipher.getOutputSize(myOutLen);
            final byte[] myDecrypted = new byte[myMaxClearLen];
            pCipher.processAADBytes(myAEAD, 0, aeadLen);
            int myClearLen = pCipher.processBytes(myEncrypted, 0, myEncrypted.length, myDecrypted, 0);
            myClearLen += pCipher.doFinal(myDecrypted, myClearLen);
            final byte[] myResult = Arrays.copyOf(myDecrypted, msgLen);

            /* Check that we have the same result */
            if (!Arrays.areEqual(myData, myResult))
            {
                System.out.println("Cipher " + pCipher.getAlgorithmName() + " failed");
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw new RuntimeException(e);
        }
    }

    static void checkAEADCipherOutputSize(SimpleTest parent, int keySize, int ivSize, int blockSize, int tagSize, AEADCipher cipher)
        throws InvalidCipherTextException
    {
        final SecureRandom random = new SecureRandom();
        int tmpLength = random.nextInt(blockSize - 1) + 1;
        final byte[] plaintext = new byte[blockSize * 2 + tmpLength];
        byte[] key = new byte[keySize];
        byte[] iv = new byte[ivSize];
        random.nextBytes(key);
        random.nextBytes(iv);
        random.nextBytes(plaintext);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)];
        //before the encrypt
        isEqualTo(parent, plaintext.length + tagSize, ciphertext.length);
        isEqualTo(parent, plaintext.length, cipher.getUpdateOutputSize(plaintext.length) + tmpLength);
        //during the encrypt process of the first block
        int len = cipher.processBytes(plaintext, 0, tmpLength, ciphertext, 0);
        isEqualTo(parent, plaintext.length + tagSize, len + cipher.getOutputSize(plaintext.length - tmpLength));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(plaintext.length - tmpLength) + tmpLength);
        //during the encrypt process of the second block
        len += cipher.processBytes(plaintext, tmpLength, blockSize, ciphertext, len);
        isEqualTo(parent, plaintext.length + tagSize, len + cipher.getOutputSize(plaintext.length - tmpLength - blockSize));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(plaintext.length - tmpLength - blockSize) + tmpLength);
        //process the remaining bytes
        len += cipher.processBytes(plaintext, tmpLength + blockSize, blockSize, ciphertext, len);
        isEqualTo(parent, plaintext.length + tagSize, len + cipher.getOutputSize(0));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(0) + tmpLength);
        //process doFinal
        len += cipher.doFinal(ciphertext, len);
        isEqualTo(parent, len, ciphertext.length);

        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        //before the encrypt
        isEqualTo(parent, plaintext.length, cipher.getOutputSize(ciphertext.length));
        isEqualTo(parent, plaintext.length, cipher.getUpdateOutputSize(ciphertext.length) + tmpLength);
        //during the encrypt process of the first block
        len = cipher.processBytes(ciphertext, 0, tmpLength, plaintext, 0);
        isEqualTo(parent, plaintext.length, len + cipher.getOutputSize(ciphertext.length - tmpLength));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(ciphertext.length - tmpLength) + tmpLength);
        //during the encrypt process of the second block
        len += cipher.processBytes(ciphertext, tmpLength, blockSize, plaintext, len);
        isEqualTo(parent, plaintext.length, len + cipher.getOutputSize(ciphertext.length - tmpLength - blockSize));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(ciphertext.length - tmpLength - blockSize) + tmpLength);
        //process the remaining bytes
        len += cipher.processBytes(ciphertext, tmpLength + blockSize, blockSize + tagSize, plaintext, len);
        isEqualTo(parent, plaintext.length, len + cipher.getOutputSize(0));
        isEqualTo(parent, plaintext.length, len + cipher.getUpdateOutputSize(0) + tmpLength);
        //process doFinal
        len += cipher.doFinal(plaintext, len);
        isEqualTo(parent, len, plaintext.length);
    }

    static void isEqualTo(
        SimpleTest parent,
        int a,
        int b)
    {
        if (a != b)
        {
            throw new TestFailedException(SimpleTestResult.failed(parent, "no message"));
        }
    }

    void checkCipher(final BlockCipher pCipher, final int datalen)
        throws Exception
    {
        final SecureRandom random = new SecureRandom();
        /* Create the data */
        final byte[] myData = new byte[datalen];
        random.nextBytes(myData);

        /* Create the Key parameters */
        final CipherKeyGenerator myGenerator = new CipherKeyGenerator();
        final KeyGenerationParameters myGenParams = new KeyGenerationParameters(random, 256);
        myGenerator.init(myGenParams);
        final byte[] myKey = myGenerator.generateKey();
        final KeyParameter myKeyParams = new KeyParameter(myKey);

        /* Create the IV */
        final byte[] myIV = new byte[16];
        random.nextBytes(myIV);

        /* Create the initParams */
        final ParametersWithIV myParams = new ParametersWithIV(myKeyParams, myIV);

        /* Wrap Block Cipher with buffered BlockCipher */
        final BufferedBlockCipher myCipher = new DefaultBufferedBlockCipher(pCipher);

        /* Initialise the cipher for encryption */
        myCipher.init(true, myParams);

        /* Encipher the text */
        final byte[] myOutput = new byte[myCipher.getOutputSize(datalen)];
        int myOutLen = myCipher.processBytes(myData, 0, datalen, myOutput, 0);
        myCipher.doFinal(myOutput, myOutLen);

        /* Re-Encipher the text (after implicit reset) */
        final byte[] myOutput2 = new byte[myCipher.getOutputSize(datalen)];
        myOutLen = myCipher.processBytes(myData, 0, datalen, myOutput2, 0);
        myCipher.doFinal(myOutput2, myOutLen);

        myCipher.init(false, myParams);
        final byte[] plaintext = new byte[myCipher.getOutputSize(myOutput.length)];
        myOutLen = myCipher.processBytes(myOutput2, 0, datalen, plaintext, 0);
        myCipher.doFinal(plaintext, myOutLen);

        /* Check that the cipherTexts are identical */
        isTrue(areEqual(myOutput, myOutput2));
        isTrue(areEqual(myData, plaintext));
    }

    static void checkAEADParemeter(SimpleTest test, int keySize, int ivSize, final int macSize, int blockSize, final AEADCipher cipher)
        throws Exception
    {
        final SecureRandom random = new SecureRandom();
        final byte[] key = new byte[keySize];
        final byte[] iv = new byte[ivSize];
        int tmpLength = random.nextInt(blockSize - 1) + 1;
        final byte[] plaintext = new byte[blockSize * 2 + tmpLength];
        byte[] aad = new byte[random.nextInt(100) + 2];
        random.nextBytes(key);
        random.nextBytes(iv);
        random.nextBytes(plaintext);
        random.nextBytes(aad);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] ciphertext1 = new byte[cipher.getOutputSize(plaintext.length)];
        for (int i = 0; i < aad.length; ++i)
        {
            cipher.processAADByte(aad[i]);
        }
        int len = 0;
        for (int i = 0; i < plaintext.length; ++i)
        {
            len += cipher.processByte(plaintext[i], ciphertext1, len);
        }
        len += cipher.doFinal(ciphertext1, len);
        int aadSplit = random.nextInt(aad.length) + 1;
        cipher.init(true, new AEADParameters(new KeyParameter(key), macSize * 8, iv, Arrays.copyOf(aad, aadSplit)));
        cipher.processAADBytes(aad, aadSplit, aad.length - aadSplit);
        byte[] ciphertext2 = new byte[cipher.getOutputSize(plaintext.length)];
        len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext2, 0);
        len += cipher.doFinal(ciphertext2, len);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] ciphertext3 = new byte[cipher.getOutputSize(plaintext.length)];
        cipher.processAADBytes(aad, 0, aad.length);
        len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext3, 0);
        len += cipher.doFinal(ciphertext3, len);
        test.isTrue("cipher text check", Arrays.areEqual(ciphertext1, ciphertext2));
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        for (int i = 0; i < aad.length; ++i)
        {
            cipher.processAADByte(aad[i]);
        }
        len = 0;
        byte[] plaintext1 = new byte[plaintext.length];
        for (int i = 0; i < ciphertext1.length; ++i)
        {
            len += cipher.processByte(ciphertext1[i], plaintext1, len);
        }
        len += cipher.doFinal(plaintext1, len);

        test.testException("Invalid value for MAC size: ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                int macSize2 = random.nextInt();
                while (macSize2 == macSize * 8)
                {
                    macSize2 = random.nextInt();
                }
                cipher.init(true, new AEADParameters(new KeyParameter(key), macSize2, iv, null));
            }
        });
    }


    /**
     * @param DATALEN  Data length
     * @param PARTLEN  Partial Data length. Must be greater than or equal to internal buffer length to exhibit problem.
     * @param AEADLEN  AEAD length.
     * @param NONCELEN Nonce length.
     */
    static void checkAEADCipherMultipleBlocks(SimpleTest test, int DATALEN, int PARTLEN, int AEADLEN, int strength, int NONCELEN, final AEADCipher pCipher)
        throws InvalidCipherTextException
    {
        /* Obtain some random data */
        final byte[] myData = new byte[DATALEN];
        final SecureRandom myRandom = new SecureRandom();
        myRandom.nextBytes(myData);

        /* Obtain some random AEAD */
        final byte[] myAEAD = new byte[AEADLEN];
        myRandom.nextBytes(myAEAD);

        /* Create the Key parameters */
        final CipherKeyGenerator myGenerator = new CipherKeyGenerator();
        final KeyGenerationParameters myGenParams = new KeyGenerationParameters(myRandom, strength);
        myGenerator.init(myGenParams);
        final byte[] myKey = myGenerator.generateKey();
        final KeyParameter myKeyParams = new KeyParameter(myKey);

        /* Create the nonce */
        final byte[] myNonce = new byte[NONCELEN];
        myRandom.nextBytes(myNonce);
        final ParametersWithIV myParams = new ParametersWithIV(myKeyParams, myNonce);

        /* Initialise the cipher for encryption */
        pCipher.init(true, myParams);
        final int myExpectedOutLen = pCipher.getOutputSize(DATALEN);
        final byte[] myEncrypted = new byte[myExpectedOutLen];
        pCipher.processAADBytes(myAEAD, 0, AEADLEN);

        /* Loop processing partial data */
        int myOutLen = 0;
        for (int myPos = 0; myPos < DATALEN; myPos += PARTLEN)
        {
            final int myLen = Math.min(PARTLEN, DATALEN - myPos);
            myOutLen += pCipher.processBytes(myData, myPos, myLen, myEncrypted, myOutLen);
        }

        /* Finish the encryption */
        myOutLen += pCipher.doFinal(myEncrypted, myOutLen);

        /* Initialise the cipher for decryption */
        pCipher.init(false, myParams);
        final int myExpectedClearLen = pCipher.getOutputSize(myOutLen);
        final byte[] myDecrypted = new byte[myExpectedClearLen];
        pCipher.processAADBytes(myAEAD, 0, AEADLEN);
        int myClearLen = 0;
        for (int myPos = 0; myPos < myOutLen; myPos += PARTLEN)
        {
            final int myLen = Math.min(PARTLEN, myOutLen - myPos);
            myClearLen += pCipher.processBytes(myEncrypted, myPos, myLen, myDecrypted, myClearLen);
        }
        myClearLen += pCipher.doFinal(myDecrypted, myClearLen);
        final byte[] myResult = Arrays.copyOf(myDecrypted, myClearLen);

        /* Check that we have the same result */
        test.isTrue("cipher text check", Arrays.areEqual(myData, myResult));
    }

    static void implTestVectorsEngine(AEADCipher cipher, String path, String filename, SimpleTest test)
        throws Exception
    {
        Random random = new Random();
        InputStream src = TestResourceFinder.findTestResource(path, filename);
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
                int count = Integer.parseInt((String)map.get("Count"));
//                if (count != 67)
//                {
//                    continue;
//                }
                byte[] key = Hex.decode((String)map.get("Key"));
                byte[] nonce = Hex.decode((String)map.get("Nonce"));
                byte[] ad = Hex.decode((String)map.get("AD"));
                byte[] pt = Hex.decode((String)map.get("PT"));
                byte[] ct = Hex.decode((String)map.get("CT"));

                CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), nonce);

                // Encrypt
                {
                    cipher.init(true, parameters);

                    byte[] rv = new byte[cipher.getOutputSize(pt.length)];
                    random.nextBytes(rv); // should overwrite any existing data

                    cipher.processAADBytes(ad, 0, ad.length);
                    int len = cipher.processBytes(pt, 0, pt.length, rv, 0);
                    len += cipher.doFinal(rv, len);

                    if (!test.areEqual(rv, 0, len, ct, 0, ct.length))
                    {
                        mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv, test);
                    }
                }

                // Decrypt
                {
                    cipher.init(false, parameters);

                    byte[] rv = new byte[cipher.getOutputSize(ct.length)];
                    random.nextBytes(rv); // should overwrite any existing data

                    cipher.processAADBytes(ad, 0, ad.length);
                    int len = cipher.processBytes(ct, 0, ct.length, rv, 0);
                    len += cipher.doFinal(rv, len);

                    if (!test.areEqual(rv, 0, len, pt, 0, pt.length))
                    {
                        mismatch("Reccover Keystream " + map.get("Count"), (String)map.get("PT"), rv, test);
                    }
                }
                //System.out.println("pass " + count);
                map.clear();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    static void mismatch(String name, String expected, byte[] found, SimpleTest test)
        throws Exception
    {
        test.fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    static void implTestBufferingEngine(int keySize, int ivSize, final int macSize, SimpleTest test, Instance instance)
        throws Exception
    {
        Random random = new Random();

        int plaintextLength = 256;
        byte[] plaintext = new byte[plaintextLength];
        random.nextBytes(plaintext);

        AEADCipher cipher0 = instance.createInstance();
        AEADParameters parameters = new AEADParameters(new KeyParameter(new byte[keySize]), macSize, new byte[ivSize], null);
        cipher0.init(true, parameters);

        byte[] ciphertext = new byte[cipher0.getOutputSize(plaintextLength)];
        random.nextBytes(ciphertext);

        int ciphertextLength = cipher0.processBytes(plaintext, 0, plaintextLength, ciphertext, 0);
        ciphertextLength += cipher0.doFinal(ciphertext, ciphertextLength);

        byte[] output = new byte[ciphertextLength];

        // Encryption
        for (int split = 1; split < plaintextLength; ++split)
        {
            AEADCipher cipher = instance.createInstance();
            cipher.init(true, parameters);

            random.nextBytes(output);

            int length = cipher.processBytes(plaintext, 0, split, output, 0);

            if (0 != cipher.getUpdateOutputSize(0))
            {
                test.fail("fail in implTestBufferingEngine encryption");
            }

            length += cipher.processBytes(plaintext, split, plaintextLength - split, output, length);
            length += cipher.doFinal(output, length);

            if (!Arrays.areEqual(ciphertext, 0, ciphertextLength, output, 0, length))
            {
                test.fail("encryption failed with split: " + split);
            }
        }

        // Decryption
        for (int split = 16; split < ciphertextLength; ++split)
        {
            AEADCipher cipher = instance.createInstance();
            cipher.init(false, parameters);

            random.nextBytes(output);

            int length = cipher.processBytes(ciphertext, 0, split, output, 0);

            if (0 != cipher.getUpdateOutputSize(0))
            {
                test.fail("fail in implTestBufferingEngine decryption");
            }

            length += cipher.processBytes(ciphertext, split, ciphertextLength - split, output, length);
            length += cipher.doFinal(output, length);

            if (!Arrays.areEqual(plaintext, 0, plaintextLength, output, 0, length))
            {
                test.fail("decryption failed with split: " + split);
            }
        }
    }

    static void implTestExceptionsEngine(int keysize, int ivsize, SimpleTest test, Instance instance)
        throws Exception
    {
        AEADCipher cipher = instance.createInstance();

        int offset;
        byte[] k = new byte[keysize];
        byte[] iv = new byte[ivsize];
        byte[] m = new byte[0];
        CipherParameters params = new ParametersWithIV(new KeyParameter(k), iv);
        try
        {
            cipher.processBytes(m, 0, m.length, null, 0);
            test.fail(cipher.getAlgorithmName() + " need to be initialized before processBytes");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            cipher.processByte((byte)0, null, 0);
            test.fail(cipher.getAlgorithmName() + " need to be initialized before processByte");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            cipher.reset();
            test.fail(cipher.getAlgorithmName() + " need to be initialized before reset");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            cipher.doFinal(null, m.length);
            test.fail(cipher.getAlgorithmName() + " need to be initialized before dofinal");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            cipher.getMac();
            cipher.getOutputSize(0);
            cipher.getUpdateOutputSize(0);
        }
        catch (IllegalStateException e)
        {
            //expected
            test.fail(cipher.getAlgorithmName() + " functions can be called before initialization");
        }

        Random rand = new Random();
        int randomNum;
        while ((randomNum = rand.nextInt(100)) == keysize) ;
        byte[] k1 = new byte[randomNum];
        while ((randomNum = rand.nextInt(100)) == ivsize) ;
        byte[] iv1 = new byte[randomNum];
        try
        {
            cipher.init(true, new ParametersWithIV(new KeyParameter(k1), iv));
            test.fail(cipher.getAlgorithmName() + " k size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }
        try
        {
            cipher.init(true, new ParametersWithIV(new KeyParameter(k), iv1));
            test.fail(cipher.getAlgorithmName() + "iv size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        try
        {
            cipher.init(true, new AEADParameters(new KeyParameter(k), 0, iv));
            test.fail(cipher.getAlgorithmName() + " wrong type of CipherParameters");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        cipher.init(true, params);
        byte[] c1 = new byte[cipher.getOutputSize(m.length)];
        try
        {
            cipher.doFinal(c1, m.length);
        }
        catch (Exception e)
        {
            test.fail(cipher.getAlgorithmName() + " allows no input for AAD and plaintext");
        }
        byte[] mac2 = cipher.getMac();
        if (mac2 == null)
        {
            test.fail("mac should not be empty after dofinal");
        }
        if (!Arrays.areEqual(mac2, c1))
        {
            test.fail("mac should be equal when calling dofinal and getMac");
        }
        cipher.init(true, params);
        cipher.processAADByte((byte)0);
        byte[] mac1 = new byte[cipher.getOutputSize(0)];
        cipher.doFinal(mac1, 0);
        if (Arrays.areEqual(mac1, mac2))
        {
            test.fail("mac should not match");
        }
        cipher.init(true, params);
        cipher.processByte((byte)0, new byte[1], 0);
        try
        {
            cipher.processAADByte((byte)0);
            // Romuls-M stores message into Stream, so the procssAADbyte(s) is allowed
            if (!cipher.getAlgorithmName().equals("Romulus-M"))
            {
                test.fail("processAADByte(s) cannot be called after encryption/decryption");
            }
        }
        catch (IllegalStateException e)
        {
            //expected
        }
        try
        {
            cipher.processAADBytes(new byte[]{0}, 0, 1);
            if (!cipher.getAlgorithmName().equals("Romulus-M"))
            {
                test.fail("processAADByte(s) cannot be called once only");
            }
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        cipher.reset();
        try
        {
            cipher.processAADBytes(new byte[]{0}, 1, 1);
            test.fail("input for processAADBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            cipher.processBytes(new byte[]{0}, 1, 1, c1, 0);
            test.fail("input for processBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        cipher.init(true, params);
        try
        {
            int need = cipher.getUpdateOutputSize(64);
            cipher.processBytes(new byte[64], 0, 64, new byte[need], 1);
            if (!cipher.getAlgorithmName().equals("Romulus-M"))
            {
                test.fail("output for processBytes is too short");
            }
        }
        catch (OutputLengthException e)
        {
            //expected
        }
        try
        {
            cipher.doFinal(new byte[2], 2);
            test.fail("output for dofinal is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }

        implTestExceptionsGetUpdateOutputSize(cipher, false, params, 100, test);
        implTestExceptionsGetUpdateOutputSize(cipher, true, params, 100, test);

        mac1 = new byte[cipher.getOutputSize(0)];
        mac2 = new byte[cipher.getOutputSize(0)];
        cipher.init(true, params);
        cipher.processAADBytes(new byte[]{0, 0}, 0, 2);
        cipher.doFinal(mac1, 0);
        cipher.init(true, params);
        cipher.processAADByte((byte)0);
        cipher.processAADByte((byte)0);
        cipher.doFinal(mac2, 0);
        if (!Arrays.areEqual(mac1, mac2))
        {
            test.fail("mac should match for the same AAD with different ways of inputing");
        }

        byte[] c2 = new byte[cipher.getOutputSize(10)];
        byte[] c3 = new byte[cipher.getOutputSize(10) + 2];

        byte[] aad2 = {0, 1, 2, 3, 4};
        byte[] aad3 = {0, 0, 1, 2, 3, 4, 5};
        byte[] m2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] m3 = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        byte[] m4 = new byte[m2.length];
        cipher.init(true, params);
        cipher.processAADBytes(aad2, 0, aad2.length);
        offset = cipher.processBytes(m2, 0, m2.length, c2, 0);
        cipher.doFinal(c2, offset);
        cipher.init(true, params);
        cipher.processAADBytes(aad3, 1, aad2.length);
        offset = cipher.processBytes(m3, 1, m2.length, c3, 1);
        cipher.doFinal(c3, offset + 1);
        byte[] c3_partial = new byte[c2.length];
        System.arraycopy(c3, 1, c3_partial, 0, c2.length);
        if (!Arrays.areEqual(c2, c3_partial))
        {
            test.fail("mac should match for the same AAD and message with different offset for both input and output");
        }
        cipher.init(false, params);
        cipher.processAADBytes(aad2, 0, aad2.length);
        offset = cipher.processBytes(c2, 0, c2.length, m4, 0);
        cipher.doFinal(m4, offset);
        if (!Arrays.areEqual(m2, m4))
        {
            test.fail("The encryption and decryption does not recover the plaintext");
        }
        c2[c2.length - 1] ^= 1;
        cipher.init(false, params);
        cipher.processAADBytes(aad2, 0, aad2.length);
        offset = cipher.processBytes(c2, 0, c2.length, m4, 0);
        try
        {
            cipher.doFinal(m4, offset);
            test.fail("The decryption should fail");
        }
        catch (InvalidCipherTextException e)
        {
            //expected;
        }

        byte[] m7 = new byte[32 + rand.nextInt(32)];
        rand.nextBytes(m7);

        cipher.init(true, params);
        byte[] c7 = new byte[cipher.getOutputSize(m7.length)];
        byte[] c8 = new byte[c7.length];
        byte[] c9 = new byte[c7.length];
        cipher.processAADBytes(aad2, 0, aad2.length);
        offset = cipher.processBytes(m7, 0, m7.length, c7, 0);
        cipher.doFinal(c7, offset);

        cipher.init(true, params);
        cipher.processAADBytes(aad2, 0, aad2.length);
        offset = cipher.processBytes(m7, 0, m7.length / 2, c8, 0);
        offset += cipher.processBytes(m7, m7.length / 2, m7.length - m7.length / 2, c8, offset);
        cipher.doFinal(c8, offset);

        cipher.init(true, params);
        int split = rand.nextInt(m7.length - 1) + 1;
        cipher.processAADBytes(aad2, 0, aad2.length);
        offset = cipher.processBytes(m7, 0, split, c9, 0);
        offset += cipher.processBytes(m7, split, m7.length - split, c9, offset);
        cipher.doFinal(c9, offset);

        if (!Arrays.areEqual(c7, c8) || !Arrays.areEqual(c7, c9))
        {
            test.fail("Splitting input of plaintext should output the same ciphertext");
        }
    }

    static void implTestExceptionsGetUpdateOutputSize(AEADCipher cipher, boolean forEncryption,
                                                      CipherParameters parameters, int maxInputSize, SimpleTest test)
    {
        cipher.init(forEncryption, parameters);

        int maxOutputSize = cipher.getUpdateOutputSize(maxInputSize);

        byte[] input = new byte[maxInputSize];
        byte[] output = new byte[maxOutputSize];

        for (int inputSize = 0; inputSize <= maxInputSize; ++inputSize)
        {
            cipher.init(forEncryption, parameters);

            int outputSize = cipher.getUpdateOutputSize(inputSize);
            if (outputSize > 0)
            {
                try
                {
                    cipher.processBytes(input, 0, inputSize, output, maxOutputSize - outputSize + 1);
                    test.fail("output for processBytes is too short");
                }
                catch (OutputLengthException e)
                {
                    //expected
                }
            }
            else
            {
                cipher.processBytes(input, 0, inputSize, null, 0);
            }
        }
    }

    static void testOverlapping(SimpleTest test, int keySize, int ivSize, int macSize, int blockSize, AEADCipher cipher)
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[keySize];
        byte[] ivBytes = new byte[ivSize];
        int offset = 1 + random.nextInt(blockSize - 1);
        byte[] data = new byte[blockSize * 2 + offset + macSize];
        byte[] expected;
        random.nextBytes(keyBytes);
        random.nextBytes(ivBytes);
        random.nextBytes(data);
        AEADParameters parameters = new AEADParameters(new KeyParameter(new byte[keySize]), macSize * 8, new byte[ivSize], null);
        cipher.init(true, parameters);
        expected = new byte[cipher.getOutputSize(blockSize * 2)];
        int len = cipher.processBytes(data, 0, blockSize * 2, expected, 0);
        cipher.doFinal(expected, len);
        cipher.init(true, parameters);
        len = cipher.processBytes(data, 0, blockSize * 2, data, offset);
        cipher.doFinal(data, len + offset);
        test.isTrue("fail on testing overlapping of encryption for " + cipher.getAlgorithmName(),
            Arrays.areEqual(expected, 0, expected.length, data, offset, offset + expected.length));
        System.arraycopy(data, offset, data, 0, expected.length);
        cipher.init(false, parameters);
        expected = new byte[cipher.getOutputSize(data.length)];
        len = cipher.processBytes(data, 0, blockSize * 2 + macSize, expected, 0);
        cipher.doFinal(expected, len);
        cipher.init(false, parameters);
        len = cipher.processBytes(data, 0, blockSize * 2 + macSize, data, offset);
        cipher.doFinal(data, len + offset);
        test.isTrue("fail on testing overlapping of decryption for " + cipher.getAlgorithmName(),
            Arrays.areEqual(expected, 0, blockSize * 2, data, offset, offset + blockSize * 2));

    }
}
