package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
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
        int len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext1, 0);
        len += cipher.doFinal(ciphertext1, len);
        int aadSplit = random.nextInt(aad.length) + 1;
        cipher.init(true, new AEADParameters(new KeyParameter(key), macSize * 8, iv, Arrays.copyOf(aad, aadSplit)));
        cipher.processAADBytes(aad, aadSplit, aad.length - aadSplit);
        byte[] ciphertext2 = new byte[cipher.getOutputSize(plaintext.length)];
        len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext2, 0);
        len += cipher.doFinal(ciphertext2, len);
        test.isTrue("cipher text check", Arrays.areEqual(ciphertext1, ciphertext2));

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
     * */
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
}
