package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.modes.AEADCipher;
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
}
