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

    interface Instace
    {
        AEADCipher CreateInstace();
    }

    static void checkCipher(int aeadLen, int ivLen, int msgLen,  Instace instace)
    {
        AEADCipher pCipher = instace.CreateInstace();

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
            final KeyGenerationParameters myGenParams = new KeyGenerationParameters(myRandom, 128);
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
            pCipher = instace.CreateInstace();
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
}
