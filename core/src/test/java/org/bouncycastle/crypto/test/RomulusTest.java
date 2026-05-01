package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.RomulusDigest;
import org.bouncycastle.crypto.engines.RomulusEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class RomulusTest
    extends SimpleTest
{
    /**
     * Data length.
     */
    private static final int DATALEN = 1025;

    /**
     * AEAD length.
     */
    private static final int AEADLEN = 10;


    /**
     * Check cipher.
     *
     * @param pCipher the cipher
     */
    private static void checkCipher(final AEADCipher pCipher,
                                    final int pNonceLen)
        throws Exception
    {
        try
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
            final KeyGenerationParameters myGenParams = new KeyGenerationParameters(myRandom, 128);
            myGenerator.init(myGenParams);
            final byte[] myKey = myGenerator.generateKey();
            final KeyParameter myKeyParams = new KeyParameter(myKey);

            /* Create the nonce */
            final byte[] myNonce = new byte[pNonceLen];
            myRandom.nextBytes(myNonce);
            final ParametersWithIV myParams = new ParametersWithIV(myKeyParams, myNonce);

            /* Initialise the cipher for encryption */
            pCipher.init(true, myParams);
            final int myMaxOutLen = pCipher.getOutputSize(DATALEN);
            final byte[] myEncrypted = new byte[myMaxOutLen];
            //pCipher.processAADBytes(myAEAD, 0, AEADLEN);
            int myOutLen = pCipher.processBytes(myData, 0, DATALEN, myEncrypted, 0);
            int myRemaining = pCipher.getOutputSize(0);
            if (myRemaining + myOutLen < myMaxOutLen)
            {
                //
                // FAILS HERE                                                                                   */
                //
                System.out.println("Bad outputLength on encryption for " + pCipher.getAlgorithmName());
            }
            int myProcessed = pCipher.doFinal(myEncrypted, myOutLen);
            if (myOutLen + myProcessed != myMaxOutLen)
            {
                System.out.println("Bad total on encryption for " + pCipher.getAlgorithmName());
            }

            /* Note that myOutLen is too large by DATALEN  */

            /* Initialise the cipher for decryption */
            pCipher.init(false, myParams);
            final int myMaxClearLen = pCipher.getOutputSize(myMaxOutLen);
            final byte[] myDecrypted = new byte[myMaxClearLen];
            //pCipher.processAADBytes(myAEAD, 0, AEADLEN);
            int myClearLen = pCipher.processBytes(myEncrypted, 0, myEncrypted.length, myDecrypted, 0);
            myRemaining = pCipher.getOutputSize(0);
            if (myRemaining + myClearLen < myMaxClearLen)
            {
                System.out.println("Bad outputLength on decryption for " + pCipher.getAlgorithmName());
            }
            myProcessed = pCipher.doFinal(myDecrypted, myClearLen);
            if (myClearLen + myProcessed != myMaxClearLen)
            {
                System.out.println("Bad total on decryption for " + pCipher.getAlgorithmName());
            }
            final byte[] myResult = Arrays.copyOf(myDecrypted, DATALEN);

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

    public String getName()
    {
        return "Romulus";
    }

    public void performTest()
        throws Exception
    {
        checkCipher(new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM), 16);
        DigestTest.implTestVectorsDigest(this, new RomulusDigest(), "crypto/romulus", "LWC_HASH_KAT_256.txt");
        DigestTest.checkDigestReset(this, new RomulusDigest());
        DigestTest.implTestExceptionsAndParametersDigest(this, new RomulusDigest(), 32);

        CipherTest.implTestVectorsEngine(new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM), "crypto/romulus", "m_LWC_AEAD_KAT_128_128.txt", this);
        CipherTest.implTestVectorsEngine(new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT), "crypto/romulus", "t_LWC_AEAD_KAT_128_128.txt", this);
        CipherTest.implTestVectorsEngine(new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN), "crypto/romulus", "n_LWC_AEAD_KAT_128_128.txt", this);

        //TODO: StreamDataOperator does not suit for implTestBufferingEngine
//        CipherTest.implTestBufferingEngine(16, 16, 128, this, new CipherTest.Instance()
//        {
//            @Override
//            public AEADCipher createInstance()
//            {
//                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM);
//            }
//        });
        CipherTest.implTestBufferingEngine(16, 16, 128, this, new CipherTest.Instance()
        {
            @Override
            public AEADCipher createInstance()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT);
            }
        });
        CipherTest.implTestBufferingEngine(16, 16, 128, this, new CipherTest.Instance()
        {
            @Override
            public AEADCipher createInstance()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN);
            }
        });
        //TODO: StreamDataOperator does not suit for implTestExceptionsEngine
//        CipherTest.implTestExceptionsEngine(16, 16, this, new CipherTest.Instance()
//        {
//            @Override
//            public AEADCipher createInstance()
//            {
//                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM);
//            }
//        });
        CipherTest.implTestExceptionsEngine(16, 16, this, new CipherTest.Instance()
        {
            @Override
            public AEADCipher createInstance()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT);
            }
        });
        CipherTest.implTestExceptionsEngine(16, 16, this, new CipherTest.Instance()
        {
            @Override
            public AEADCipher createInstance()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN);
            }
        });
        implTestParametersEngine(new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM), 16, 16, 16);
        implTestParametersEngine(new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT), 16, 16, 16);
        implTestParametersEngine(new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN), 16, 16, 16);
        CipherTest.checkAEADParemeter(this, 16, 16, 16, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM));
        CipherTest.checkAEADParemeter(this, 16, 16, 16, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT));
        CipherTest.checkAEADParemeter(this, 16, 16, 16, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN));
        CipherTest.testOverlapping(this, 16, 16, 16, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM));
        CipherTest.testOverlapping(this, 16, 16, 16, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT));
        CipherTest.testOverlapping(this, 16, 16, 16, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN));
        CipherTest.checkAEADCipherMultipleBlocks(this, 1025, 33, 16, 128, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM));
        CipherTest.checkAEADCipherMultipleBlocks(this, 1025, 33, 16, 128, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT));
        CipherTest.checkAEADCipherMultipleBlocks(this, 1025, 33, 16, 128, 16, new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN));

        CipherTest.checkCipher(16, 16, 40, 128, new CipherTest.Instance()
        {
            public AEADCipher createInstance()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM);
            }
        });
        CipherTest.checkCipher(16, 16, 40, 128, new CipherTest.Instance()
        {
            public AEADCipher createInstance()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT);
            }
        });

        CipherTest.checkCipher(16, 16, 40, 128, new CipherTest.Instance()
        {
            public AEADCipher createInstance()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN);
            }
        });

//        RomulusEngine romulus = new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT);
//        testExceptions(romulus, romulus.getKeyBytesSize(), romulus.getIVBytesSize(), romulus.getBlockSize());
//        romulus = new RomulusEngine(RomulusEngine.RomulusParameters.RomulusM);
//        testExceptions(romulus, romulus.getKeyBytesSize(), romulus.getIVBytesSize(), romulus.getBlockSize());
//        romulus = new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN);
//        testExceptions(romulus, romulus.getKeyBytesSize(), romulus.getIVBytesSize(), romulus.getBlockSize());
//        testExceptions(new RomulusDigest(), 32);
//        //testVectorsHash();
//        testVectors(RomulusEngine.RomulusParameters.RomulusT, "t");
//        testVectors(RomulusEngine.RomulusParameters.RomulusM, "m");
//        testVectors(RomulusEngine.RomulusParameters.RomulusN, "n");
    }

    private void implTestParametersEngine(RomulusEngine cipher, int keySize, int ivSize,
                                          int macSize)
    {
        if (cipher.getKeyBytesSize() != keySize)
        {
            fail("key bytes of " + cipher.getAlgorithmName() + " is not correct");
        }
        if (cipher.getIVBytesSize() != ivSize)
        {
            fail("iv bytes of " + cipher.getAlgorithmName() + " is not correct");
        }

        CipherParameters parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

        cipher.init(true, parameters);
        if (cipher.getOutputSize(0) != macSize)
        {
            fail("getOutputSize of " + cipher.getAlgorithmName() + " is incorrect for encryption");
        }

        cipher.init(false, parameters);
        if (cipher.getOutputSize(macSize) != 0)
        {
            fail("getOutputSize of " + cipher.getAlgorithmName() + " is incorrect for decryption");
        }
    }

//    public static void main(String[] args)
//    {
//        runTest(new RomulusTest());
//    }
}



