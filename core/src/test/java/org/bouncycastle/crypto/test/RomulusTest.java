package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RomulusDigest;
import org.bouncycastle.crypto.engines.RomulusEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class RomulusTest
    extends SimpleTest
{
    public String getName()
    {
        return "Romulus";
    }

    public void performTest()
        throws Exception
    {
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


    private void testVectorsHash()
        throws Exception
    {
        RomulusDigest Romulus = new RomulusDigest();
        InputStream src = RomulusTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/romulus/LWC_HASH_KAT_256.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] ptByte, adByte;
        byte[] rv;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
//                if (!map.get("Count").equals("3"))
//                {
//                    continue;
//                }
                Romulus.reset();
                ptByte = Hex.decode((String)map.get("Msg"));
                Romulus.update(ptByte, 0, ptByte.length);
                byte[] hash = new byte[Romulus.getDigestSize()];
                Romulus.doFinal(hash, 0);
                if (!areEqual(hash, Hex.decode((String)map.get("MD"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                map.clear();
                Romulus.reset();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("Romulus Hash pass");
    }


    private void testExceptions(Digest digest, int digestsize)
    {
        if (digest.getDigestSize() != digestsize)
        {
            fail(digest.getAlgorithmName() + ": digest size is not correct");
        }

        try
        {
            digest.update(new byte[1], 1, 1);
            fail(digest.getAlgorithmName() + ": input for update is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            digest.doFinal(new byte[digest.getDigestSize() - 1], 2);
            fail(digest.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        System.out.println(digest.getAlgorithmName() + " test Exceptions pass");
    }


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new RomulusTest());
    }

}



