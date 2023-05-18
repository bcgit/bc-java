package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Random;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.digests.SparkleDigest;
import org.bouncycastle.crypto.engines.SparkleEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SparkleTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new SparkleTest());
    }

    public String getName()
    {
        return "Sparkle";
    }

    public void performTest()
        throws Exception
    {
        testBufferingEngine_SCHWAEMM128_128();
        testBufferingEngine_SCHWAEMM192_192();
        testBufferingEngine_SCHWAEMM256_128();
        testBufferingEngine_SCHWAEMM256_256();

        testExceptionsDigest_ESCH256();
        testExceptionsDigest_ESCH384();;

        testExceptionsEngine_SCHWAEMM128_128();
        testExceptionsEngine_SCHWAEMM192_192();
        testExceptionsEngine_SCHWAEMM256_128();
        testExceptionsEngine_SCHWAEMM256_256();

        testParametersDigest_ESCH256();
        testParametersDigest_ESCH384();

        testParametersEngine_SCHWAEMM128_128();
        testParametersEngine_SCHWAEMM192_192();
        testParametersEngine_SCHWAEMM256_128();
        testParametersEngine_SCHWAEMM256_256();

        testVectorsDigest_ESCH256();
        testVectorsDigest_ESCH384();

        testVectorsEngine_SCHWAEMM128_128();
        testVectorsEngine_SCHWAEMM192_192();
        testVectorsEngine_SCHWAEMM256_128();
        testVectorsEngine_SCHWAEMM256_256();
    }

    public void testBufferingEngine_SCHWAEMM128_128() throws Exception
    {
        implTestBufferingEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128);
    }

    public void testBufferingEngine_SCHWAEMM192_192() throws Exception
    {
        implTestBufferingEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192);
    }

    public void testBufferingEngine_SCHWAEMM256_128() throws Exception
    {
        implTestBufferingEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128);
    }

    public void testBufferingEngine_SCHWAEMM256_256() throws Exception
    {
        implTestBufferingEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256);
    }

    public void testExceptionsDigest_ESCH256() throws Exception
    {
        implTestExceptionsDigest(SparkleDigest.SparkleParameters.ESCH256);
    }

    public void testExceptionsDigest_ESCH384() throws Exception
    {
        implTestExceptionsDigest(SparkleDigest.SparkleParameters.ESCH384);
    }

    public void testExceptionsEngine_SCHWAEMM128_128() throws Exception
    {
        implTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128);
    }

    public void testExceptionsEngine_SCHWAEMM192_192() throws Exception
    {
        implTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192);
    }

    public void testExceptionsEngine_SCHWAEMM256_128() throws Exception
    {
        implTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128);
    }

    public void testExceptionsEngine_SCHWAEMM256_256() throws Exception
    {
        implTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256);
    }

    public void testParametersDigest_ESCH256() throws Exception
    {
        implTestParametersDigest(SparkleDigest.SparkleParameters.ESCH256, 32);
    }

    public void testParametersDigest_ESCH384() throws Exception
    {
        implTestParametersDigest(SparkleDigest.SparkleParameters.ESCH384, 48);
    }

    public void testParametersEngine_SCHWAEMM128_128() throws Exception
    {
        implTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128, 16, 16, 16);
    }

    public void testParametersEngine_SCHWAEMM192_192() throws Exception
    {
        implTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192, 24, 24, 24);
    }

    public void testParametersEngine_SCHWAEMM256_128() throws Exception
    {
        implTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128, 16, 32, 16);
    }

    public void testParametersEngine_SCHWAEMM256_256() throws Exception
    {
        implTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256, 32, 32, 32);
    }

    public void testVectorsDigest_ESCH256() throws Exception
    {
        implTestVectorsDigest(SparkleDigest.SparkleParameters.ESCH256, "256");
    }

    public void testVectorsDigest_ESCH384() throws Exception
    {
        implTestVectorsDigest(SparkleDigest.SparkleParameters.ESCH384, "384");
    }

    public void testVectorsEngine_SCHWAEMM128_128() throws Exception
    {
        implTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128, "128_128");
    }

    public void testVectorsEngine_SCHWAEMM192_192() throws Exception
    {
        implTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192, "192_192");
    }

    public void testVectorsEngine_SCHWAEMM256_128() throws Exception
    {
        implTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128, "128_256");
    }

    public void testVectorsEngine_SCHWAEMM256_256() throws Exception
    {
        implTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256, "256_256");
    }

    private static SparkleDigest createDigest(SparkleDigest.SparkleParameters sparkleParameters)
    {
        return new SparkleDigest(sparkleParameters);
    }

    private static SparkleEngine createEngine(SparkleEngine.SparkleParameters sparkleParameters)
    {
        return new SparkleEngine(sparkleParameters);
    }

    private void implTestBufferingEngine(SparkleEngine.SparkleParameters sparkleParameters)
        throws Exception
    {
        Random random = new Random();

        int plaintextLength = 256;
        byte[] plaintext = new byte[plaintextLength];
        random.nextBytes(plaintext);

        SparkleEngine sparkle0 = createEngine(sparkleParameters);
        initEngine(sparkle0, true);

        byte[] ciphertext = new byte[sparkle0.getOutputSize(plaintextLength)];
        random.nextBytes(ciphertext);

        int ciphertextLength = sparkle0.processBytes(plaintext, 0, plaintextLength, ciphertext, 0);
        ciphertextLength += sparkle0.doFinal(ciphertext, ciphertextLength);

        byte[] output = new byte[ciphertextLength];

        // Encryption
        for (int split = 1; split < plaintextLength; ++split)
        {
            SparkleEngine sparkle = createEngine(sparkleParameters);
            initEngine(sparkle, true);

            random.nextBytes(output);

            int length = sparkle.processBytes(plaintext, 0, split, output, 0);

            if (0 != sparkle.getUpdateOutputSize(0))
            {
                fail("");
            }

            length += sparkle.processBytes(plaintext, split, plaintextLength - split, output, length);
            length += sparkle.doFinal(output, length);

            if (!Arrays.areEqual(ciphertext, 0, ciphertextLength, output, 0, length))
            {
                fail("encryption failed with split: " + split);
            }
        }

        // Decryption
        for (int split = 1; split < ciphertextLength; ++split)
        {
            SparkleEngine sparkle = createEngine(sparkleParameters);
            initEngine(sparkle, false);

            random.nextBytes(output);

            int length = sparkle.processBytes(ciphertext, 0, split, output, 0);

            if (0 != sparkle.getUpdateOutputSize(0))
            {
                fail("");
            }

            length += sparkle.processBytes(ciphertext, split, ciphertextLength - split, output, length);
            length += sparkle.doFinal(output, length);

            if (!Arrays.areEqual(plaintext, 0, plaintextLength, output, 0, length))
            {
                fail("decryption failed with split: " + split);
            }
        }
    }

    private void implTestExceptionsDigest(SparkleDigest.SparkleParameters sparkleParameters)
    {
        SparkleDigest sparkle = createDigest(sparkleParameters);

        try
        {
            sparkle.update(new byte[1], 1, 1);
            fail(sparkle.getAlgorithmName() + ": input for update is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }

        try
        {
            sparkle.doFinal(new byte[sparkle.getDigestSize() - 1], 2);
            fail(sparkle.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
    }

    private void implTestVectorsDigest(SparkleDigest.SparkleParameters sparkleParameters, String filename)
        throws Exception
    {
        Random random = new Random();
        SparkleDigest sparkle = createDigest(sparkleParameters);
        InputStream src = TestResourceFinder.findTestResource("crypto/sparkle", "LWC_HASH_KAT_" + filename + ".txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
                byte[] ptByte = Hex.decode((String)map.get("Msg"));
                byte[] expected = Hex.decode((String)map.get("MD"));

                byte[] hash = new byte[sparkle.getDigestSize()];

                sparkle.update(ptByte, 0, ptByte.length);
                sparkle.doFinal(hash, 0);
                if (!areEqual(hash, expected))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }

                if (ptByte.length > 1)
                {
                    int split = random.nextInt(ptByte.length - 1) + 1;
                    sparkle.update(ptByte, 0, split);
                    sparkle.update(ptByte, split, ptByte.length - split);
                    sparkle.doFinal(hash, 0);
                    if (!areEqual(hash, expected))
                    {
                        mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                    }
                }

                map.clear();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    private void implTestVectorsEngine(SparkleEngine.SparkleParameters pbp, String filename)
        throws Exception
    {
        Random random = new Random();
        SparkleEngine sparkle = createEngine(pbp);
        InputStream src = TestResourceFinder.findTestResource("crypto/sparkle", "LWC_AEAD_KAT_"
            + filename + ".txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
                byte[] key = Hex.decode(map.get("Key"));
                byte[] nonce = Hex.decode(map.get("Nonce"));
                byte[] ad = Hex.decode(map.get("AD"));
                byte[] pt = Hex.decode(map.get("PT"));
                byte[] ct = Hex.decode(map.get("CT"));

                CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), nonce);

                // Encrypt
                {
                    sparkle.init(true, parameters);

                    byte[] rv = new byte[sparkle.getOutputSize(pt.length)];
                    random.nextBytes(rv); // should overwrite any existing data

                    sparkle.processAADBytes(ad, 0, ad.length);
                    int len = sparkle.processBytes(pt, 0, pt.length, rv, 0);
                    len += sparkle.doFinal(rv, len);

                    if (!areEqual(rv, 0, len, ct, 0, ct.length))
                    {
                        mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                    }
                }

                // Decrypt
                {
                    sparkle.init(false, parameters);

                    byte[] rv = new byte[sparkle.getOutputSize(ct.length)];
                    random.nextBytes(rv); // should overwrite any existing data

                    sparkle.processAADBytes(ad, 0, ad.length);
                    int len = sparkle.processBytes(ct, 0, ct.length, rv, 0);
                    len += sparkle.doFinal(rv, len);

                    if (!areEqual(rv, 0, len, pt, 0, pt.length))
                    {
                        mismatch("Reccover Keystream " + map.get("Count"), (String)map.get("PT"), rv);
                    }
                }

                map.clear();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    private void implTestExceptionsEngine(SparkleEngine.SparkleParameters sparkleParameters)
        throws Exception
    {
        SparkleEngine sparkle = createEngine(sparkleParameters);

        int keysize = sparkle.getKeyBytesSize(), ivsize = sparkle.getIVBytesSize();
        int offset;
        byte[] k = new byte[keysize];
        byte[] iv = new byte[ivsize];
        byte[] m = new byte[0];
        CipherParameters params = new ParametersWithIV(new KeyParameter(k), iv);
        try
        {
            sparkle.processBytes(m, 0, m.length, null, 0);
            fail(sparkle.getAlgorithmName() + " need to be initialized before processBytes");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            sparkle.processByte((byte)0, null, 0);
            fail(sparkle.getAlgorithmName() + " need to be initialized before processByte");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            sparkle.reset();
            fail(sparkle.getAlgorithmName() + " need to be initialized before reset");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            sparkle.doFinal(null, m.length);
            fail(sparkle.getAlgorithmName() + " need to be initialized before dofinal");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            sparkle.getMac();
            sparkle.getOutputSize(0);
            sparkle.getUpdateOutputSize(0);
        }
        catch (IllegalStateException e)
        {
            //expected
            fail(sparkle.getAlgorithmName() + " functions can be called before initialization");
        }

        Random rand = new Random();
        int randomNum;
        while ((randomNum = rand.nextInt(100)) == keysize) ;
        byte[] k1 = new byte[randomNum];
        while ((randomNum = rand.nextInt(100)) == ivsize) ;
        byte[] iv1 = new byte[randomNum];
        try
        {
            sparkle.init(true, new ParametersWithIV(new KeyParameter(k1), iv));
            fail(sparkle.getAlgorithmName() + " k size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }
        try
        {
            sparkle.init(true, new ParametersWithIV(new KeyParameter(k), iv1));
            fail(sparkle.getAlgorithmName() + "iv size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        try
        {
            sparkle.init(true, new AEADParameters(new KeyParameter(k), 0, iv));
            fail(sparkle.getAlgorithmName() + " wrong type of CipherParameters");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        sparkle.init(true, params);
        byte[] c1 = new byte[sparkle.getOutputSize(m.length)];
        try
        {
            sparkle.doFinal(c1, m.length);
        }
        catch (Exception e)
        {
            fail(sparkle.getAlgorithmName() + " allows no input for AAD and plaintext");
        }
        byte[] mac2 = sparkle.getMac();
        if (mac2 == null)
        {
            fail("mac should not be empty after dofinal");
        }
        if (!areEqual(mac2, c1))
        {
            fail("mac should be equal when calling dofinal and getMac");
        }
        sparkle.init(true, params);
        sparkle.processAADByte((byte)0);
        byte[] mac1 = new byte[sparkle.getOutputSize(0)];
        sparkle.doFinal(mac1, 0);
        if (areEqual(mac1, mac2))
        {
            fail("mac should not match");
        }
        sparkle.init(true, params);
        sparkle.processByte((byte)0, null, 0);
        try
        {
            sparkle.processAADByte((byte)0);
            fail("processAADByte(s) cannot be called after encryption/decryption");
        }
        catch (IllegalStateException e)
        {
            //expected
        }
        try
        {
            sparkle.processAADBytes(new byte[]{0}, 0, 1);
            fail("processAADByte(s) cannot be called once only");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        sparkle.reset();
        try
        {
            sparkle.processAADBytes(new byte[]{0}, 1, 1);
            fail("input for processAADBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            sparkle.processBytes(new byte[]{0}, 1, 1, c1, 0);
            fail("input for processBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        sparkle.init(true, params);
        try
        {
            int need = sparkle.getUpdateOutputSize(64);
            sparkle.processBytes(new byte[64], 0, 64, new byte[need], 1);
            fail("output for processBytes is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
        try
        {
            sparkle.doFinal(new byte[2], 2);
            fail("output for dofinal is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }

        implTestExceptionsGetUpdateOutputSize(sparkle, false, params, 100);
        implTestExceptionsGetUpdateOutputSize(sparkle, true, params, 100);

        mac1 = new byte[sparkle.getOutputSize(0)];
        mac2 = new byte[sparkle.getOutputSize(0)];
        sparkle.init(true, params);
        sparkle.processAADBytes(new byte[]{0, 0}, 0, 2);
        sparkle.doFinal(mac1, 0);
        sparkle.init(true, params);
        sparkle.processAADByte((byte)0);
        sparkle.processAADByte((byte)0);
        sparkle.doFinal(mac2, 0);
        if (!areEqual(mac1, mac2))
        {
            fail("mac should match for the same AAD with different ways of inputing");
        }

        byte[] c2 = new byte[sparkle.getOutputSize(10)];
        byte[] c3 = new byte[sparkle.getOutputSize(10) + 2];

        byte[] aad2 = {0, 1, 2, 3, 4};
        byte[] aad3 = {0, 0, 1, 2, 3, 4, 5};
        byte[] m2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] m3 = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        byte[] m4 = new byte[m2.length];
        sparkle.init(true, params);
        sparkle.processAADBytes(aad2, 0, aad2.length);
        offset = sparkle.processBytes(m2, 0, m2.length, c2, 0);
        sparkle.doFinal(c2, offset);
        sparkle.init(true, params);
        sparkle.processAADBytes(aad3, 1, aad2.length);
        offset = sparkle.processBytes(m3, 1, m2.length, c3, 1);
        sparkle.doFinal(c3, offset + 1);
        byte[] c3_partial = new byte[c2.length];
        System.arraycopy(c3, 1, c3_partial, 0, c2.length);
        if (!areEqual(c2, c3_partial))
        {
            fail("mac should match for the same AAD and message with different offset for both input and output");
        }
        sparkle.init(false, params);
        sparkle.processAADBytes(aad2, 0, aad2.length);
        offset = sparkle.processBytes(c2, 0, c2.length, m4, 0);
        sparkle.doFinal(m4, offset);
        if (!areEqual(m2, m4))
        {
            fail("The encryption and decryption does not recover the plaintext");
        }
        c2[c2.length - 1] ^= 1;
        sparkle.init(false, params);
        sparkle.processAADBytes(aad2, 0, aad2.length);
        offset = sparkle.processBytes(c2, 0, c2.length, m4, 0);
        try
        {
            sparkle.doFinal(m4, offset);
            fail("The decryption should fail");
        }
        catch (InvalidCipherTextException e)
        {
            //expected;
        }

        byte[] m7 = new byte[32 + rand.nextInt(32)];
        rand.nextBytes(m7);

        sparkle.init(true, params);
        byte[] c7 = new byte[sparkle.getOutputSize(m7.length)];
        byte[] c8 = new byte[c7.length];
        byte[] c9 = new byte[c7.length];
        sparkle.processAADBytes(aad2, 0, aad2.length);
        offset = sparkle.processBytes(m7, 0, m7.length, c7, 0);
        sparkle.doFinal(c7, offset);

        sparkle.init(true, params);
        sparkle.processAADBytes(aad2, 0, aad2.length);
        offset = sparkle.processBytes(m7, 0, m7.length / 2, c8, 0);
        offset += sparkle.processBytes(m7, m7.length / 2, m7.length - m7.length / 2, c8, offset);
        sparkle.doFinal(c8, offset);

        sparkle.init(true, params);
        int split = rand.nextInt(m7.length - 1) + 1;
        sparkle.processAADBytes(aad2, 0, aad2.length);
        offset = sparkle.processBytes(m7, 0, split, c9, 0);
        offset += sparkle.processBytes(m7, split, m7.length - split, c9, offset);
        sparkle.doFinal(c9, offset);

        if (!areEqual(c7, c8) || !areEqual(c7, c9))
        {
            fail("Splitting input of plaintext should output the same ciphertext");
        }
    }

    private void implTestExceptionsGetUpdateOutputSize(SparkleEngine sparkle, boolean forEncryption,
        CipherParameters parameters, int maxInputSize)
    {
        sparkle.init(forEncryption, parameters);

        int maxOutputSize = sparkle.getUpdateOutputSize(maxInputSize);

        byte[] input = new byte[maxInputSize];
        byte[] output = new byte[maxOutputSize];

        for (int inputSize = 0; inputSize <= maxInputSize; ++inputSize)
        {
            sparkle.init(forEncryption, parameters);

            int outputSize = sparkle.getUpdateOutputSize(inputSize);
            if (outputSize > 0)
            {
                try
                {
                    sparkle.processBytes(input, 0, inputSize, output, maxOutputSize - outputSize + 1);
                    fail("output for processBytes is too short");
                }
                catch (OutputLengthException e)
                {
                    //expected
                }
            }
            else
            {
                sparkle.processBytes(input, 0, inputSize, null, 0);
            }
        }
    }

    private void implTestParametersDigest(SparkleDigest.SparkleParameters sparkleParameters, int digestSize)
    {
        SparkleDigest sparkle = createDigest(sparkleParameters);

        if (sparkle.getDigestSize() != digestSize)
        {
            fail(sparkle.getAlgorithmName() + ": digest size is not correct");
        }
    }

    private void implTestParametersEngine(SparkleEngine.SparkleParameters sparkleParameters, int keySize, int ivSize,
        int macSize)
    {
        SparkleEngine sparkle = createEngine(sparkleParameters);

        if (sparkle.getKeyBytesSize() != keySize)
        {
            fail("key bytes of " + sparkle.getAlgorithmName() + " is not correct");
        }
        if (sparkle.getIVBytesSize() != ivSize)
        {
            fail("iv bytes of " + sparkle.getAlgorithmName() + " is not correct");
        }

        CipherParameters parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

        sparkle.init(true, parameters);
        if (sparkle.getOutputSize(0) != macSize)
        {
            fail("getOutputSize of " + sparkle.getAlgorithmName() + " is incorrect for encryption");
        }

        sparkle.init(false, parameters);
        if (sparkle.getOutputSize(macSize) != 0)
        {
            fail("getOutputSize of " + sparkle.getAlgorithmName() + " is incorrect for decryption");
        }
    }

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    private static void initEngine(SparkleEngine sparkle, boolean forEncryption)
    {
        int keySize = sparkle.getKeyBytesSize();
        int ivSize = sparkle.getIVBytesSize();
        int macSize = keySize * 8;

        AEADParameters parameters = new AEADParameters(new KeyParameter(new byte[keySize]), macSize, new byte[ivSize], null);
        sparkle.init(forEncryption, parameters);
    }
}
