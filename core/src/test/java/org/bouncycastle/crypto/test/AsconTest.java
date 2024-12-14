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
import org.bouncycastle.crypto.digests.AsconDigest;
import org.bouncycastle.crypto.digests.AsconXof;
import org.bouncycastle.crypto.engines.AsconEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class AsconTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new AsconTest());
    }
    
    public String getName()
    {
        return "Ascon";
    }

    public void performTest()
        throws Exception
    {
        testBufferingEngine_ascon128();
        testBufferingEngine_ascon128a();
        testBufferingEngine_ascon80();

        testExceptionsDigest_AsconHash();
        testExceptionsDigest_AsconHashA();

        testExceptionsEngine_ascon128();
        testExceptionsEngine_ascon128a();
        testExceptionsEngine_ascon80pq();

        testExceptionsXof_AsconXof();
        testExceptionsXof_AsconXofA();

        testParametersDigest_AsconHash();
        testParametersDigest_AsconHashA();

        testParametersEngine_ascon128();
        testParametersEngine_ascon128a();
        testParametersEngine_ascon80pq();

        testParametersXof_AsconXof();
        testParametersXof_AsconXofA();

        testVectorsDigest_AsconHash();
        testVectorsDigest_AsconHashA();

        testVectorsEngine_ascon128();
        testVectorsEngine_ascon128a();
        testVectorsEngine_ascon80pq();

        testVectorsXof_AsconXof();
        testVectorsXof_AsconXofA();
    }

    public void testBufferingEngine_ascon128() throws Exception
    {
        implTestBufferingEngine(AsconEngine.AsconParameters.ascon128);
    }

    public void testBufferingEngine_ascon128a() throws Exception
    {
        implTestBufferingEngine(AsconEngine.AsconParameters.ascon128a);
    }

    public void testBufferingEngine_ascon80() throws Exception
    {
        implTestBufferingEngine(AsconEngine.AsconParameters.ascon80pq);
    }

    public void testExceptionsDigest_AsconHash() throws Exception
    {
        implTestExceptionsDigest(AsconDigest.AsconParameters.AsconHash);
    }

    public void testExceptionsDigest_AsconHashA() throws Exception
    {
        implTestExceptionsDigest(AsconDigest.AsconParameters.AsconHashA);
    }

    public void testExceptionsEngine_ascon128() throws Exception
    {
        implTestExceptionsEngine(AsconEngine.AsconParameters.ascon128);
    }

    public void testExceptionsEngine_ascon128a() throws Exception
    {
        implTestExceptionsEngine(AsconEngine.AsconParameters.ascon128a);
    }

    public void testExceptionsEngine_ascon80pq() throws Exception
    {
        implTestExceptionsEngine(AsconEngine.AsconParameters.ascon80pq);
    }

    public void testExceptionsXof_AsconXof() throws Exception
    {
        implTestExceptionsXof(AsconXof.AsconParameters.AsconXof);
    }

    public void testExceptionsXof_AsconXofA() throws Exception
    {
        implTestExceptionsXof(AsconXof.AsconParameters.AsconXofA);
    }

    public void testParametersDigest_AsconHash() throws Exception
    {
        implTestParametersDigest(AsconDigest.AsconParameters.AsconHash, 32);
    }

    public void testParametersDigest_AsconHashA() throws Exception
    {
        implTestParametersDigest(AsconDigest.AsconParameters.AsconHashA, 32);
    }

    public void testParametersEngine_ascon128() throws Exception
    {
        implTestParametersEngine(AsconEngine.AsconParameters.ascon128, 16, 16, 16);
    }

    public void testParametersEngine_ascon128a() throws Exception
    {
        implTestParametersEngine(AsconEngine.AsconParameters.ascon128a, 16, 16, 16);
    }

    public void testParametersEngine_ascon80pq() throws Exception
    {
        implTestParametersEngine(AsconEngine.AsconParameters.ascon80pq, 20, 16, 16);
    }

    public void testParametersXof_AsconXof() throws Exception
    {
        implTestParametersXof(AsconXof.AsconParameters.AsconXof, 32);
    }

    public void testParametersXof_AsconXofA() throws Exception
    {
        implTestParametersXof(AsconXof.AsconParameters.AsconXofA, 32);
    }

    public void testVectorsDigest_AsconHash() throws Exception
    {
        implTestVectorsDigest(AsconDigest.AsconParameters.AsconHash, "asconhash");
    }

    public void testVectorsDigest_AsconHashA() throws Exception
    {
        implTestVectorsDigest(AsconDigest.AsconParameters.AsconHashA, "asconhasha");
    }

    public void testVectorsEngine_ascon128() throws Exception
    {
        implTestVectorsEngine(AsconEngine.AsconParameters.ascon128, "128_128");
    }

    public void testVectorsEngine_ascon128a() throws Exception
    {
        implTestVectorsEngine(AsconEngine.AsconParameters.ascon128a, "128_128_a");
    }

    public void testVectorsEngine_ascon80pq() throws Exception
    {
        implTestVectorsEngine(AsconEngine.AsconParameters.ascon80pq, "160_128");
    }

    public void testVectorsXof_AsconXof() throws Exception
    {
        implTestVectorsXof(AsconXof.AsconParameters.AsconXof, "asconxof");
    }

    public void testVectorsXof_AsconXofA() throws Exception
    {
        implTestVectorsXof(AsconXof.AsconParameters.AsconXofA, "asconxofa");
    }

    private static AsconDigest createDigest(AsconDigest.AsconParameters asconParameters)
    {
        return new AsconDigest(asconParameters);
    }

    private static AsconEngine createEngine(AsconEngine.AsconParameters asconParameters)
    {
        return new AsconEngine(asconParameters);
    }

    private static AsconXof createXof(AsconXof.AsconParameters asconParameters)
    {
        return new AsconXof(asconParameters);
    }

    private void implTestBufferingEngine(AsconEngine.AsconParameters asconParameters)
        throws Exception
    {
        Random random = new Random();

        int plaintextLength = 256;
        byte[] plaintext = new byte[plaintextLength];
        random.nextBytes(plaintext);

        AsconEngine ascon0 = createEngine(asconParameters);
        initEngine(ascon0, true);

        byte[] ciphertext = new byte[ascon0.getOutputSize(plaintextLength)];
        random.nextBytes(ciphertext);

        int ciphertextLength = ascon0.processBytes(plaintext, 0, plaintextLength, ciphertext, 0);
        ciphertextLength += ascon0.doFinal(ciphertext, ciphertextLength);

        byte[] output = new byte[ciphertextLength];

        // Encryption
        for (int split = 1; split < plaintextLength; ++split)
        {
            AsconEngine ascon = createEngine(asconParameters);
            initEngine(ascon, true);

            random.nextBytes(output);

            int length = ascon.processBytes(plaintext, 0, split, output, 0);

            if (0 != ascon.getUpdateOutputSize(0))
            {
                fail("");
            }
            
            length += ascon.processBytes(plaintext, split, plaintextLength - split, output, length);
            length += ascon.doFinal(output, length);

            if (!Arrays.areEqual(ciphertext, 0, ciphertextLength, output, 0, length))
            {
                fail("encryption failed with split: " + split);
            }
        }

        // Decryption
        for (int split = 1; split < ciphertextLength; ++split)
        {
            AsconEngine ascon = createEngine(asconParameters);
            initEngine(ascon, false);

            random.nextBytes(output);

            int length = ascon.processBytes(ciphertext, 0, split, output, 0);

            if (0 != ascon.getUpdateOutputSize(0))
            {
                fail("");
            }

            length += ascon.processBytes(ciphertext, split, ciphertextLength - split, output, length);
            length += ascon.doFinal(output, length);

            if (!Arrays.areEqual(plaintext, 0, plaintextLength, output, 0, length))
            {
                fail("decryption failed with split: " + split);
            }
        }
    }

    private void implTestExceptionsDigest(AsconDigest.AsconParameters asconParameters)
    {
        AsconDigest ascon = createDigest(asconParameters);

        try
        {
            ascon.update(new byte[1], 1, 1);
            fail(ascon.getAlgorithmName() + ": input for update is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }

        try
        {
            ascon.doFinal(new byte[ascon.getDigestSize() - 1], 2);
            fail(ascon.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
    }

    private void implTestExceptionsEngine(AsconEngine.AsconParameters asconParameters)
        throws Exception
    {
        AsconEngine ascon = createEngine(asconParameters);
        int keySize = ascon.getKeyBytesSize(), ivSize = ascon.getIVBytesSize();
        int offset;
        byte[] k = new byte[keySize];
        byte[] iv = new byte[ivSize];
        byte[] m = new byte[0];
        CipherParameters params = new ParametersWithIV(new KeyParameter(k), iv);
        try
        {
            ascon.processBytes(m, 0, m.length, null, 0);
            fail(ascon.getAlgorithmName() + " need to be initialized before processBytes");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            ascon.processByte((byte)0, null, 0);
            fail(ascon.getAlgorithmName() + " need to be initialized before processByte");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            ascon.reset();
            fail(ascon.getAlgorithmName() + " need to be initialized before reset");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            ascon.doFinal(null, m.length);
            fail(ascon.getAlgorithmName() + " need to be initialized before dofinal");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            ascon.getMac();
            ascon.getOutputSize(0);
            ascon.getUpdateOutputSize(0);
        }
        catch (IllegalStateException e)
        {
            //expected
            fail(ascon.getAlgorithmName() + " functions can be called before initialization");
        }

        Random rand = new Random();
        int randomNum;
        while ((randomNum = rand.nextInt(100)) == keySize) ;
        byte[] k1 = new byte[randomNum];
        while ((randomNum = rand.nextInt(100)) == ivSize) ;
        byte[] iv1 = new byte[randomNum];
        try
        {
            ascon.init(true, new ParametersWithIV(new KeyParameter(k1), iv));
            fail(ascon.getAlgorithmName() + " k size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }
        try
        {
            ascon.init(true, new ParametersWithIV(new KeyParameter(k), iv1));
            fail(ascon.getAlgorithmName() + "iv size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        try
        {
            ascon.init(true, new AEADParameters(new KeyParameter(k), 0, iv));
            fail(ascon.getAlgorithmName() + " wrong type of CipherParameters");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        ascon.init(true, params);
        byte[] c1 = new byte[ascon.getOutputSize(m.length)];
        try
        {
            ascon.doFinal(c1, m.length);
        }
        catch (Exception e)
        {
            fail(ascon.getAlgorithmName() + " allows no input for AAD and plaintext");
        }
        byte[] mac2 = ascon.getMac();
        if (mac2 == null)
        {
            fail("mac should not be empty after dofinal");
        }
        if (!areEqual(mac2, c1))
        {
            fail("mac should be equal when calling dofinal and getMac");
        }
        ascon.init(true, params);
        ascon.processAADByte((byte)0);
        byte[] mac1 = new byte[ascon.getOutputSize(0)];
        ascon.doFinal(mac1, 0);
        if (areEqual(mac1, mac2))
        {
            fail("mac should not match");
        }
        ascon.init(true, params);
        ascon.processByte((byte)0, null, 0);
        try
        {
            ascon.processAADByte((byte)0);
            fail("processAADByte(s) cannot be called after encryption/decryption");
        }
        catch (IllegalStateException e)
        {
            //expected
        }
        try
        {
            ascon.processAADBytes(new byte[]{0}, 0, 1);
            fail("processAADByte(s) cannot be called once only");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        ascon.reset();
        try
        {
            ascon.processAADBytes(new byte[]{0}, 1, 1);
            fail("input for processAADBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            ascon.processBytes(new byte[]{0}, 1, 1, c1, 0);
            fail("input for processBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        ascon.init(true, params);
        try
        {
            int need = ascon.getUpdateOutputSize(64);
            ascon.processBytes(new byte[64], 0, 64, new byte[need], 1);
            fail("output for processBytes is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
        try
        {
            ascon.doFinal(new byte[2], 2);
            fail("output for dofinal is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }

        implTestExceptionsGetUpdateOutputSize(ascon, false, params, 100);
        implTestExceptionsGetUpdateOutputSize(ascon, true, params, 100);

        mac1 = new byte[ascon.getOutputSize(0)];
        mac2 = new byte[ascon.getOutputSize(0)];
        ascon.init(true, params);
        ascon.processAADBytes(new byte[]{0, 0}, 0, 2);
        ascon.doFinal(mac1, 0);
        ascon.init(true, params);
        ascon.processAADByte((byte)0);
        ascon.processAADByte((byte)0);
        ascon.doFinal(mac2, 0);
        if (!areEqual(mac1, mac2))
        {
            fail("mac should match for the same AAD with different ways of inputing");
        }

        byte[] c2 = new byte[ascon.getOutputSize(10)];
        byte[] c3 = new byte[ascon.getOutputSize(10) + 2];

        byte[] aad2 = {0, 1, 2, 3, 4};
        byte[] aad3 = {0, 0, 1, 2, 3, 4, 5};
        byte[] m2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] m3 = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        byte[] m4 = new byte[m2.length];
        ascon.init(true, params);
        ascon.processAADBytes(aad2, 0, aad2.length);
        offset = ascon.processBytes(m2, 0, m2.length, c2, 0);
        ascon.doFinal(c2, offset);
        ascon.init(true, params);
        ascon.processAADBytes(aad3, 1, aad2.length);
        offset = ascon.processBytes(m3, 1, m2.length, c3, 1);
        ascon.doFinal(c3, offset + 1);
        byte[] c3_partial = new byte[c2.length];
        System.arraycopy(c3, 1, c3_partial, 0, c2.length);
        if (!areEqual(c2, c3_partial))
        {
            fail("mac should match for the same AAD and message with different offset for both input and output");
        }
        ascon.init(false, params);
        ascon.processAADBytes(aad2, 0, aad2.length);
        offset = ascon.processBytes(c2, 0, c2.length, m4, 0);
        ascon.doFinal(m4, offset);
        if (!areEqual(m2, m4))
        {
            fail("The encryption and decryption does not recover the plaintext");
        }
        c2[c2.length - 1] ^= 1;
        ascon.init(false, params);
        ascon.processAADBytes(aad2, 0, aad2.length);
        offset = ascon.processBytes(c2, 0, c2.length, m4, 0);
        try
        {
            ascon.doFinal(m4, offset);
            fail("The decryption should fail");
        }
        catch (InvalidCipherTextException e)
        {
            //expected;
        }

        byte[] m7 = new byte[32 + rand.nextInt(32)];
        rand.nextBytes(m7);

        ascon.init(true, params);
        byte[] c7 = new byte[ascon.getOutputSize(m7.length)];
        byte[] c8 = new byte[c7.length];
        byte[] c9 = new byte[c7.length];
        ascon.processAADBytes(aad2, 0, aad2.length);
        offset = ascon.processBytes(m7, 0, m7.length, c7, 0);
        ascon.doFinal(c7, offset);

        ascon.init(true, params);
        ascon.processAADBytes(aad2, 0, aad2.length);
        offset = ascon.processBytes(m7, 0, m7.length / 2, c8, 0);
        offset += ascon.processBytes(m7, m7.length / 2, m7.length - m7.length / 2, c8, offset);
        offset += ascon.doFinal(c8, offset);

        ascon.init(true, params);
        int split = rand.nextInt(m7.length - 1) + 1;
        ascon.processAADBytes(aad2, 0, aad2.length);
        offset = ascon.processBytes(m7, 0, split, c9, 0);
        offset += ascon.processBytes(m7, split, m7.length - split, c9, offset);
        offset += ascon.doFinal(c9, offset);

        if (!areEqual(c7, c8) || !areEqual(c7, c9))
        {
            fail("Splitting input of plaintext should output the same ciphertext");
        }
    }

    private void implTestExceptionsGetUpdateOutputSize(AsconEngine ascon, boolean forEncryption,
        CipherParameters parameters, int maxInputSize)
    {
        ascon.init(forEncryption, parameters);

        int maxOutputSize = ascon.getUpdateOutputSize(maxInputSize);

        byte[] input = new byte[maxInputSize];
        byte[] output = new byte[maxOutputSize];

        for (int inputSize = 0; inputSize <= maxInputSize; ++inputSize)
        {
            ascon.init(forEncryption, parameters);

            int outputSize = ascon.getUpdateOutputSize(inputSize);
            if (outputSize > 0)
            {
                try
                {
                    ascon.processBytes(input, 0, inputSize, output, maxOutputSize - outputSize + 1);
                    fail("output for processBytes is too short");
                }
                catch (OutputLengthException e)
                {
                    //expected
                }
            }
            else
            {
                ascon.processBytes(input, 0, inputSize, null, 0);
            }
        }
    }

    private void implTestExceptionsXof(AsconXof.AsconParameters asconParameters)
    {
        AsconXof ascon = createXof(asconParameters);

        try
        {
            ascon.update(new byte[1], 1, 1);
            fail(ascon.getAlgorithmName() + ": input for update is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }

        try
        {
            ascon.doFinal(new byte[ascon.getDigestSize() - 1], 2);
            fail(ascon.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
    }

    private void implTestParametersDigest(AsconDigest.AsconParameters asconParameters, int digestSize)
    {
        AsconDigest ascon = createDigest(asconParameters);

        if (ascon.getDigestSize() != digestSize)
        {
            fail(ascon.getAlgorithmName() + ": digest size is not correct");
        }
    }

    private void implTestParametersEngine(AsconEngine.AsconParameters asconParameters, int keySize, int ivSize,
        int macSize)
    {
        AsconEngine ascon = createEngine(asconParameters);

        if (ascon.getKeyBytesSize() != keySize)
        {
            fail("key bytes of " + ascon.getAlgorithmName() + " is not correct");
        }
        if (ascon.getIVBytesSize() != ivSize)
        {
            fail("iv bytes of " + ascon.getAlgorithmName() + " is not correct");
        }

        CipherParameters parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

        ascon.init(true, parameters);
        if (ascon.getOutputSize(0) != macSize)
        {
            fail("getOutputSize of " + ascon.getAlgorithmName() + " is incorrect for encryption");
        }

        ascon.init(false, parameters);
        if (ascon.getOutputSize(macSize) != 0)
        {
            fail("getOutputSize of " + ascon.getAlgorithmName() + " is incorrect for decryption");
        }
    }

    private void implTestParametersXof(AsconXof.AsconParameters asconParameters, int digestSize)
    {
        AsconXof ascon = createXof(asconParameters);

        if (ascon.getDigestSize() != digestSize)
        {
            fail(ascon.getAlgorithmName() + ": digest size is not correct");
        }
    }

    private void implTestVectorsDigest(AsconDigest.AsconParameters asconParameters, String filename)
        throws Exception
    {
        Random random = new Random();
        AsconDigest ascon = createDigest(asconParameters);
        InputStream src = TestResourceFinder.findTestResource("crypto/ascon", filename + "_LWC_HASH_KAT_256.txt");
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

                byte[] hash = new byte[ascon.getDigestSize()];

                ascon.update(ptByte, 0, ptByte.length);
                ascon.doFinal(hash, 0);
                if (!areEqual(hash, expected))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }

                if (ptByte.length > 1)
                {
                    int split = random.nextInt(ptByte.length - 1) + 1;
                    ascon.update(ptByte, 0, split);
                    ascon.update(ptByte, split, ptByte.length - split);
                    ascon.doFinal(hash, 0);
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

    private void implTestVectorsEngine(AsconEngine.AsconParameters asconParameters, String filename)
        throws Exception
    {
        Random random = new Random();
        AsconEngine ascon = createEngine(asconParameters);
        InputStream src = TestResourceFinder.findTestResource("crypto/ascon", "LWC_AEAD_KAT_" + filename + ".txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
                byte[] key = Hex.decode((String)map.get("Key"));
                byte[] nonce = Hex.decode((String)map.get("Nonce"));
                byte[] ad = Hex.decode((String)map.get("AD"));
                byte[] pt = Hex.decode((String)map.get("PT"));
                byte[] ct = Hex.decode((String)map.get("CT"));

                CipherParameters parameters = new ParametersWithIV(new KeyParameter(key), nonce);

                // Encrypt
                {
                    ascon.init(true, parameters);

                    byte[] rv = new byte[ascon.getOutputSize(pt.length)];
                    random.nextBytes(rv); // should overwrite any existing data

                    ascon.processAADBytes(ad, 0, ad.length);
                    int len = ascon.processBytes(pt, 0, pt.length, rv, 0);
                    len += ascon.doFinal(rv, len);

                    if (!areEqual(rv, 0, len, ct, 0, ct.length))
                    {
                        mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                    }
                }

                // Decrypt
                {
                    ascon.init(false, parameters);

                    byte[] rv = new byte[ascon.getOutputSize(ct.length)];
                    random.nextBytes(rv); // should overwrite any existing data

                    ascon.processAADBytes(ad, 0, ad.length);
                    int len = ascon.processBytes(ct, 0, ct.length, rv, 0);
                    len += ascon.doFinal(rv, len);

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

    private void implTestVectorsXof(AsconXof.AsconParameters asconParameters, String filename)
        throws Exception
    {
        Random random = new Random();
        AsconXof ascon = createXof(asconParameters);
        InputStream src = TestResourceFinder.findTestResource("crypto/ascon", filename + "_LWC_HASH_KAT_256.txt");
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

                byte[] hash = new byte[ascon.getDigestSize()];

                ascon.update(ptByte, 0, ptByte.length);
                ascon.doFinal(hash, 0);
                if (!areEqual(hash, expected))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }

                if (ptByte.length > 1)
                {
                    int split = random.nextInt(ptByte.length - 1) + 1;
                    ascon.update(ptByte, 0, split);
                    ascon.update(ptByte, split, ptByte.length - split);
                    ascon.doFinal(hash, 0);
                    if (!areEqual(hash, expected))
                    {
                        mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                    }
                }
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    private static void initEngine(AsconEngine ascon, boolean forEncryption)
    {
        int keySize = ascon.getKeyBytesSize();
        int ivSize = ascon.getIVBytesSize();
        int macSize = ivSize * 8;

        AEADParameters parameters = new AEADParameters(new KeyParameter(new byte[keySize]), macSize, new byte[ivSize], null);
        ascon.init(forEncryption, parameters);
    }
}
