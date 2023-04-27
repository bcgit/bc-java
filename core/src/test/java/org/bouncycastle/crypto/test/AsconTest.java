package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Random;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.AsconDigest;
import org.bouncycastle.crypto.digests.AsconXof;
import org.bouncycastle.crypto.engines.AsconEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
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
    public String getName()
    {
        return "Ascon";
    }

    public void performTest()
        throws Exception
    {
        implTestBufferingEngine(AsconEngine.AsconParameters.ascon128);
        implTestBufferingEngine(AsconEngine.AsconParameters.ascon128a);
        implTestBufferingEngine(AsconEngine.AsconParameters.ascon80pq);

        testVectorsHash(AsconDigest.AsconParameters.AsconHashA, "asconhasha");
        testVectorsHash(AsconDigest.AsconParameters.AsconHash, "asconhash");
        testVectorsHash(AsconXof.AsconParameters.AsconXof, "asconxof");
        testVectorsHash(AsconXof.AsconParameters.AsconXofA, "asconxofa");
        implTestExceptions(new AsconDigest(AsconDigest.AsconParameters.AsconHashA), 32);
        implTestExceptions(new AsconDigest(AsconDigest.AsconParameters.AsconHash), 32);
        implTestExceptions(new AsconXof(AsconXof.AsconParameters.AsconXof), 32);
        implTestExceptions(new AsconXof(AsconXof.AsconParameters.AsconXofA), 32);
        AsconEngine Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon80pq);
        testExceptions(Ascon, Ascon.getKeyBytesSize(), Ascon.getIVBytesSize(), 8);
        testParameters(Ascon, 20, 16, 16);
        Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon128a);
        testExceptions(Ascon, Ascon.getKeyBytesSize(), Ascon.getIVBytesSize(), 16);
        testParameters(Ascon, 16, 16, 16);
        Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon128);
        testExceptions(Ascon, Ascon.getKeyBytesSize(), Ascon.getIVBytesSize(), 8);
        testParameters(Ascon, 16, 16, 16);
        testVectors(AsconEngine.AsconParameters.ascon80pq, "160_128");
        testVectors(AsconEngine.AsconParameters.ascon128a, "128_128_a");
        testVectors(AsconEngine.AsconParameters.ascon128, "128_128");
    }

    private void implTestBufferingEngine(AsconEngine.AsconParameters asconParameters)
        throws Exception
    {
        Random random = new Random();

        int plaintextLength = 256;
        byte[] plaintext = new byte[plaintextLength];
        random.nextBytes(plaintext);

        AsconEngine ascon0 = new AsconEngine(asconParameters);
        initEngine(ascon0, true);

        byte[] ciphertext = new byte[ascon0.getOutputSize(plaintextLength)];
        random.nextBytes(ciphertext);

        int ciphertextLength = ascon0.processBytes(plaintext, 0, plaintextLength, ciphertext, 0);
        ciphertextLength += ascon0.doFinal(ciphertext, ciphertextLength);

        byte[] output = new byte[ciphertextLength];

        // Encryption
        for (int split = 1; split < plaintextLength; ++split)
        {
            AsconEngine ascon = new AsconEngine(asconParameters);
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
            AsconEngine ascon = new AsconEngine(asconParameters);
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

    private void testVectors(AsconEngine.AsconParameters asconParameters, String filename)
        throws Exception
    {
        AsconEngine Ascon = new AsconEngine(asconParameters);
        CipherParameters params;
        InputStream src = TestResourceFinder.findTestResource("crypto/ascon", "LWC_AEAD_KAT_" + filename + ".txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] rv;
        HashMap<String, String> map = new HashMap<String, String>();
        Random random = new Random();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
//                if (!map.get("Count").equals("71"))
//                {
//                    continue;
//                }
                byte[] key = Hex.decode((String)map.get("Key"));
                byte[] nonce = Hex.decode((String)map.get("Nonce"));
                byte[] ad = Hex.decode((String)map.get("AD"));
                byte[] pt = Hex.decode((String)map.get("PT"));
                byte[] ct = Hex.decode((String)map.get("CT"));
                params = new ParametersWithIV(new KeyParameter(key), nonce);
                Ascon.init(true, params);
                Ascon.processAADBytes(ad, 0, ad.length);
                rv = new byte[Ascon.getOutputSize(pt.length)];
                random.nextBytes(rv);
                int len = Ascon.processBytes(pt, 0, pt.length, rv, 0);
                Ascon.doFinal(rv, len);
                if (!areEqual(rv, ct))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                }
                else
                {
                    System.out.println("Keystream " + map.get("Count") + " pass");
                }
                Ascon.reset();
                Ascon.init(false, params);
                //Decrypt
                Ascon.processAADBytes(ad, 0, ad.length);
                rv = new byte[pt.length + 16];
                random.nextBytes(rv);
                len = Ascon.processBytes(ct, 0, ct.length, rv, 0);
                Ascon.doFinal(rv, len);
                byte[] pt_recovered = new byte[pt.length];
                System.arraycopy(rv, 0, pt_recovered, 0, pt.length);
                if (!areEqual(pt, pt_recovered))
                {
                    mismatch("Reccover Keystream " + map.get("Count"), (String)map.get("PT"), pt_recovered);
                }
                Ascon.reset();
                map.clear();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println(Ascon.getAlgorithmName() + " " + Ascon.getAlgorithmVersion() + " Pass");
    }

    private void testExceptions(AEADCipher aeadBlockCipher, int keysize, int ivsize, int blocksize)
        throws Exception
    {
        CipherParameters params;
        byte[] k = new byte[keysize];
        byte[] iv = new byte[ivsize];
        byte[] m = new byte[0];
        byte[] c1 = new byte[aeadBlockCipher.getOutputSize(m.length)];
        params = new ParametersWithIV(new KeyParameter(k), iv);
        try
        {
            aeadBlockCipher.processBytes(m, 0, m.length, c1, 0);
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before processBytes");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.processByte((byte)0, c1, 0);
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before processByte");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.reset();
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before reset");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.doFinal(c1, m.length);
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before dofinal");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.getMac();
            aeadBlockCipher.getAlgorithmName();
            aeadBlockCipher.getOutputSize(0);
            aeadBlockCipher.getUpdateOutputSize(0);
        }
        catch (IllegalStateException e)
        {
            //expected
            fail(aeadBlockCipher.getAlgorithmName() + " functions can be called before initialisation");
        }
        Random rand = new Random();
        int randomNum;
        while ((randomNum = rand.nextInt(100)) == keysize) ;
        byte[] k1 = new byte[randomNum];
        while ((randomNum = rand.nextInt(100)) == ivsize) ;
        byte[] iv1 = new byte[randomNum];
        try
        {
            aeadBlockCipher.init(true, new ParametersWithIV(new KeyParameter(k1), iv));
            fail(aeadBlockCipher.getAlgorithmName() + " k size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.init(true, new ParametersWithIV(new KeyParameter(k), iv1));
            fail(aeadBlockCipher.getAlgorithmName() + "iv size does not match");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.init(true, new AEADParameters(new KeyParameter(k), 0, iv));
            fail(aeadBlockCipher.getAlgorithmName() + " wrong type of CipherParameters");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        aeadBlockCipher.init(true, params);
        try
        {
            aeadBlockCipher.doFinal(c1, m.length);
        }
        catch (Exception e)
        {
            fail(aeadBlockCipher.getAlgorithmName() + " allows no input for AAD and plaintext");
        }
        byte[] mac2 = aeadBlockCipher.getMac();
        if (mac2 == null)
        {
            fail("mac should not be empty after dofinal");
        }
        if (!areEqual(mac2, c1))
        {
            fail("mac should be equal when calling dofinal and getMac");
        }
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADByte((byte)0);
        byte[] mac1 = new byte[aeadBlockCipher.getOutputSize(0)];
        aeadBlockCipher.doFinal(mac1, 0);
        if (areEqual(mac1, mac2))
        {
            fail("mac should not match");
        }
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processBytes(new byte[16], 0, 16, new byte[16], 0);
        try
        {
            aeadBlockCipher.processAADByte((byte)0);
            fail("processAADByte(s) cannot be called after encryption/decryption");
        }
        catch (IllegalStateException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.processAADBytes(new byte[]{0}, 0, 1);
            fail("processAADByte(s) cannot be called once only");
        }
        catch (IllegalStateException e)
        {
            //expected
        }

        aeadBlockCipher.reset();
        try
        {
            aeadBlockCipher.processAADBytes(new byte[]{0}, 1, 1);
            fail("input for processAADBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.processBytes(new byte[]{0}, 1, 1, c1, 0);
            fail("input for processBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        aeadBlockCipher.init(true, params);
        try
        {
            aeadBlockCipher.processBytes(new byte[16], 0, 16, new byte[16], 8);
            fail("output for processBytes is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.doFinal(new byte[2], 2);
            fail("output for dofinal is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }

        mac1 = new byte[aeadBlockCipher.getOutputSize(0)];
        mac2 = new byte[aeadBlockCipher.getOutputSize(0)];
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(new byte[]{0, 0}, 0, 2);
        aeadBlockCipher.doFinal(mac1, 0);
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADByte((byte)0);
        aeadBlockCipher.processAADByte((byte)0);
        aeadBlockCipher.doFinal(mac2, 0);
        if (!areEqual(mac1, mac2))
        {
            fail("mac should match for the same AAD with different ways of inputing");
        }

        byte[] c2 = new byte[aeadBlockCipher.getOutputSize(10)];
        byte[] c3 = new byte[aeadBlockCipher.getOutputSize(10) + 2];

        byte[] aad2 = {0, 1, 2, 3, 4};
        byte[] aad3 = {0, 0, 1, 2, 3, 4, 5};
        byte[] m2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] m3 = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        byte[] m4 = new byte[m2.length];
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        int offset = aeadBlockCipher.processBytes(m2, 0, m2.length, c2, 0);
        aeadBlockCipher.doFinal(c2, offset);
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(aad3, 1, aad2.length);
        offset = aeadBlockCipher.processBytes(m3, 1, m2.length, c3, 1);
        aeadBlockCipher.doFinal(c3, offset + 1);
        byte[] c3_partial = new byte[c2.length];
        System.arraycopy(c3, 1, c3_partial, 0, c2.length);
        if (!areEqual(c2, c3_partial))
        {
            fail("mac should match for the same AAD and message with different offset for both input and output");
        }
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        aeadBlockCipher.doFinal(m4, offset);
        if (!areEqual(m2, m4))
        {
            fail("The encryption and decryption does not recover the plaintext");
        }
        c2[c2.length - 1] ^= 1;
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        try
        {
            aeadBlockCipher.doFinal(m4, offset);
            fail("The decryption should fail");
        }
        catch (InvalidCipherTextException e)
        {
            //expected;
        }

        byte[] m7 = new byte[blocksize * 2];
        rand.nextBytes(m7);

        aeadBlockCipher.init(true, params);
        byte[] c7 = new byte[aeadBlockCipher.getOutputSize(m7.length)];
        byte[] c8 = new byte[c7.length];
        byte[] c9 = new byte[c7.length];
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, m7.length, c7, 0);
        aeadBlockCipher.doFinal(c7, offset);
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, blocksize, c8, 0);
        offset += aeadBlockCipher.processBytes(m7, blocksize, m7.length - blocksize, c8, offset);
        aeadBlockCipher.doFinal(c8, offset);
        aeadBlockCipher.init(true, params);
        int split = rand.nextInt(blocksize * 2);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, split, c9, 0);
        offset += aeadBlockCipher.processBytes(m7, split, m7.length - split, c9, offset);
        aeadBlockCipher.doFinal(c9, offset);
        if (!areEqual(c7, c8) || !areEqual(c7, c9))
        {
            fail("Splitting input of plaintext should output the same ciphertext");
        }

        System.out.println(aeadBlockCipher.getAlgorithmName() + " test Exceptions pass");
    }

    private void testParameters(AsconEngine ascon, int keySize, int ivSize, int macSize)
    {
        if (ascon.getKeyBytesSize() != keySize)
        {
            fail("key bytes of " + ascon.getAlgorithmName() + " is not correct");
        }
        if (ascon.getIVBytesSize() != ivSize)
        {
            fail("iv bytes of " + ascon.getAlgorithmName() + " is not correct");
        }
        if (ascon.getOutputSize(0) != macSize)
        {
            fail("mac bytes of " + ascon.getAlgorithmName() + " is not correct");
        }
        System.out.println(ascon.getAlgorithmName() + " test Parameters pass");
    }

    private void testVectorsHash(AsconDigest.AsconParameters AsconParameters, String filename)
        throws Exception
    {
        AsconDigest Ascon = new AsconDigest(AsconParameters);
        InputStream src = TestResourceFinder.findTestResource("crypto/ascon", filename + "_LWC_HASH_KAT_256.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] ptByte;
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
                Ascon.reset();
                ptByte = Hex.decode((String)map.get("Msg"));
                Ascon.update(ptByte, 0, ptByte.length);
                byte[] hash = new byte[Ascon.getDigestSize()];
                Ascon.doFinal(hash, 0);
                if (!areEqual(hash, Hex.decode((String)map.get("MD"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                map.clear();
                Ascon.reset();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("Ascon Hash pass");
    }

    private void testVectorsHash(AsconXof.AsconParameters AsconParameters, String filename)
        throws Exception
    {
        AsconXof Ascon = new AsconXof(AsconParameters);
        InputStream src = TestResourceFinder.findTestResource("crypto/ascon", filename + "_LWC_HASH_KAT_256.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] ptByte;
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
                Ascon.reset();
                ptByte = Hex.decode((String)map.get("Msg"));
                Ascon.update(ptByte, 0, ptByte.length);
                byte[] hash = new byte[Ascon.getDigestSize()];
                Ascon.doFinal(hash, 0);
                if (!areEqual(hash, Hex.decode((String)map.get("MD"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                map.clear();
                Ascon.reset();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("Ascon Hash pass");
    }

    private void implTestExceptions(Digest digest, int digestsize)
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

    private void implTestExceptions(Xof xof, int digestsize)
    {
        if (xof.getDigestSize() != digestsize)
        {
            fail(xof.getAlgorithmName() + ": digest size is not correct");
        }

        try
        {
            xof.update(new byte[1], 1, 1);
            fail(xof.getAlgorithmName() + ": input for update is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            xof.doFinal(new byte[xof.getDigestSize() - 1], 2);
            fail(xof.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        System.out.println(xof.getAlgorithmName() + " test Exceptions pass");
    }

    private static void initEngine(AsconEngine ascon, boolean forEncryption)
    {
        int keySize = ascon.getKeyBytesSize();
        int ivSize = ascon.getIVBytesSize();
        int macSize = ivSize * 8;

        AEADParameters parameters = new AEADParameters(new KeyParameter(new byte[keySize]), macSize, new byte[ivSize], null);
        ascon.init(forEncryption, parameters);
    }

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new AsconTest());
    }
}
