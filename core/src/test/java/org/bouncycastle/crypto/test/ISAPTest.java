package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Random;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.digests.ISAPDigest;
import org.bouncycastle.crypto.engines.ISAPEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import static org.bouncycastle.crypto.engines.ISAPEngine.IsapType;

public class ISAPTest
    extends SimpleTest
{
    public String getName()
    {
        return "ISAP";
    }

    public void performTest()
        throws Exception
    {
        ISAPEngine ISAP = new ISAPEngine(IsapType.ISAP_K_128A);
        testExceptions(ISAP, ISAP.getKeyBytesSize(), ISAP.getIVBytesSize(), ISAP.getBlockSize());
        testParameters(ISAP, 16, 16, 16);
        ISAP = new ISAPEngine(IsapType.ISAP_K_128);
        testExceptions(ISAP, ISAP.getKeyBytesSize(), ISAP.getIVBytesSize(), ISAP.getBlockSize());
        testParameters(ISAP, 16, 16, 16);
        ISAP = new ISAPEngine(IsapType.ISAP_A_128A);
        testExceptions(ISAP, ISAP.getKeyBytesSize(), ISAP.getIVBytesSize(), ISAP.getBlockSize());
        testParameters(ISAP, 16, 16, 16);
        ISAP = new ISAPEngine(IsapType.ISAP_A_128);
        testExceptions(ISAP, ISAP.getKeyBytesSize(), ISAP.getIVBytesSize(), ISAP.getBlockSize());
        testParameters(ISAP, 16, 16, 16);
        testExceptions(new ISAPDigest(), 32);
        testVectors("isapa128av20", IsapType.ISAP_A_128A);
        testVectors("isapa128v20", IsapType.ISAP_A_128);
        testVectors("isapk128av20", IsapType.ISAP_K_128A);
        testVectors("isapk128v20", IsapType.ISAP_K_128);
        testVectors();
    }

    private void testVectors(String filename, IsapType isapType)
        throws Exception
    {
        ISAPEngine isap = new ISAPEngine(isapType);
        CipherParameters params;
        InputStream src = TestResourceFinder.findTestResource("crypto/isap", filename + "_LWC_AEAD_KAT_128_128.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] rv;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
//                if (!map.get("Count").equals("265"))
//                {
//                    continue;
//                }
                byte[] key = Hex.decode(map.get("Key"));
                byte[] nonce = Hex.decode(map.get("Nonce"));
                byte[] ad = Hex.decode(map.get("AD"));
                byte[] pt = Hex.decode(map.get("PT"));
                byte[] ct = Hex.decode(map.get("CT"));
                params = new ParametersWithIV(new KeyParameter(key), nonce);
                isap.init(true, params);
                isap.processAADBytes(ad, 0, ad.length);
                rv = new byte[isap.getOutputSize(pt.length)];
                int len = isap.processBytes(pt, 0, pt.length, rv, 0);
                isap.doFinal(rv, len);
                if (!areEqual(rv, ct))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                isap.reset();
                isap.init(false, params);
                //Decrypt
                isap.processAADBytes(ad, 0, ad.length);
                rv = new byte[pt.length + 16];
                len = isap.processBytes(ct, 0, ct.length, rv, 0);
                isap.doFinal(rv, len);
                byte[] pt_recovered = new byte[pt.length];
                System.arraycopy(rv, 0, pt_recovered, 0, pt.length);
                if (!areEqual(pt, pt_recovered))
                {
                    mismatch("Reccover Keystream " + map.get("Count"), (String)map.get("PT"), pt_recovered);
                }
                isap.reset();
                map.clear();

            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println(filename + " pass");
    }

    private void testVectors()
        throws Exception
    {
        ISAPDigest isap = new ISAPDigest();
        InputStream src = TestResourceFinder.findTestResource("crypto/isap", "LWC_HASH_KAT_256.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] ptByte;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
//                if (!map.get("Count").equals("10"))
//                {
//                    continue;
//                }
                ptByte = Hex.decode((String)map.get("Msg"));
                isap.update(ptByte, 0, ptByte.length);
                byte[] hash = new byte[32];
                isap.doFinal(hash, 0);
                if (!areEqual(hash, Hex.decode((String)map.get("MD"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }
//                else
//                {
//                    System.out.println(map.get("Count") + " pass");
//                }
                map.clear();
                isap.reset();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("ISAP Hash pass");
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
        catch (IllegalArgumentException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.processByte((byte)0, c1, 0);
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before processByte");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.reset();
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before reset");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }

        try
        {
            aeadBlockCipher.doFinal(c1, m.length);
            fail(aeadBlockCipher.getAlgorithmName() + " need to be initialed before dofinal");
        }
        catch (IllegalArgumentException e)
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
        catch (IllegalArgumentException e)
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
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should not be empty after dofinal");
        }
        if (!areEqual(mac2, c1))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should be equal when calling dofinal and getMac");
        }
        aeadBlockCipher.processAADByte((byte)0);
        byte[] mac1 = new byte[aeadBlockCipher.getOutputSize(0)];
        aeadBlockCipher.doFinal(mac1, 0);
        if (areEqual(mac1, mac2))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should not match");
        }
        aeadBlockCipher.reset();
        aeadBlockCipher.processBytes(new byte[16], 0, 16, new byte[16], 0);
//        try
//        {
//            aeadBlockCipher.processAADByte((byte)0);
//            fail(aeadBlockCipher.getAlgorithmName()+ ": processAADByte(s) cannot be called after encryption/decryption");
//        }
//        catch (IllegalArgumentException e)
//        {
//            //expected
//        }
//        try
//        {
//            aeadBlockCipher.processAADBytes(new byte[]{0}, 0, 1);
//            fail(aeadBlockCipher.getAlgorithmName()+ ": processAADByte(s) cannot be called once only");
//        }
//        catch (IllegalArgumentException e)
//        {
//            //expected
//        }

        aeadBlockCipher.reset();
        try
        {
            aeadBlockCipher.processAADBytes(new byte[]{0}, 1, 1);
            fail(aeadBlockCipher.getAlgorithmName() + ": input for processAADBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.processBytes(new byte[]{0}, 1, 1, c1, 0);
            fail(aeadBlockCipher.getAlgorithmName() + ": input for processBytes is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.processBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], blocksize >> 1);
            fail(aeadBlockCipher.getAlgorithmName() + ": output for processBytes is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.doFinal(new byte[2], 2);
            fail(aeadBlockCipher.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }

        mac1 = new byte[aeadBlockCipher.getOutputSize(0)];
        mac2 = new byte[aeadBlockCipher.getOutputSize(0)];
        aeadBlockCipher.reset();
        aeadBlockCipher.processAADBytes(new byte[]{0, 0}, 0, 2);
        aeadBlockCipher.doFinal(mac1, 0);
        aeadBlockCipher.reset();
        aeadBlockCipher.processAADByte((byte)0);
        aeadBlockCipher.processAADByte((byte)0);
        aeadBlockCipher.doFinal(mac2, 0);
        if (!areEqual(mac1, mac2))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should match for the same AAD with different ways of inputing");
        }

        byte[] c2 = new byte[aeadBlockCipher.getOutputSize(10)];
        byte[] c3 = new byte[aeadBlockCipher.getOutputSize(10) + 2];

        byte[] aad2 = {0, 1, 2, 3, 4};
        byte[] aad3 = {0, 0, 1, 2, 3, 4, 5};
        byte[] m2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] m3 = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        byte[] m4 = new byte[m2.length];
        aeadBlockCipher.reset();
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        int offset = aeadBlockCipher.processBytes(m2, 0, m2.length, c2, 0);
        aeadBlockCipher.doFinal(c2, offset);
        aeadBlockCipher.reset();
        aeadBlockCipher.processAADBytes(aad3, 1, aad2.length);
        offset = aeadBlockCipher.processBytes(m3, 1, m2.length, c3, 1);
        aeadBlockCipher.doFinal(c3, offset + 1);
        byte[] c3_partial = new byte[c2.length];
        System.arraycopy(c3, 1, c3_partial, 0, c2.length);
        if (!areEqual(c2, c3_partial))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": mac should match for the same AAD and message with different offset for both input and output");
        }
        aeadBlockCipher.reset();
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        aeadBlockCipher.doFinal(m4, offset);
        if (!areEqual(m2, m4))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": The encryption and decryption does not recover the plaintext");
        }

        c2[c2.length - 1] ^= 1;
        aeadBlockCipher.reset();
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        try
        {
            aeadBlockCipher.doFinal(m4, offset);
            fail(aeadBlockCipher.getAlgorithmName() + ": The decryption should fail");
        }
        catch (IllegalArgumentException e)
        {
            //expected;
        }

        byte[] m7 = new byte[blocksize * 2];
        for (int i = 0; i < m7.length; ++i)
        {
            m7[i] = (byte)rand.nextInt();
        }
        byte[] c7 = new byte[aeadBlockCipher.getOutputSize(m7.length)];
        byte[] c8 = new byte[c7.length];
        byte[] c9 = new byte[c7.length];
        aeadBlockCipher.init(true, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, m7.length, c7, 0);
        aeadBlockCipher.doFinal(c7, offset);
        aeadBlockCipher.reset();
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, blocksize, c8, 0);
        offset += aeadBlockCipher.processBytes(m7, blocksize, m7.length - blocksize, c8, offset);
        aeadBlockCipher.doFinal(c8, offset);
        aeadBlockCipher.reset();
        int split = rand.nextInt(blocksize * 2);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(m7, 0, split, c9, 0);
        offset += aeadBlockCipher.processBytes(m7, split, m7.length - split, c9, offset);
        aeadBlockCipher.doFinal(c9, offset);
        if (!areEqual(c7, c8) || !areEqual(c7, c9))
        {
            fail(aeadBlockCipher.getAlgorithmName() + ": Splitting input of plaintext should output the same ciphertext");
        }
        System.out.println(aeadBlockCipher.getAlgorithmName() + " test Exceptions pass");
    }

    private void testParameters(ISAPEngine isap, int keySize, int ivSize, int macSize)
    {
        if (isap.getKeyBytesSize() != keySize)
        {
            fail(isap.getAlgorithmName() + ": key bytes of " + isap.getAlgorithmName() + " is not correct");
        }
        if (isap.getIVBytesSize() != ivSize)
        {
            fail(isap.getAlgorithmName() + ": iv bytes of " + isap.getAlgorithmName() + " is not correct");
        }
        if (isap.getOutputSize(0) != macSize)
        {
            fail(isap.getAlgorithmName() + ": mac bytes of " + isap.getAlgorithmName() + " is not correct");
        }
        System.out.println(isap.getAlgorithmName() + " test Parameters pass");
    }


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new ISAPTest());
    }
}
