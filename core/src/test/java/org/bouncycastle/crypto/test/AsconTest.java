package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Random;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.AsconEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;

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
        AsconEngine Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon80pq);
        testExceptions(Ascon, Ascon.getKeyBytesSize(), Ascon.getIVBytesSize());
        testParameters(Ascon, 20, 16, 16);
        Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon128a);
        testExceptions(Ascon, Ascon.getKeyBytesSize(), Ascon.getIVBytesSize());
        testParameters(Ascon, 16, 16, 16);
        Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon128);
        testExceptions(Ascon, Ascon.getKeyBytesSize(), Ascon.getIVBytesSize());
        testParameters(Ascon, 16, 16, 16);
        testVectors(AsconEngine.AsconParameters.ascon80pq, "160_128");
        testVectors(AsconEngine.AsconParameters.ascon128a, "128_128_a");
        testVectors(AsconEngine.AsconParameters.ascon128, "128_128");
    }


    private void testVectors(AsconEngine.AsconParameters asconParameters, String filename)
        throws Exception
    {
        AsconEngine Ascon = new AsconEngine(asconParameters);
        CipherParameters params;
        InputStream src = AsconTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/ascon/LWC_AEAD_KAT_" + filename + ".txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        byte[] rv;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
//                if (!map.get("Count").equals("793"))
//                {
//                    continue;
//                }
                byte[] key = Hex.decode(map.get("Key"));
                byte[] nonce = Hex.decode(map.get("Nonce"));
                byte[] ad = Hex.decode(map.get("AD"));
                byte[] pt = Hex.decode(map.get("PT"));
                byte[] ct = Hex.decode(map.get("CT"));
                params = new ParametersWithIV(new KeyParameter(key), nonce);
                Ascon.init(true, params);
                Ascon.processAADBytes(ad, 0, ad.length);
                rv = new byte[Ascon.getOutputSize(pt.length)];
                int len = Ascon.processBytes(pt, 0, pt.length, rv, 0);
                Ascon.doFinal(rv, len);
                if (!areEqual(rv, ct))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                Ascon.reset();
                Ascon.init(false, params);
                //Decrypt
                Ascon.processAADBytes(ad, 0, ad.length);
                rv = new byte[pt.length + 16];
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

    private void testExceptions(AEADBlockCipher aeadBlockCipher, int keysize, int ivsize)
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
            fail("mac should not be empty after dofinal");
        }
        if (!areEqual(mac2, c1))
        {
            fail("mac should be equal when calling dofinal and getMac");
        }
        aeadBlockCipher.processAADByte((byte)0);
        byte[] mac1 = new byte[aeadBlockCipher.getOutputSize(0)];
        aeadBlockCipher.doFinal(mac1, 0);
        if (areEqual(mac1, mac2))
        {
            fail("mac should not match");
        }
        aeadBlockCipher.reset();
        aeadBlockCipher.processBytes(new byte[16], 0, 16, new byte[16], 0);
        try
        {
            aeadBlockCipher.processAADByte((byte)0);
            fail("processAADByte(s) cannot be called after encryption/decryption");
        }
        catch (IllegalArgumentException e)
        {
            //expected
        }
        try
        {
            aeadBlockCipher.processAADBytes(new byte[]{0}, 0, 1);
            fail("processAADByte(s) cannot be called once only");
        }
        catch (IllegalArgumentException e)
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
        aeadBlockCipher.reset();
        aeadBlockCipher.processAADBytes(new byte[]{0, 0}, 0, 2);
        aeadBlockCipher.doFinal(mac1, 0);
        aeadBlockCipher.reset();
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
            fail("mac should match for the same AAD and message with different offset for both input and output");
        }
        aeadBlockCipher.reset();
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        aeadBlockCipher.doFinal(m4, offset);
        if (!areEqual(m2, m4))
        {
            fail("The encryption and decryption does not recover the plaintext");
        }
        System.out.println(aeadBlockCipher.getAlgorithmName() + " test Exceptions pass");
        c2[c2.length - 1] ^= 1;
        aeadBlockCipher.reset();
        aeadBlockCipher.init(false, params);
        aeadBlockCipher.processAADBytes(aad2, 0, aad2.length);
        offset = aeadBlockCipher.processBytes(c2, 0, c2.length, m4, 0);
        try
        {
            aeadBlockCipher.doFinal(m4, offset);
            fail("The decryption should fail");
        }
        catch (IllegalArgumentException e)
        {
            //expected;
        }
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


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new AsconTest());
    }
}
