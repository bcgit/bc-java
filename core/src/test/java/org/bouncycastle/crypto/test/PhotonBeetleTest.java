package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.PhotonBeetleDigest;
import org.bouncycastle.crypto.engines.PhotonBeetleEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class PhotonBeetleTest
    extends SimpleTest
{
    public String getName()
    {
        return "PhotonBeetle";
    }

    public void performTest()
        throws Exception
    {
        testVectorsHash();
        testVectors(PhotonBeetleEngine.PhotonBeetleParameters.pb32, "v32");
        testVectors(PhotonBeetleEngine.PhotonBeetleParameters.pb128, "v128");
    }

    private void testVectorsHash()
        throws Exception
    {
        PhotonBeetleDigest PhotonBeetle = new PhotonBeetleDigest();
        CipherParameters params;
        InputStream src = PhotonBeetleTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/photonbeetle/LWC_HASH_KAT_256.txt");
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
                PhotonBeetle.reset();
                ptByte = Hex.decode((String)map.get("Msg"));
                PhotonBeetle.update(ptByte, 0, ptByte.length);
                byte[] hash = new byte[32];
                PhotonBeetle.doFinal(hash, 0);
                if (!areEqual(hash, Hex.decode((String)map.get("MD"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                map.clear();
                PhotonBeetle.reset();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("PhotonBeetle Hash pass");
    }

    private void testVectors(PhotonBeetleEngine.PhotonBeetleParameters pbp, String filename)
        throws Exception
    {
        PhotonBeetleEngine PhotonBeetle = new PhotonBeetleEngine(pbp);
        CipherParameters params;
        InputStream src = PhotonBeetleTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/photonbeetle/"
            + filename + "_LWC_AEAD_KAT_128_128.txt");
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
//                if (!map.get("Count").equals("166"))
//                {
//                    continue;
//                }
                params = new ParametersWithIV(new KeyParameter(Hex.decode((String)map.get("Key"))), Hex.decode((String)map.get("Nonce")));
                PhotonBeetle.init(true, params);
                adByte = Hex.decode((String)map.get("AD"));
                PhotonBeetle.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode((String)map.get("PT"));
                rv = new byte[ptByte.length];
                PhotonBeetle.processBytes(ptByte, 0, ptByte.length, rv, 0);
                byte[] mac = new byte[16 + ptByte.length];
                PhotonBeetle.doFinal(mac, 0);
                if (!areEqual(mac, Hex.decode((String)map.get("CT"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), mac);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                map.clear();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("PhotonBeetle AEAD pass");
    }


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new PhotonBeetleTest());
    }
}

