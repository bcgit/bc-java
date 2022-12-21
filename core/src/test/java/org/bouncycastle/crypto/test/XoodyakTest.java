package org.bouncycastle.crypto.test;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.XoodyakDigest;
import org.bouncycastle.crypto.engines.XoodyakEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;


public class XoodyakTest
    extends SimpleTest
{
    public String getName()
    {
        return "xoodyak";
    }

    public void performTest()
        throws Exception
    {
        testVectorsHash();
        testVectors();
    }
    private void testVectorsHash()
        throws Exception
    {
        XoodyakDigest xoodyak = new XoodyakDigest();
        CipherParameters params;
        InputStream src = XoodyakTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/xoodyak/LWC_HASH_KAT_256.txt");
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
//                if (!map.get("Count").equals("18"))
//                {
//                    continue;
//                }
                xoodyak.reset();
                ptByte = Hex.decode((String)map.get("Msg"));
                xoodyak.update(ptByte, 0, ptByte.length);
                byte[] hash = new byte[32];
                xoodyak.doFinal(hash, 0);
                if (!areEqual(hash, Hex.decode((String)map.get("MD"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("MD"), hash);
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
        System.out.println("Xoodyak Hash pass");
    }

    private void testVectors()
        throws Exception
    {
        XoodyakEngine xoodyak = new XoodyakEngine();
        CipherParameters params;
        InputStream src = XoodyakTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/xoodyak/LWC_AEAD_KAT_128_128.txt");
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
//                if (!map.get("Count").equals("628"))
//                {
//                    continue;
//                }
                params = new ParametersWithIV(new KeyParameter(Hex.decode((String)map.get("Key"))), Hex.decode((String)map.get("Nonce")));
                xoodyak.init(true, params);
                adByte = Hex.decode((String)map.get("AD"));
                xoodyak.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode((String)map.get("PT"));
                rv = new byte[ptByte.length];
                xoodyak.processBytes(ptByte, 0, ptByte.length, rv, 0);
                byte[] mac = new byte[16];
                xoodyak.doFinal(mac, 0);
                if (!areEqual(Arrays.concatenate(rv, mac), Hex.decode((String)map.get("CT"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), Arrays.concatenate(rv, mac));
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
        System.out.println("Xoodyak AEAD pass");
    }


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new XoodyakTest());
    }
}
