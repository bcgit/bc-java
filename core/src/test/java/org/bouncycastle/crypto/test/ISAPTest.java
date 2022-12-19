package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.ISAPDigest;
import org.bouncycastle.crypto.engines.ISAPEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
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
        InputStream src = ISAPTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/isap/" + filename + "_LWC_AEAD_KAT_128_128.txt");
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
//                if (!map.get("Count").equals("265"))
//                {
//                    continue;
//                }
                params = new ParametersWithIV(new KeyParameter(Hex.decode((String)map.get("Key"))), Hex.decode((String)map.get("Nonce")));
                isap.init(true, params);
                adByte = Hex.decode((String)map.get("AD"));
                isap.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode((String)map.get("PT"));
                rv = new byte[ptByte.length];
                isap.processBytes(ptByte, 0, ptByte.length, rv, 0);
                byte[] mac = new byte[16];
                isap.doFinal(mac, 0);
                if (!areEqual(Arrays.concatenate(rv, mac), Hex.decode((String)map.get("CT"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), Arrays.concatenate(rv, mac));
                }
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
        InputStream src = ISAPTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/isap/LWC_HASH_KAT_256.txt");
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

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new ISAPTest());
    }
}
