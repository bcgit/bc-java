package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AsconEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
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
        byte[] ptByte, adByte;
        byte[] rv;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
//                if (!map.get("Count").equals("34"))
//                {
//                    continue;
//                }
                params = new ParametersWithIV(new KeyParameter(Hex.decode((String)map.get("Key"))), Hex.decode((String)map.get("Nonce")));
                Ascon.init(true, params);
                adByte = Hex.decode((String)map.get("AD"));
                Ascon.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode((String)map.get("PT"));
                rv = new byte[Ascon.getOutputSize(ptByte.length)];
                Ascon.processBytes(ptByte, 0, ptByte.length, rv, 0);
                Ascon.doFinal(rv, ptByte.length);
                if (!areEqual(rv, Hex.decode((String)map.get("CT"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
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
        System.out.println("Ascon AEAD pass");
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
