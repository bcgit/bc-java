package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.ElephantEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ElephantTest
    extends SimpleTest
{
    public String getName()
    {
        return "Elephant";
    }

    public void performTest()
        throws Exception
    {
        testVectors(ElephantEngine.ElephantParameters.elephant160, "v160");
        testVectors(ElephantEngine.ElephantParameters.elephant176, "v176");
        testVectors(ElephantEngine.ElephantParameters.elephant200, "v200");
    }


    private void testVectors(ElephantEngine.ElephantParameters pbp, String filename)
        throws Exception
    {
        ElephantEngine Elephant = new ElephantEngine(pbp);
        CipherParameters params;
        InputStream src = ElephantTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/elephant/"
            + filename + "_LWC_AEAD_KAT_128_96.txt");
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
                Elephant.init(true, params);
                adByte = Hex.decode((String)map.get("AD"));
                Elephant.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode((String)map.get("PT"));
                rv = new byte[Elephant.getOutputSize(ptByte.length)];
                Elephant.processBytes(ptByte, 0, ptByte.length, rv, 0);
                Elephant.doFinal(rv, ptByte.length);

                if (!areEqual(rv, Hex.decode((String)map.get("CT"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                map.clear();
                Elephant.reset();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("Elephant AEAD pass");
    }


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new ElephantTest());
    }
}

