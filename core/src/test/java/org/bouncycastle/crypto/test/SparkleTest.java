package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SparkleEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SparkleTest
    extends SimpleTest
{
    public String getName()
    {
        return "Sparkle";
    }

    public void performTest()
        throws Exception
    {
        testVectors(SparkleEngine.SparkleParameters.SCHWAEMM128_128, "128_128");
        testVectors(SparkleEngine.SparkleParameters.SCHWAEMM192_192, "192_192");
        testVectors(SparkleEngine.SparkleParameters.SCHWAEMM256_128, "128_256");
        testVectors(SparkleEngine.SparkleParameters.SCHWAEMM256_256, "256_256");
    }


    private void testVectors(SparkleEngine.SparkleParameters pbp, String filename)
        throws Exception
    {
        SparkleEngine Sparkle = new SparkleEngine(pbp);
        CipherParameters params;
        InputStream src = SparkleTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/sparkle/LWC_AEAD_KAT_"
            + filename + ".txt");
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
                Sparkle.init(true, params);
                adByte = Hex.decode((String)map.get("AD"));
                Sparkle.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode((String)map.get("PT"));
                rv = new byte[Sparkle.getOutputSize(ptByte.length)];
                Sparkle.processBytes(ptByte, 0, ptByte.length, rv, 0);
                Sparkle.doFinal(rv, ptByte.length);
                if (!areEqual(rv, Hex.decode((String)map.get("CT"))))
                {
                    mismatch("Keystream " + map.get("Count"), (String)map.get("CT"), rv);
                }
//                else
//                {
//                    System.out.println("Keystream " + map.get("Count") + " pass");
//                }
                map.clear();
                Sparkle.reset();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
        System.out.println("Sparkle AEAD pass");
    }


    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new SparkleTest());
    }
}


