package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.Grain128AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

public class Grain128AEADTest
    extends SimpleTest
{


    public String getName()
    {
        return "Grain-128AEAD";
    }

    public void performTest()
        throws Exception
    {
        Grain128AEADTest1();
    }

    private void Grain128AEADTest1()
        throws IOException
    {
        Grain128AEADCipher grain = new Grain128AEADCipher();
        CipherParameters params;
        InputStream src = Grain128AEADTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/LWC_AEAD_KAT_128_96.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line, key = null, nonce = null, pt = null, ad = null, ct = null, count = null;
        String[] data;
        byte[] ptByte, adByte;
        byte[] rv;
        HashMap<String, String> map = new HashMap<>();
        while ((line = bin.readLine()) != null)
        {
            data = line.split(" ");
            if (data.length == 1)
            {
                params = new ParametersWithIV(new KeyParameter(Hex.decode(map.get("Key"))), Hex.decode(map.get("Nonce")));
                grain.init(true, params);
                adByte = Hex.decode(map.get("AD"));
                grain.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode(map.get("PT"));
                rv = new byte[ptByte.length + 8];
                grain.processBytes(ptByte, 0, ptByte.length, rv, 0);
                if (!areEqual(rv, Hex.decode(map.get("CT"))))
                {
                    mismatch("Keystream " + count, ct, rv);
                }
                map.clear();
            }
            else
            {
                if (data.length >= 3)
                {
                    map.put(data[0].trim(), data[2].trim());
                }
                else
                {
                    map.put(data[0].trim(), "");
                }
            }
        }
    }

    private void mismatch(String name, String expected, byte[] found)
    {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args)
    {
        runTest(new Grain128AEADTest());
    }
}

