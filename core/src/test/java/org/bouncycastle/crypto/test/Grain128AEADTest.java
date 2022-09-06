package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Grain128Engine;
import org.bouncycastle.crypto.modes.Grain128AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Grain128AEADTest extends SimpleTest {


    public String getName() {
        return "Grain-128AEAD";
    }

    public void performTest() throws Exception {
        Grain128AEADTest1();
    }

    private void Grain128AEADTest1() throws IOException {
        Grain128AEADCipher grain = new Grain128AEADCipher();
        CipherParameters params;
        InputStream src = Grain128AEADTest.class.getResourceAsStream("/org/bouncycastle/crypto/test/LWC_AEAD_KAT_128_96.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line, key = null, nonce = null, pt = null, ad = null, ct = null, count = null;
        String[] data;
        byte[] ptByte, adByte;
        byte[] rv;
        while ((line = bin.readLine()) != null) {
            data = line.split(" ");
            if (data.length == 1) {
                params = new ParametersWithIV(new KeyParameter(Hex.decode(key)), Hex.decode(nonce));
                grain.init(true, params);
                adByte = Hex.decode(ad);
                if(count.equals("67")){
                    System.out.println("break");
                }
                grain.processAADBytes(adByte, 0, adByte.length);
                ptByte = Hex.decode(pt);
                rv = new byte[ptByte.length + 8];
                grain.processBytes(ptByte, 0, ptByte.length, rv, 0);
                if (!areEqual(rv, Hex.decode(ct))) {
                    mismatch("Keystream " + count, ct, rv);
                }
            } else {
                switch (data[0]) {
                    case "Count":
                        count = getDataString(data);
                        break;
                    case "Key":
                        key = getDataString(data);
                        break;
                    case "Nonce":
                        nonce = getDataString(data);
                        break;
                    case "PT":
                        pt = getDataString(data);
                        break;
                    case "AD":
                        ad = getDataString(data);
                        break;
                    case "CT":
                        ct = getDataString(data);
                        break;
                }
            }

        }

    }

    private String getDataString(String[] data) {
        if (data.length >= 3) {
            return data[2].trim();
        }
        return "";
    }

    private void mismatch(String name, String expected, byte[] found) {
        fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    public static void main(String[] args) {
        runTest(new Grain128AEADTest());
    }
}

