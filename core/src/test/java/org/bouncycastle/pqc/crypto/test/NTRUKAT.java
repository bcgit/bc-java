package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

public class NTRUKAT
{
    public int count;
    public byte[] seed;
    /**
     * Public key
     */
    public byte[] pk;
    /**
     * Private key
     */
    public byte[] sk;
    /**
     * Ciphertext
     */
    public byte[] ct;
    /**
     * Shared key
     */
    public byte[] ss;

    private static final TestSampler sampler = new TestSampler();

    public static List<NTRUKAT> getKAT(InputStream src)
    {
        List<NTRUKAT> kats = new ArrayList<NTRUKAT>();
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        HashMap<String, String> buf = new HashMap<String, String>();
        try
        {
            for (String line = bin.readLine(); line != null; line = bin.readLine())
            {
                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        NTRUKAT kat = new NTRUKAT();
                        kat.count = Integer.parseInt((String)buf.get("count"));
                        kat.seed = Hex.decode((String)buf.get("seed")); // seed for secure random
                        kat.pk = Hex.decode((String)buf.get("pk"));     // public key
                        kat.sk = Hex.decode((String)buf.get("sk"));     // private key
                        kat.ct = Hex.decode((String)buf.get("ct"));
                        kat.ss = Hex.decode((String)buf.get("ss"));

                        if (sampler.skipTest(kat.count))
                        {
                            continue;
                        }

                        kats.add(kat);
                    }
                    buf.clear();
                    continue;
                }
                // append fields
                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        return kats;
    }
}
