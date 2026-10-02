package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Reads the SM9 test vectors under crypto/sm9 in bc-test-data: one name = value pair per line,
 * blank lines and lines starting with # ignored. Shared by the SM9 tests in this package, with
 * g2 assembling the G2 points the vectors print; the provider's SM9 tests carry the same reader
 * in their package, since neither test tree sees the other.
 */
class SM9Vectors
{
    private SM9Vectors()
    {
    }

    static Map load(String fileName)
        throws IOException
    {
        Map vectors = new HashMap();
        BufferedReader br = new BufferedReader(
            new InputStreamReader(TestResourceFinder.findTestResource("crypto/sm9", fileName)));
        try
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq > 0)
                {
                    vectors.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
        }
        finally
        {
            br.close();
        }
        return vectors;
    }

    static byte[] hex(Map vectors, String key)
    {
        return Hex.decode((String)vectors.get(key));
    }

    // a G2 point as the vectors print it: 0x04 || x_hi || x_lo || y_hi || y_lo
    static byte[] g2(Map v, String xHi, String xLo, String yHi, String yLo)
    {
        return Arrays.concatenate(
            Arrays.concatenate(new byte[]{0x04}, hex(v, xHi), hex(v, xLo)),
            Arrays.concatenate(hex(v, yHi), hex(v, yLo)));
    }
}
