package org.bouncycastle.jce.provider.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.encoders.Hex;

/**
 * Reads the SM9 test vectors under crypto/sm9 in bc-test-data: one name = value pair per line,
 * blank lines and lines starting with # ignored. Shared by the SM9 tests in this package; the
 * lightweight SM9 tests carry the same class in org.bouncycastle.crypto.test, since neither test
 * tree sees the other.
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
}
