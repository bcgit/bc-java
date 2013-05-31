package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.FileReader;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/*
 * scrypt test vectors from "Stronger Key Derivation Via Sequential Memory-hard Functions" Appendix B.
 * (http://www.tarsnap.com/scrypt/scrypt.pdf)
 */
public class SCryptTest extends SimpleTest
{
    private static final String TEST_DATA_HOME = "bc.test.data.home";

    public String getName()
    {
        return "SCrypt";
    }

    public void performTest() throws Exception
    {
        BufferedReader br = new BufferedReader(new FileReader(getDataHome() + "/TestVectors.txt"));

        int count = 0;
        String line = br.readLine();

        while (line != null)
        {
            ++count;
            String header = line;
            StringBuffer data = new StringBuffer();

            while (!isEndData(line = br.readLine()))
            {
                for (int i = 0; i != line.length(); i++)
                {
                    if (line.charAt(i) != ' ')
                    {
                        data.append(line.charAt(i));
                    }
                }
            }

            int start = header.indexOf('(') + 1;
            int limit = header.lastIndexOf(')');
            String argStr = header.substring(start, limit);
            String[] args = Strings.split(argStr, ',');

            byte[] P = extractQuotedString(args[0]);
            byte[] S = extractQuotedString(args[1]);
            int N = extractInteger(args[2]);
            int r = extractInteger(args[3]);
            int p = extractInteger(args[4]);
            int dkLen = extractInteger(args[5]);
            byte[] expected = Hex.decode(data.toString());

            // This skips very expensive test case(s), remove check to re-enable
            if (N <= 16384)
            {
                byte[] result = SCrypt.generate(P, S, N, r, p, dkLen);

                if (!areEqual(expected, result))
                {
                    fail("Result does not match expected value in test case " + count);
                }
            }
        }

        br.close();
    }

    private static boolean isEndData(String line)
    {
        return line == null || line.startsWith("scrypt");
    }

    private static byte[] extractQuotedString(String arg)
    {
        arg = arg.trim();
        arg = arg.substring(1, arg.length() - 1);
        return Strings.toByteArray(arg);
    }

    private static int extractInteger(String arg)
    {
        return Integer.parseInt(arg.trim());
    }

    private static String getDataHome()
    {
        String dataHome = System.getProperty(TEST_DATA_HOME);

        if (dataHome == null)
        {
            throw new IllegalStateException(TEST_DATA_HOME + " property not set");
        }

        return dataHome + "/scrypt";
    }

    public static void main(String[] args)
    {
        runTest(new SCryptTest());
    }
}
