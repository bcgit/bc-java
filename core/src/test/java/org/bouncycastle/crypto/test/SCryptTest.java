package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/*
 * scrypt test vectors from "Stronger Key Derivation Via Sequential Memory-hard Functions" Appendix B.
 * (https://www.tarsnap.com/scrypt/scrypt.pdf)
 */
public class SCryptTest
    extends SimpleTest
{
    public String getName()
    {
        return "SCrypt";
    }

    public void performTest()
        throws Exception
    {
        testPermutations();
        testParameters();
        testVectors();
    }

    public void testParameters()
    {
        checkOK("Minimal values", new byte[0], new byte[0], 2, 1, 1, 1);
        checkIllegal("Cost parameter must be > 1", new byte[0], new byte[0], 1, 1, 1, 1);
        checkOK("Cost parameter 32768 OK for r == 1", new byte[0], new byte[0], 32768, 1, 1, 1);
        checkIllegal("Cost parameter must < 65536 for r == 1", new byte[0], new byte[0], 65536, 1, 1, 1);
        checkIllegal("Block size must be >= 1", new byte[0], new byte[0], 2, 0, 2, 1);
        checkIllegal("Parallelisation parameter must be >= 1", new byte[0], new byte[0], 2, 1, 0, 1);
        // checkOK("Parallelisation parameter 65535 OK for r = 4", new byte[0], new byte[0], 2, 32,
        // 65535, 1);
        checkIllegal("Parallelisation parameter must be < 65535 for r = 4", new byte[0], new byte[0], 2, 32, 65536, 1);

        checkIllegal("Len parameter must be > 1", new byte[0], new byte[0], 2, 1, 1, 0);
    }


    public void testPermutations()
        throws Exception
    {

        byte[] rootPassword = Strings.toByteArray("aabcdd");
        byte[] buf = null;

        byte[][] salts = new byte[3][];

        salts[0] = new byte[16];
        salts[1] = new byte[16];
        salts[2] = new byte[16];
        for (int t = 0; t < 16; t++)
        {
            salts[1][t] = (byte)t;
            salts[2][t] = (byte)(16 - t);
        }

        //
        // Permutation, starting with a shorter array, same length then one longer.
        //
        for (int j = rootPassword.length - 1; j < rootPassword.length + 2; j++)
        {
            buf = new byte[j];

            for (int a = 0; a < rootPassword.length; a++)
            {
                for (int b = 0; b < buf.length; b++)
                {
                    buf[b] = rootPassword[(a + b) % rootPassword.length];
                }


                ArrayList<byte[]> permutations = new ArrayList<byte[]>();
                permute(permutations, buf, 0, buf.length - 1);

                for (int i = 0; i != permutations.size(); i++)
                {
                    byte[] candidate = (byte[])permutations.get(i);
                    for (int k = 0; k != salts.length; k++)
                    {
                        byte[] salt = salts[k];
                        byte[] expected = SCrypt.generate(rootPassword,salt,   2,1,1,32);
                        byte[] testValue = SCrypt.generate(candidate,salt,   2,1,1,32);

                        //
                        // If the passwords are the same for the same salt we should have the same string.
                        //
                        boolean sameAsRoot = Arrays.areEqual(rootPassword, candidate);
                        isTrue("expected same result", sameAsRoot == Arrays.areEqual(expected, testValue));

                    }

                }
            }
        }
    }

    private void swap(byte[] buf, int i, int j)
    {
        byte b = buf[i];
        buf[i] = buf[j];
        buf[j] = b;
    }

    private void permute(ArrayList<byte[]> permutation, byte[] a, int l, int r)
    {
        if (l == r)
        {
            permutation.add(Arrays.clone(a));
        }
        else
        {

            for (int i = l; i <= r; i++)
            {
                // Swapping done
                swap(a, l, i);

                // Recursion called
                permute(permutation, a, l + 1, r);

                //backtrack
                swap(a, l, i);
            }
        }
    }


    private void checkOK(String msg, byte[] pass, byte[] salt, int N, int r, int p, int len)
    {
        try
        {
            SCrypt.generate(pass, salt, N, r, p, len);
        }
        catch (IllegalArgumentException e)
        {
            e.printStackTrace();
            fail(msg);
        }
    }

    private void checkIllegal(String msg, byte[] pass, byte[] salt, int N, int r, int p, int len)
    {
        try
        {
            SCrypt.generate(pass, salt, N, r, p, len);
            fail(msg);
        }
        catch (IllegalArgumentException e)
        {
            // e.printStackTrace();
        }
    }

    public void testVectors()
        throws Exception
    {
        BufferedReader br = new BufferedReader(new InputStreamReader(
            getClass().getResourceAsStream("SCryptTestVectors.txt")));

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

    public static void main(String[] args)
    {
        runTest(new SCryptTest());
    }
}
