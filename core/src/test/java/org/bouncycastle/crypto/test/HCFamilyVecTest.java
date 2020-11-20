package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HC-128 and HC-256 Tests. Based on the test vectors in the official reference
 * papers, respectively:
 * 
 * https://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
 * https://www.ecrypt.eu.org/stream/p3ciphers/hc/hc256_p3.pdf
 */
public class HCFamilyVecTest
    extends SimpleTest
{
    private static class PeekableLineReader extends BufferedReader
    {
        public PeekableLineReader(Reader r) throws IOException
        {
            super(r);

            peek = super.readLine();
        }

        public String peekLine()
        {
            return peek;
        }

        public String readLine() throws IOException
        {
            String tmp = peek;
            peek = super.readLine();
            return tmp;
        }

        private String peek; 
    }

    public String getName()
    {
        return "HC-128 and HC-256 (ecrypt)";
    }

    public void performTest() throws Exception
    {
        runTests(new HC128Engine(), "ecrypt_HC-128.txt");
        runTests(new HC256Engine(), "ecrypt_HC-256_128K_128IV.txt");
        runTests(new HC256Engine(), "ecrypt_HC-256_256K_128IV.txt");
        runTests(new HC256Engine(), "ecrypt_HC-256_128K_256IV.txt");
        runTests(new HC256Engine(), "ecrypt_HC-256_256K_256IV.txt");
    }

    private void runTests(StreamCipher hc, String fileName) throws IOException
    {
        Reader resource = new InputStreamReader(getClass().getResourceAsStream(fileName));
        PeekableLineReader r = new PeekableLineReader(resource);
        runAllVectors(hc, fileName, r);
    }

    private void runAllVectors(StreamCipher hc, String fileName, PeekableLineReader r)
        throws IOException
    {
        for (;;)
        {
            String line = r.readLine();
            if (line == null)
            {
                break;
            }

            line = line.trim();

            if (line.startsWith("Set "))
            {
                runVector(hc, fileName, r, dellChar(line, ':'));
            }
        }
    }

    private String dellChar(String s, char c)
    {
        StringBuffer b = new StringBuffer();

        for (int i = 0; i != s.length(); i++)
        {
            if (s.charAt(i) != c)
            {
                b.append(s.charAt(i));
            }
        }

        return b.toString();
    }

    private void runVector(StreamCipher hc, String fileName, PeekableLineReader r, String vectorName)
        throws IOException
    {
//        System.out.println(fileName + " => " + vectorName);
        String hexKey = readBlock(r);
        String hexIV = readBlock(r);

        CipherParameters cp = new KeyParameter(Hex.decode(hexKey));
        cp = new ParametersWithIV(cp, Hex.decode(hexIV));
        hc.init(true, cp);

        byte[] input = new byte[64];
        byte[] output = new byte[64];
        byte[] digest = new byte[64];
        int pos = 0;

        for (;;)
        {
            String line1 = r.peekLine().trim();
            int equalsPos = line1.indexOf('=');
            String lead = line1.substring(0, equalsPos - 1);

            String hexData = readBlock(r);
            byte[] data = Hex.decode(hexData);

            if (lead.equals("xor-digest"))
            {
                if (!Arrays.areEqual(data, digest))
                {
                    fail("Failed in " + fileName + " for test vector: " + vectorName + " at " + lead);
//                  System.out.println(fileName + " => " + vectorName + " failed at " + lead); return;
                }
                break;
            }

            int posA = lead.indexOf('[');
            int posB = lead.indexOf("..");
            int posC = lead.indexOf(']');
            int start = Integer.parseInt(lead.substring(posA + 1, posB));
            int end = Integer.parseInt(lead.substring(posB + 2, posC));

            if (start % 64 != 0 || (end - start != 63))
            {
                throw new IllegalStateException(vectorName + ": " + lead + " not on 64 byte boundaries");
            }

            while (pos < end)
            {
                hc.processBytes(input, 0, input.length, output, 0);
                xor(digest, output);
                pos += 64;
            }

            if (!Arrays.areEqual(data, output))
            {
                fail("Failed in " + fileName + " for test vector: " + vectorName + " at " + lead);
//              System.out.println(fileName + " => " + vectorName + " failed at " + lead); return;
            }
        }
    }

    private static String readBlock(PeekableLineReader r) throws IOException
    {
        String first = r.readLine().trim();
        String result = first.substring(first.lastIndexOf(' ') + 1);

        for (;;)
        {
            String peek = r.peekLine().trim();
            if (peek.length() < 1 || peek.indexOf('=') >= 0)
            {
                break;
            }
            result += r.readLine().trim();
        }

        return result;
    }

    private static void xor(byte[] digest, byte[] block)
    {
        for (int i = 0; i < digest.length; ++i)
        {
            digest[i] ^= block[i];
        }
    }

    public static void main(String[] args)
    {
        runTest(new HCFamilyVecTest());
    }
}
