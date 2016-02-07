package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * SHAKE Digest Test
 */
public class SHAKEDigestTest
    extends SimpleTest
{
    static class MySHAKEDigest extends SHAKEDigest
    {
        MySHAKEDigest(int bitLength)
        {
            super(bitLength);
        }

        int myDoFinal(byte[] out, int outOff, int outLen, byte partialByte, int partialBits)
        {
            return doFinal(out, outOff, outLen, partialByte, partialBits);
        }
    }

    SHAKEDigestTest()
    {
    }

    public String getName()
    {
        return "SHAKE";
    }

    public void performTest() throws Exception
    {
        testVectors();
    }

    public void testVectors() throws Exception
    {
        BufferedReader r = new BufferedReader(new InputStreamReader(
            getClass().getResourceAsStream("SHAKETestVectors.txt")));

        String line;
        while (null != (line = readLine(r)))
        {
            if (line.length() != 0)
            {
                TestVector v = readTestVector(r, line);
                runTestVector(v);
            }
        }

        r.close();
    }

    private MySHAKEDigest createDigest(String algorithm) throws Exception
    {
        if (algorithm.startsWith("SHAKE-"))
        {
            int bits = parseDecimal(algorithm.substring("SHAKE-".length()));
            return new MySHAKEDigest(bits);
        }
        throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
    }

    private byte[] decodeBinary(String block)
    {
        int bits = block.length();
        int fullBytes = bits / 8;
        int totalBytes = (bits + 7) / 8;
        byte[] result = new byte[totalBytes];

        for (int i = 0; i < fullBytes; ++i)
        {
            String byteStr = reverse(block.substring(i * 8, (i + 1) * 8));
            result[i] = (byte)parseBinary(byteStr);
        }

        if (totalBytes > fullBytes)
        {
            String byteStr = reverse(block.substring(fullBytes * 8));
            result[fullBytes] = (byte)parseBinary(byteStr);
        }

        return result;
    }

    private int parseBinary(String s)
    {
        return Integer.parseInt(s, 2);
    }

    private int parseDecimal(String s)
    {
        return Integer.parseInt(s);
    }

    private String readBlock(BufferedReader r) throws IOException
    {
        StringBuffer b = new StringBuffer();
        String line;
        while ((line = readBlockLine(r)) != null)
        {
            b.append(line);
        }
        return b.toString();
    }

    private String readBlockLine(BufferedReader r) throws IOException
    {
        String line = readLine(r);
        if (line == null || line.length() == 0)
        {
            return null;
        }

        char[] chars = line.toCharArray();

        int pos = 0;
        for (int i = 0; i != chars.length; i++)
        {
            if (chars[i] != ' ')
            {
                chars[pos++] = chars[i];
            }
        }

        return new String(chars, 0, pos);
    }

    private TestVector readTestVector(BufferedReader r, String header) throws IOException
    {
        String[] parts = splitAround(header, TestVector.SAMPLE_OF);

        String algorithm = parts[0];
        int bits = parseDecimal(stripFromChar(parts[1], '-'));

        skipUntil(r, TestVector.MSG_HEADER);
        String messageBlock = readBlock(r);
        if (messageBlock.length() != bits)
        {
            throw new IllegalStateException("Test vector length mismatch");
        }
        byte[] message = decodeBinary(messageBlock);

        skipUntil(r, TestVector.OUTPUT_HEADER);
        byte[] output = Hex.decode(readBlock(r));

        return new TestVector(algorithm, bits, message, output);
    }

    private String readLine(BufferedReader r) throws IOException
    {
        String line = r.readLine();
        return line == null ? null : stripFromChar(line, '#').trim();
    }

    private String requireLine(BufferedReader r) throws IOException
    {
        String line = readLine(r);
        if (line == null)
        {
            throw new EOFException();
        }
        return line;
    }

    private String reverse(String s)
    {
        return new StringBuffer(s).reverse().toString();
    }

    private void runTestVector(TestVector v) throws Exception
    {
        int bits = v.getBits();
        int partialBits = bits % 8;

        byte[] expected = v.getOutput();

//        System.out.println(v.getAlgorithm() + " " + bits + "-bit");
//        System.out.println(Hex.toHexString(v.getMessage()).toUpperCase());
//        System.out.println(Hex.toHexString(expected).toUpperCase());

        int outLen = expected.length;

        MySHAKEDigest d = createDigest(v.getAlgorithm());
        byte[] output = new byte[outLen];

        byte[] m = v.getMessage();
        if (partialBits == 0)
        {
            d.update(m, 0, m.length);
            d.doFinal(output, 0, outLen);
        }
        else
        {
            d.update(m, 0, m.length - 1);
            d.myDoFinal(output, 0, outLen, m[m.length - 1], partialBits);
        }

        if (!Arrays.areEqual(expected, output))
        {
            fail(v.getAlgorithm() + " " + v.getBits() + "-bit test vector hash mismatch");
//            System.err.println(v.getAlgorithm() + " " + v.getBits() + "-bit test vector hash mismatch");
//            System.err.println(Hex.toHexString(output).toUpperCase());
        }

        if (partialBits == 0)
        {
            d = createDigest(v.getAlgorithm());

            m = v.getMessage();

            d.update(m, 0, m.length);
            d.doOutput(output, 0, outLen / 2);
            d.doOutput(output, outLen / 2, output.length - outLen / 2);

            if (!Arrays.areEqual(expected, output))
            {
                fail(v.getAlgorithm() + " " + v.getBits() + "-bit test vector extended hash mismatch");
            }

            try
            {
                d.update((byte)0x01);
                fail("no exception");
            }
            catch (IllegalStateException e)
            {
                isTrue("wrong exception", "attempt to absorb while squeezing".equals(e.getMessage()));
            }

            d = createDigest(v.getAlgorithm());

            m = v.getMessage();

            d.update(m, 0, m.length);
            d.doOutput(output, 0, outLen / 2);
            d.doFinal(output, outLen / 2, output.length - outLen / 2);

            if (!Arrays.areEqual(expected, output))
            {
                fail(v.getAlgorithm() + " " + v.getBits() + "-bit test vector extended doFinal hash mismatch");
            }

            d.update((byte)0x01); // this should be okay as we've reset on doFinal()
        }
    }

    private void skipUntil(BufferedReader r, String header) throws IOException
    {
        String line;
        do
        {
            line = requireLine(r);
        }
        while (line.length() == 0);
        if (!line.equals(header))
        {
            throw new IOException("Expected: " + header);
        }
    }

    private String[] splitAround(String s, String separator)
    {
        List strings = new ArrayList();

        String remaining = s;
        int index;

        while ((index = remaining.indexOf(separator)) > 0)
        {
            strings.add(remaining.substring(0, index));
            remaining = remaining.substring(index + separator.length());
        }
        strings.add(remaining);

        return (String[])strings.toArray(new String[strings.size()]);
    }

    private String stripFromChar(String s, char c)
    {
        int i = s.indexOf(c);
        if (i >= 0)
        {
            s = s.substring(0, i);
        }
        return s;
    }

    public static void main(
        String[]    args)
    {
        runTest(new SHAKEDigestTest());
    }

    private static class TestVector
    {
        private static String SAMPLE_OF = " sample of ";
        private static String MSG_HEADER = "Msg as bit string";
        private static String OUTPUT_HEADER = "Output val is";

        private String algorithm;
        private int bits;
        private byte[] message;
        private byte[] output;

        private TestVector(String algorithm, int bits, byte[] message, byte[] output)
        {
            this.algorithm = algorithm;
            this.bits = bits;
            this.message = message;
            this.output = output;
        }

        public String getAlgorithm()
        {
            return algorithm;
        }

        public int getBits()
        {
            return bits;
        }
        
        public byte[] getMessage()
        {
            return message;
        }

        public byte[] getOutput()
        {
            return output;
        }
    }
}
