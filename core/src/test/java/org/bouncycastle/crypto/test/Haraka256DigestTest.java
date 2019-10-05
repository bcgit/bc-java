package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.Haraka256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Haraka256DigestTest
    extends SimpleTest
{
    public String getName()
    {
        return "Haraka 256";
    }

    public void testKnownVector()
    {
        byte[] in = new byte[32];
        for (int t = 0; t < in.length; t++)
        {
            in[t] = (byte)t;
        }

        // From Appendix B, Haraka-256 v2, https://eprint.iacr.org/2016/098.pdf
        byte[] expected256 = Hex.decode("8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c");

        Haraka256Digest haraka = new Haraka256Digest();
        haraka.update(in, 0, in.length);
        byte[] out = new byte[haraka.getDigestSize()];
        haraka.doFinal(out, 0);
        isTrue("Did not match vector", this.areEqual(expected256, out));
    }


    public void testInputTooShort()
    {
        try
        {
            Haraka256Digest haraka = new Haraka256Digest();
            byte[] in = new byte[31];
            haraka.update(in, 0, in.length);
            haraka.doFinal(null, 0);
            fail("fail on input not 32 bytes.");
        }
        catch (IllegalStateException ilarex)
        {
            isTrue("message", contains(ilarex.getMessage(), "input must be exactly 32 bytes"));
        }
    }

    public void testInputTooLong()
    {
        try
        {
            Haraka256Digest haraka = new Haraka256Digest();
            byte[] in = new byte[33];
            haraka.update(in, 0, in.length);
            haraka.doFinal(null, 0);
            fail("fail on input not 32 bytes.");
        }
        catch (IllegalArgumentException ilarex)
        {
            isTrue("long message", contains(ilarex.getMessage(), "total input cannot be more than 32 bytes"));
        }
    }

    public void testOutput()
    {

        //
        // Buffer too short.
        //
        try
        {
            Haraka256Digest haraka = new Haraka256Digest();
            byte[] in = new byte[32];
            haraka.update(in, 0, in.length);
            byte[] out = new byte[31];
            haraka.doFinal(out, 0);
            fail("Output too short for digest result.");
        }
        catch (IllegalArgumentException ilarex)
        {
            isTrue("message 1", contains(ilarex.getMessage(), "output too short to receive digest"));
        }

        //
        // Offset puts end past length of buffer.
        //
        try
        {
            Haraka256Digest haraka = new Haraka256Digest();
            byte[] in = new byte[32];
            haraka.update(in, 0, in.length);
            byte[] out = new byte[48];
            haraka.doFinal(out, 17);
            fail("Output too short for digest result.");
        }
        catch (IllegalArgumentException ilarex)
        {
            isTrue("message 2", contains(ilarex.getMessage(), "output too short to receive digest"));
        }


        //
        // Offset output..
        //
        byte[] in = new byte[32];
        for (int t = 0; t < in.length; t++)
        {
            in[t] = (byte)t;
        }

        byte[] expected256 = Hex.decode("000000008027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c");

        Haraka256Digest haraka = new Haraka256Digest();
        haraka.update(in, 0, in.length);
        byte[] out = new byte[haraka.getDigestSize() + 4];
        haraka.doFinal(out, 4);
        isTrue(this.areEqual(expected256, out));
    }

    void testMonty()
    {
        int c = 0;
        String[][] vectors = new String[][]{
            {
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "e78599d7163ab58f1c90f0171c6fc4e852eb4b8cc29a4af63194fd9977c1de84"
            },
            {
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "c4cebda63c00c4cd312f36ea92afd4b0f6048507c5b367326ef9d8fdd2d5c09a"
            }
        };

        for (int i = 0; i != vectors.length; i++)
        {
            //
            // 1000 rounds of digest application, where alternative outputs are copied over alternate halves of the input.
            //
            String[] vector = vectors[i];

            byte[] expected = Hex.decode(vector[1]);

            // Load initial message.

            Haraka256Digest haraka = new Haraka256Digest();
            byte[] result = Hex.decode(vector[0]);
            for (int t = 0; t < 1000; t++)
            {
                haraka.update(result, 0, result.length);
                haraka.doFinal(result, 0);
            }
            isTrue("Monte Carlo test: " + c, this.areEqual(expected, result));

            //
            // Deliberately introduce incorrect value.
            //

            result[0] ^= 1;
            isTrue("Monte Carlo test: " + c, !this.areEqual(expected, result));
            c++;
        }
    }

    private boolean contains(String message, String sub)
    {
        return message.indexOf(sub) >= 0;
    }

    public void performTest()
        throws Exception
    {
        testKnownVector();
        testInputTooLong();
        testInputTooShort();
        testOutput();
        testMonty();
    }

    public static void main(
        String[] args)
    {
        runTest(new Haraka256DigestTest());
    }
}
