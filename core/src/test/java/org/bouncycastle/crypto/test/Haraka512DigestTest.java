package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.Haraka512Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Haraka512DigestTest
    extends SimpleTest
{
    public String getName()
    {
        return "Haraka 512";
    }

    public void testKnownVector()
    {
        byte[] in = new byte[64];
        for (int t = 0; t < in.length; t++)
        {
            in[t] = (byte)t;
        }

        // From Appendix B, Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
        byte[] expected512 = Hex.decode("be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa");

        Haraka512Digest haraka = new Haraka512Digest();
        haraka.update(in, 0, in.length);
        byte[] out = new byte[haraka.getDigestSize()];
        haraka.doFinal(out, 0);
        isTrue("Did not match vector",this.areEqual(expected512, out));
    }

    public void testInputTooShort()
    {
        try
        {
            Haraka512Digest haraka = new Haraka512Digest();
            byte[] in = new byte[63];
            haraka.update(in, 0, in.length);
            haraka.doFinal(null, 0);
            fail("fail on input not 64 bytes.");
        }
        catch (IllegalStateException ilarex)
        {
            isTrue("message", contains(ilarex.getMessage(), "input must be exactly 64 bytes"));
        }
    }

    public void testInputTooLong()
    {
        try
        {
            Haraka512Digest haraka = new Haraka512Digest();
            byte[] in = new byte[65];
            haraka.update(in, 0, in.length);
            haraka.doFinal(null, 0);
            fail("fail on input not 64 bytes.");
        }
        catch (IllegalArgumentException ilarex)
        {
            isTrue("message", contains(ilarex.getMessage(), "total input cannot be more than 64 bytes"));
        }
    }

    public void testOutput()
    {
        //
        // Buffer too short.
        //
        try
        {
            Haraka512Digest haraka = new Haraka512Digest();
            byte[] in = new byte[64];
            haraka.update(in, 0, in.length);
            byte[] out = new byte[31];
            haraka.doFinal(out, 0);
            fail("Output too short for digest result.");
        }
        catch (IllegalArgumentException ilarex)
        {
            isTrue("message", contains(ilarex.getMessage(), "output too short to receive digest"));
        }

        //
        // Offset puts end past length of buffer.
        //
        try
        {
            Haraka512Digest haraka = new Haraka512Digest();
            byte[] in = new byte[64];
            haraka.update(in, 0, in.length);
            byte[] out = new byte[48];
            haraka.doFinal(out, 17);
            fail("Output too short for digest result.");
        }
        catch (IllegalArgumentException ilarex)
        {
            isTrue("message", contains(ilarex.getMessage(), "output too short to receive digest"));
        }

        //
        // Offset output..
        //
        byte[] in = new byte[64];
        for (int t = 0; t < in.length; t++)
        {
            in[t] = (byte)t;
        }

        byte[] expected512 = Hex.decode("00000000be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa");

        Haraka512Digest haraka = new Haraka512Digest();
        haraka.update(in, 0, in.length);
        byte[] out = new byte[haraka.getDigestSize() + 4];
        haraka.doFinal(out, 4);
        isTrue(this.areEqual(expected512, out));
    }

    void testMonty()
    {
        int c = 0;
        String[][] vectors = new String[][]{
            {
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
                "ABE210FE673F3B28E70E5100C476D82F61A7E2BDB3D8423FB0A15E5DE3D3A4DE"
            },
            {
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "5F5ECB52C61F5036C96BE555D2E18C520AB3ED093954700C283A322D14DBFE02"
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
            byte[] in = Hex.decode(vector[0]);
            Haraka512Digest haraka = new Haraka512Digest();
            byte[] result = new byte[haraka.getDigestSize()];
            for (int t = 0; t < 1000; t++)
            {
                haraka.update(in, 0, in.length);
                haraka.doFinal(result, 0);

                if ((t & 0x01) == 1)
                {
                    System.arraycopy(result, 0, in, 0, result.length);
                }
                else
                {
                    System.arraycopy(result, 0, in, result.length, result.length);
                }
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
        runTest(new Haraka512DigestTest());
    }
}
