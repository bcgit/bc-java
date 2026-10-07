package org.bouncycastle.crypto.kems.mlkem;

import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

/**
 * Checks MLKEMIndCpa.sampleNtt against a direct transcription of FIPS 203 Algorithm 7 (SampleNTT). Real seeds needing
 * more than one extra XOF block occur with probability about 2^-105 per entry, so those cases use a scripted stream.
 */
public class SampleNttTest
    extends TestCase
{
    public void testShakeStreams()
    {
        Random random = new Random(1);
        for (int i = 0; i < 200; i++)
        {
            byte[] seed = new byte[34];
            random.nextBytes(seed);
            SHAKEDigest shake = new SHAKEDigest(128);
            shake.update(seed, 0, seed.length);
            byte[] stream = new byte[2048];
            shake.doFinal(stream, 0, stream.length);

            checkAgainstSpec(stream);
        }
    }

    /**
     * Leading bytes of 0xFF give candidates of 0xFFF, all rejected, forcing zero, one, two and more extra blocks.
     */
    public void testExtraBlocks()
    {
        Random random = new Random(2);
        for (int rejected = 0; rejected <= 1200; rejected += 25)
        {
            byte[] stream = new byte[4096];
            random.nextBytes(stream);
            Arrays.fill(stream, 0, rejected, (byte)0xFF);

            checkAgainstSpec(stream);
        }
    }

    private static void checkAgainstSpec(byte[] stream)
    {
        Poly a = new Poly();
        ScriptedXof xof = new ScriptedXof(stream);
        MLKEMIndCpa.sampleNtt(xof, a, new byte[3 * 168 + 2]);

        short[] expected = sampleNttSpec(stream);
        for (int i = 0; i < MLKEMEngine.N; i++)
        {
            assertEquals("coefficient " + i, expected[i], a.getCoeffIndex(i));
        }
    }

    // FIPS 203 Algorithm 7, reading the XOF output as one continuous stream
    private static short[] sampleNttSpec(byte[] c)
    {
        short[] a = new short[MLKEMEngine.N];
        int j = 0, pos = 0;
        while (j < MLKEMEngine.N)
        {
            int d1 = (c[pos] & 0xFF) + 256 * ((c[pos + 1] & 0xFF) % 16);
            int d2 = ((c[pos + 1] & 0xFF) / 16) + 16 * (c[pos + 2] & 0xFF);
            pos += 3;
            if (d1 < MLKEMEngine.Q)
            {
                a[j++] = (short)d1;
            }
            if (d2 < MLKEMEngine.Q && j < MLKEMEngine.N)
            {
                a[j++] = (short)d2;
            }
        }
        return a;
    }

    private static class ScriptedXof
        implements Xof
    {
        private final byte[] stream;
        private int pos;

        ScriptedXof(byte[] stream)
        {
            this.stream = stream;
        }

        public int doOutput(byte[] out, int outOff, int outLen)
        {
            System.arraycopy(stream, pos, out, outOff, outLen);
            pos += outLen;
            return outLen;
        }

        public int doFinal(byte[] out, int outOff, int outLen)
        {
            return doOutput(out, outOff, outLen);
        }

        public int doFinal(byte[] out, int outOff)
        {
            return doOutput(out, outOff, getDigestSize());
        }

        public String getAlgorithmName()
        {
            return "Scripted";
        }

        public int getDigestSize()
        {
            return 32;
        }

        public int getByteLength()
        {
            return 168;
        }

        public void update(byte in)
        {
            throw new IllegalStateException();
        }

        public void update(byte[] in, int inOff, int len)
        {
            throw new IllegalStateException();
        }

        public void reset()
        {
            pos = 0;
        }
    }
}
