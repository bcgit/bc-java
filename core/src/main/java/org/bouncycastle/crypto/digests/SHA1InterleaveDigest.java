package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;

/**
 * Implementation of the SHA_Interleave function from RFC 2945, section 3.1, as used by
 * SRP-SHA1 to produce a session key twice the length of a regular SHA-1 hash.
 * <p>
 * The complete input is buffered until {@link #doFinal(byte[], int)} is called: leading
 * zero bytes are removed, a further leading byte is removed if the remaining length is odd,
 * the even-numbered and odd-numbered bytes are then hashed separately with SHA-1, and the
 * two hashes are interleaved to form the 40 byte result.
 * </p>
 */
public class SHA1InterleaveDigest
    implements Digest, Memoable
{
    private static final int DIGEST_LENGTH = 40;

    private final OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();

    public SHA1InterleaveDigest()
    {
    }

    /**
     * Copy constructor. This will copy the state of the provided message digest.
     */
    public SHA1InterleaveDigest(SHA1InterleaveDigest t)
    {
        t.bOut.copyTo(bOut);
    }

    public String getAlgorithmName()
    {
        return "SHA1-INTERLEAVE";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    public void update(byte in)
    {
        bOut.write(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        bOut.write(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        if (out.length - outOff < DIGEST_LENGTH)
        {
            throw new OutputLengthException("output buffer too short");
        }

        byte[] input = bOut.toByteArray();

        // remove all leading zero bytes; if the remaining length is odd, also
        // remove the first byte (RFC 2945, section 3.1).
        int start = 0;
        while (start < input.length && input[start] == 0)
        {
            start++;
        }
        if (((input.length - start) & 1) != 0)
        {
            start++;
        }

        int half = (input.length - start) / 2;

        SHA1Digest sha = new SHA1Digest();
        byte[] g = new byte[20];
        byte[] h = new byte[20];

        for (int i = 0; i != half; i++)
        {
            sha.update(input[start + 2 * i]);
        }
        sha.doFinal(g, 0);

        for (int i = 0; i != half; i++)
        {
            sha.update(input[start + 2 * i + 1]);
        }
        sha.doFinal(h, 0);

        for (int i = 0; i != 20; i++)
        {
            out[outOff + 2 * i] = g[i];
            out[outOff + 2 * i + 1] = h[i];
        }

        Arrays.clear(input);
        Arrays.clear(g);
        Arrays.clear(h);

        reset();

        return DIGEST_LENGTH;
    }

    public void reset()
    {
        bOut.reset();
    }

    public Memoable copy()
    {
        return new SHA1InterleaveDigest(this);
    }

    public void reset(Memoable other)
    {
        SHA1InterleaveDigest d = (SHA1InterleaveDigest)other;

        bOut.reset();
        d.bOut.copyTo(bOut);
    }

    private static class OpenByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        public void reset()
        {
            super.reset();

            Arrays.clear(buf);
        }

        void copyTo(OpenByteArrayOutputStream other)
        {
            other.write(buf, 0, this.size());
        }
    }
}
