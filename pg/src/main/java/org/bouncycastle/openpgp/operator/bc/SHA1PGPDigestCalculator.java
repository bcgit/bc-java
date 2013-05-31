package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

class SHA1PGPDigestCalculator
    implements PGPDigestCalculator
{
    private Digest digest = new SHA1Digest();

    public int getAlgorithm()
    {
        return HashAlgorithmTags.SHA1;
    }

    public OutputStream getOutputStream()
    {
        return new DigestOutputStream(digest);
    }

    public byte[] getDigest()
    {
        byte[] d = new byte[digest.getDigestSize()];

        digest.doFinal(d, 0);

        return d;
    }

    public void reset()
    {
        digest.reset();
    }

    private class DigestOutputStream
        extends OutputStream
    {
        private Digest dig;

        DigestOutputStream(Digest dig)
        {
            this.dig = dig;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            dig.update(bytes, off, len);
        }

        public void write(byte[] bytes)
            throws IOException
        {
            dig.update(bytes, 0, bytes.length);
        }

        public void write(int b)
            throws IOException
        {
            dig.update((byte)b);
        }
    }
}
