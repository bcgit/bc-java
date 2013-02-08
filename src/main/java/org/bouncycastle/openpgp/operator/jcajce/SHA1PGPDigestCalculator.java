package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

class SHA1PGPDigestCalculator
    implements PGPDigestCalculator
{
    private MessageDigest digest;

    SHA1PGPDigestCalculator()
    {
        try
        {
            digest = MessageDigest.getInstance("SHA1");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("cannot find SHA-1: " + e.getMessage());
        }
    }

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
        return digest.digest();
    }

    public void reset()
    {
        digest.reset();
    }

    private class DigestOutputStream
        extends OutputStream
    {
        private MessageDigest dig;

        DigestOutputStream(MessageDigest dig)
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
            dig.update(bytes);
        }

        public void write(int b)
            throws IOException
        {
            dig.update((byte)b);
        }

        byte[] getDigest()
        {
            return dig.digest();
        }
    }
}
