package org.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
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
        return OutputStreamFactory.createStream(digest);
    }

    public byte[] getDigest()
    {
        return digest.digest();
    }

    public void reset()
    {
        digest.reset();
    }
}
