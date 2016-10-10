package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.MessageDigest;

import org.bouncycastle.tls.crypto.TlsHash;

/**
 * Wrapper class for providing support methods for a TlsHash based on the JCA MessageDigest class.
 */
public class JcaTlsHash
    implements TlsHash
{
    private final MessageDigest digest;

    public JcaTlsHash(MessageDigest digest)
    {
        this.digest = digest;
    }

    public void update(byte[] data, int offSet, int length)
    {
        digest.update(data, offSet, length);
    }

    public byte[] calculateHash()
    {
        return digest.digest();
    }

    public Object clone()
    {
        try
        {
            return new JcaTlsHash((MessageDigest)digest.clone());
        }
        catch (CloneNotSupportedException e)
        {
            throw new UnsupportedOperationException("unable to clone digest");
        }
    }

    public void reset()
    {
        digest.reset();
    }
}
