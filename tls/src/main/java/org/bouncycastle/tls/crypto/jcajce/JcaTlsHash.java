package org.bouncycastle.tls.crypto.jcajce;

import java.security.MessageDigest;

import org.bouncycastle.tls.crypto.TlsHash;

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

    public TlsHash cloneHash()
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
