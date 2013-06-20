package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.Digest;

/**
 * Buffers input until the hash algorithm is determined.
 */
class DeferredHash
    implements TlsHandshakeHash
{
    protected TlsContext context;

    private DigestInputBuffer buf = new DigestInputBuffer();
    private int prfAlgorithm = -1;
    private Digest hash = null;

    DeferredHash()
    {
        this.buf = new DigestInputBuffer();
        this.hash = null;
    }

    private DeferredHash(Digest hash)
    {
        this.buf = null;
        this.hash = hash;
    }

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public TlsHandshakeHash commit()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();

        Digest prfHash = TlsUtils.createPRFHash(prfAlgorithm);

        buf.updateDigest(prfHash);

        if (prfHash instanceof TlsHandshakeHash)
        {
            TlsHandshakeHash tlsPRFHash = (TlsHandshakeHash)prfHash;
            tlsPRFHash.init(context);
            return tlsPRFHash.commit();
        }

        this.prfAlgorithm = prfAlgorithm;
        this.hash = prfHash;
        this.buf = null;

        return this;
    }

    public TlsHandshakeHash fork()
    {
        checkHash();
        return new DeferredHash(TlsUtils.clonePRFHash(prfAlgorithm, hash));
    }

    public String getAlgorithmName()
    {
        checkHash();
        return hash.getAlgorithmName();
    }

    public int getDigestSize()
    {
        checkHash();
        return hash.getDigestSize();
    }

    public void update(byte input)
    {
        if (hash == null)
        {
            buf.write(input);
        }
        else
        {
            hash.update(input);
        }
    }

    public void update(byte[] input, int inOff, int len)
    {
        if (hash == null)
        {
            buf.write(input, inOff, len);
        }
        else
        {
            hash.update(input, inOff, len);
        }
    }

    public int doFinal(byte[] output, int outOff)
    {
        checkHash();
        return hash.doFinal(output, outOff);
    }

    public void reset()
    {
        if (hash == null)
        {
            buf.reset();
        }
        else
        {
            hash.reset();
        }
    }

    protected void checkHash()
    {
        if (hash == null)
        {
            throw new IllegalStateException("No hash algorithm has been set");
        }
    }

    private static class DigestInputBuffer extends ByteArrayOutputStream
    {
        void updateDigest(Digest d)
        {
            d.update(buf, 0, count);
        }
    }
}
