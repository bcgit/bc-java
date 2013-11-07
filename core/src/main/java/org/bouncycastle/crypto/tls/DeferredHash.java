package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;

/**
 * Buffers input until the hash algorithm is determined.
 */
class DeferredHash
    implements TlsHandshakeHash
{
    protected TlsContext context;

    private DigestInputBuffer buf = new DigestInputBuffer();
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

        this.hash = prfHash;
        this.buf = null;

        return this;
    }

    public TlsHandshakeHash fork()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
        Digest prfHash = TlsUtils.clonePRFHash(prfAlgorithm, checkHash());

        return new DeferredHash(prfHash);
    }

    public String getAlgorithmName()
    {
        return checkHash().getAlgorithmName();
    }

    public int getDigestSize()
    {
        return checkHash().getDigestSize();
    }

    public void update(byte input)
    {
        if (buf != null)
        {
            buf.write(input);
            return;
        }

        hash.update(input);
    }

    public void update(byte[] input, int inOff, int len)
    {
        if (buf != null)
        {
            buf.write(input, inOff, len);
            return;
        }

        hash.update(input, inOff, len);
    }

    public int doFinal(byte[] output, int outOff)
    {
        return checkHash().doFinal(output, outOff);
    }

    public void reset()
    {
        if (buf != null)
        {
            buf.reset();
            return;
        }

        hash.reset();
    }

    protected Digest checkHash()
    {
        if (buf != null)
        {
            throw new IllegalStateException("No hash algorithm has been decided on");
        }

        return hash;
    }
}
