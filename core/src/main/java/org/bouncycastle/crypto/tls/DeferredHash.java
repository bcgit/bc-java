package org.bouncycastle.crypto.tls;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Integers;

/**
 * Buffers input until the hash algorithm is determined.
 */
class DeferredHash
    implements TlsHandshakeHash
{
    protected TlsContext context;

    private DigestInputBuffer buf;
    private Hashtable hashes;

    DeferredHash()
    {
        this.buf = new DigestInputBuffer();
        this.hashes = null;
    }

    private DeferredHash(int prfAlgorithm, Digest prfHash)
    {
        this.buf = null;
        this.hashes = new Hashtable();
        this.hashes.put(Integers.valueOf(prfAlgorithm), prfHash);
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

        this.buf = null;
        this.hashes = new Hashtable();
        this.hashes.put(Integers.valueOf(prfAlgorithm), prfHash);

        return this;
    }

    public Digest fork()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();

        Digest prfHash = (Digest)hashes.get(Integers.valueOf(prfAlgorithm));
        if (prfHash == null)
        {
            throw new IllegalStateException("PRF digest not registered");
        }

        prfHash = TlsUtils.clonePRFHash(prfAlgorithm, prfHash);
        
        if (buf != null)
        {
            buf.updateDigest(prfHash);
        }

        return prfHash;
    }

    public String getAlgorithmName()
    {
        throw new UnsupportedOperationException("Use fork() to get a definite Digest");
    }

    public int getDigestSize()
    {
        throw new UnsupportedOperationException("Use fork() to get a definite Digest");
    }

    public void update(byte input)
    {
        if (buf != null)
        {
            buf.write(input);
            return;
        }

        Enumeration e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.update(input);
        }
    }

    public void update(byte[] input, int inOff, int len)
    {
        if (buf != null)
        {
            buf.write(input, inOff, len);
            return;
        }

        Enumeration e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.update(input, inOff, len);
        }
    }

    public int doFinal(byte[] output, int outOff)
    {
        throw new UnsupportedOperationException("Use fork() to get a definite Digest");
    }

    public void reset()
    {
        if (buf != null)
        {
            buf.reset();
            return;
        }

        Enumeration e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.reset();
        }
    }
}
