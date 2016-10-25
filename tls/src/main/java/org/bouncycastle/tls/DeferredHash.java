package org.bouncycastle.tls;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Shorts;

/**
 * Buffers input until the hash algorithm is determined.
 */
class DeferredHash
    implements TlsHandshakeHash
{
    protected static final int BUFFERING_HASH_LIMIT = 4;

    protected TlsContext context;

    private DigestInputBuffer buf;
    private Hashtable<Short, TlsHash> hashes;
    private Short prfHashAlgorithm;

    DeferredHash(TlsContext context)
    {
        this.context = context;
        this.buf = new DigestInputBuffer();
        this.hashes = new Hashtable();
        this.prfHashAlgorithm = null;
    }

    private DeferredHash(TlsContext context, Short prfHashAlgorithm, TlsHash prfHash)
    {
        this.context = context;
        this.buf = null;
        this.hashes = new Hashtable();
        this.prfHashAlgorithm = prfHashAlgorithm;
        hashes.put(prfHashAlgorithm, prfHash);
    }

    private DeferredHash(DeferredHash defHash)
    {
        this.context = defHash.context;
        this.buf = null;// TODO: need clone method?
        this.prfHashAlgorithm = defHash.prfHashAlgorithm;
        this.hashes = (Hashtable)defHash.hashes.clone();
        throw new IllegalStateException("not complete");
    }

    public TlsHandshakeHash notifyPRFDetermined()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
        {
            CombinedHash legacyHash = new CombinedHash(context);
            buf.updateDigest(legacyHash);
            return legacyHash.notifyPRFDetermined();
        }

        this.prfHashAlgorithm = Shorts.valueOf(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));

        checkTrackingHash(prfHashAlgorithm);

        return this;
    }

    public void trackHashAlgorithm(short hashAlgorithm)
    {
        if (buf == null)
        {
            throw new IllegalStateException("Too late to track more hash algorithms");
        }

        checkTrackingHash(Shorts.valueOf(hashAlgorithm));
    }

    public void sealHashAlgorithms()
    {
        checkStopBuffering();
    }

    public TlsHandshakeHash stopTracking()
    {
        TlsHash prfHash = (TlsHash)hashes.get(prfHashAlgorithm).clone();
        if (buf != null)
        {
            buf.updateDigest(prfHash);
        }
        DeferredHash result = new DeferredHash(context, prfHashAlgorithm, prfHash);

        return result;
    }

    public TlsHash forkPRFHash()
    {
        checkStopBuffering();

        if (buf != null)
        {
            TlsHash prfHash = context.getCrypto().createHash(prfHashAlgorithm.shortValue());
            buf.updateDigest(prfHash);
            return prfHash;
        }

        return (TlsHash)hashes.get(prfHashAlgorithm).clone();
    }

    public byte[] getFinalHash(short hashAlgorithm)
    {
        TlsHash d = (TlsHash)hashes.get(Shorts.valueOf(hashAlgorithm));
        if (d == null)
        {
            throw new IllegalStateException("HashAlgorithm." + HashAlgorithm.getText(hashAlgorithm) + " is not being tracked");
        }

        d = (TlsHash)d.clone();
        if (buf != null)
        {
            buf.updateDigest(d);
        }

        return d.calculateHash();
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
            TlsHash hash = (TlsHash)e.nextElement();
            hash.update(input, inOff, len);
        }
    }

    public byte[] calculateHash()
    {
        throw new IllegalStateException("Use fork() to get a definite Digest");
    }

    public Object clone()
    {
        throw new IllegalStateException("attempt to clone a DeferredHash");
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
            TlsHash hash = (TlsHash)e.nextElement();
            hash.reset();
        }
    }

    protected void checkStopBuffering()
    {
        if (buf != null && hashes.size() <= BUFFERING_HASH_LIMIT)
        {
            Enumeration e = hashes.elements();
            while (e.hasMoreElements())
            {
                TlsHash hash = (TlsHash)e.nextElement();
                buf.updateDigest(hash);
            }

            this.buf = null;
        }
    }

    protected void checkTrackingHash(Short hashAlgorithm)
    {
        if (!hashes.containsKey(hashAlgorithm))
        {
            TlsHash hash = context.getCrypto().createHash(hashAlgorithm.shortValue());
            hashes.put(hashAlgorithm, hash);
        }
    }
}
