package org.bouncycastle.crypto.tls;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
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
    private Hashtable hashes;
    private Short prfHashAlgorithm;

    DeferredHash()
    {
        this.buf = new DigestInputBuffer();
        this.hashes = new Hashtable();
        this.prfHashAlgorithm = null;
    }

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public TlsHandshakeHash notifyPRFDetermined()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
        {
            CombinedHash legacyHash = new CombinedHash();
            legacyHash.init(context);
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

    public void keepHashAlgorithms(short[] hashAlgorithms)
    {
        Hashtable kept = new Hashtable();

        Enumeration e = hashes.keys();
        while (e.hasMoreElements())
        {
            Short key = (Short)e.nextElement();
            short hashAlgorithm = key.shortValue();

            if (hashAlgorithm == prfHashAlgorithm.shortValue()
                || TlsProtocol.arrayContains(hashAlgorithms, hashAlgorithm))
            {
                kept.put(key, hashes.get(key));
            }
        }

        this.hashes = kept;

        checkStopBuffering();
    }

    public Digest fork()
    {
        if (buf != null)
        {
            Digest hash = TlsUtils.createHash(prfHashAlgorithm.shortValue());
            buf.updateDigest(hash);
            return hash;
        }

        Digest prfHash = (Digest)hashes.get(prfHashAlgorithm);
        if (prfHash == null)
        {
            throw new IllegalStateException("PRF hash algorithm not tracked");
        }

        return TlsUtils.cloneHash(prfHashAlgorithm.shortValue(), prfHash);
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

    protected void checkStopBuffering()
    {
        if (buf != null && hashes.size() <= BUFFERING_HASH_LIMIT)
        {
            Enumeration e = hashes.elements();
            while (e.hasMoreElements())
            {
                Digest hash = (Digest)e.nextElement();
                buf.updateDigest(hash);
            }

            this.buf = null;
        }
    }

    protected void checkTrackingHash(Short hashAlgorithm)
    {
        if (!hashes.containsKey(hashAlgorithm))
        {
            Digest hash = TlsUtils.createHash(hashAlgorithm.shortValue());
            hashes.put(hashAlgorithm, hash);
        }
    }
}
