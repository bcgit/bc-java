package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Integers;

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
    private boolean forceBuffering;
    private boolean sealed;

    DeferredHash(TlsContext context)
    {
        this.context = context;
        this.buf = new DigestInputBuffer();
        this.hashes = new Hashtable();
        this.forceBuffering = false;
        this.sealed = false;
    }

    private DeferredHash(TlsContext context, Hashtable hashes)
    {
        this.context = context;
        this.buf = null;
        this.hashes = hashes;
        this.forceBuffering = false;
        this.sealed = true;
    }

    public void copyBufferTo(OutputStream output)
        throws IOException
    {
        if (buf == null)
        {
            // If you see this, you need to call forceBuffering() before sealHashAlgorithms()
            throw new IllegalStateException("Not buffering");
        }

        buf.copyTo(output);
    }

    public void forceBuffering()
    {
        if (sealed)
        {
            throw new IllegalStateException("Too late to force buffering");
        }

        this.forceBuffering = true;
    }

    public void notifyPRFDetermined()
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        switch (securityParameters.getPRFAlgorithm())
        {
        case PRFAlgorithm.ssl_prf_legacy:
        case PRFAlgorithm.tls_prf_legacy:
        {
            checkTrackingHash(CryptoHashAlgorithm.md5);
            checkTrackingHash(CryptoHashAlgorithm.sha1);
            break;
        }
        default:
        {
            checkTrackingHash(securityParameters.getPRFHashAlgorithm());
            if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
            {
                sealHashAlgorithms();
            }
            break;
        }
        }
    }

    public void trackHashAlgorithm(int cryptoHashAlgorithm)
    {
        if (sealed)
        {
            throw new IllegalStateException("Too late to track more hash algorithms");
        }

        checkTrackingHash(cryptoHashAlgorithm);
    }

    public void sealHashAlgorithms()
    {
        if (sealed)
        {
            throw new IllegalStateException("Already sealed");
        }

        this.sealed = true;
        checkStopBuffering();
    }

    public TlsHandshakeHash stopTracking()
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        Hashtable newHashes = new Hashtable();
        switch (securityParameters.getPRFAlgorithm())
        {
        case PRFAlgorithm.ssl_prf_legacy:
        case PRFAlgorithm.tls_prf_legacy:
        {
            cloneHash(newHashes, HashAlgorithm.md5);
            cloneHash(newHashes, HashAlgorithm.sha1);
            break;
        }
        default:
        {
            cloneHash(newHashes, securityParameters.getPRFHashAlgorithm());
            break;
        }
        }
        return new DeferredHash(context, newHashes);
    }

    public TlsHash forkPRFHash()
    {
        checkStopBuffering();

        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        TlsHash prfHash;
        switch (securityParameters.getPRFAlgorithm())
        {
        case PRFAlgorithm.ssl_prf_legacy:
        case PRFAlgorithm.tls_prf_legacy:
        {
            prfHash = new CombinedHash(context, cloneHash(HashAlgorithm.md5), cloneHash(HashAlgorithm.sha1));
            break;
        }
        default:
        {
            prfHash = cloneHash(securityParameters.getPRFHashAlgorithm());
            break;
        }
        }

        if (buf != null)
        {
            buf.updateDigest(prfHash);
        }

        return prfHash;
    }

    public byte[] getFinalHash(int cryptoHashAlgorithm)
    {
        TlsHash d = (TlsHash)hashes.get(box(cryptoHashAlgorithm));
        if (d == null)
        {
            throw new IllegalStateException("CryptoHashAlgorithm." + cryptoHashAlgorithm + " is not being tracked");
        }

        checkStopBuffering();

        d = d.cloneHash();
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
        throw new IllegalStateException("Use 'forkPRFHash' to get a definite hash");
    }

    public TlsHash cloneHash()
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

    protected Integer box(int cryptoHashAlgorithm)
    {
        return Integers.valueOf(cryptoHashAlgorithm);
    }

    protected void checkStopBuffering()
    {
        if (!forceBuffering && sealed && buf != null && hashes.size() <= BUFFERING_HASH_LIMIT)
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

    protected void checkTrackingHash(int cryptoHashAlgorithm)
    {
        checkTrackingHash(box(cryptoHashAlgorithm));
    }

    protected void checkTrackingHash(Integer cryptoHashAlgorithm)
    {
        if (!hashes.containsKey(cryptoHashAlgorithm))
        {
            TlsHash hash = context.getCrypto().createHash(cryptoHashAlgorithm.intValue());
            hashes.put(cryptoHashAlgorithm, hash);
        }
    }

    protected TlsHash cloneHash(int cryptoHashAlgorithm)
    {
        return cloneHash(box(cryptoHashAlgorithm));
    }

    protected TlsHash cloneHash(Integer cryptoHashAlgorithm)
    {
        return ((TlsHash)hashes.get(cryptoHashAlgorithm)).cloneHash();
    }

    protected void cloneHash(Hashtable newHashes, int cryptoHashAlgorithm)
    {
        cloneHash(newHashes, box(cryptoHashAlgorithm));
    }

    protected void cloneHash(Hashtable newHashes, Integer cryptoHashAlgorithm)
    {
        TlsHash hash = cloneHash(cryptoHashAlgorithm);
        if (buf != null)
        {
            buf.updateDigest(hash);
        }
        newHashes.put(cryptoHashAlgorithm, hash);
    }
}
