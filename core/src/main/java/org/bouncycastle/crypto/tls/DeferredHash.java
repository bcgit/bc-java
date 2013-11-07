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
    protected TlsContext context;

    private DigestInputBuffer buf;
    private Hashtable hashes;

    DeferredHash()
    {
        this.buf = new DigestInputBuffer();
        this.hashes = new Hashtable();
    }

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public TlsHandshakeHash commit()
    {
        // Ensure the PRF hash algorithm is being tracked
        {
            int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
            if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
            {
                CombinedHash legacyHash = new CombinedHash();
                legacyHash.init(context);
                buf.updateDigest(legacyHash);
                return legacyHash.commit();
            }

            short prfHashAlgorithm = TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm);
            if (!this.hashes.containsKey(Shorts.valueOf(prfHashAlgorithm)))
            {
                Digest prfHash = TlsUtils.createHash(prfHashAlgorithm);
                this.hashes.put(Shorts.valueOf(prfHashAlgorithm), prfHash);
            }
        }

        Enumeration e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            buf.updateDigest(hash);
        }

        this.buf = null;

        return this;
    }

    public Digest fork()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
        {
            throw new IllegalStateException("Legacy PRF shouldn't be calling this");
        }

        short hashAlgorithm = TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm);

        if (buf != null)
        {
            Digest hash = TlsUtils.createHash(hashAlgorithm);
            buf.updateDigest(hash);
            return hash;
        }

        Digest hash = (Digest)hashes.get(Shorts.valueOf(hashAlgorithm));
        if (hash == null)
        {
            throw new IllegalStateException("Digest not registered");
        }

        return TlsUtils.cloneHash(hashAlgorithm, hash);
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
