package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;

/**
 * A combined hash, which implements md5(m) || sha1(m).
 */
public class CombinedHash
    implements TlsHandshakeHash
{
    protected TlsContext context;
    protected TlsHash md5;
    protected TlsHash sha1;

    public CombinedHash(TlsContext context)
    {
        this.context = context;
        this.md5 = context.getCrypto().createHash(HashAlgorithm.md5);
        this.sha1 = context.getCrypto().createHash(HashAlgorithm.sha1);
    }

    public CombinedHash(CombinedHash t)
    {
        this.context = t.context;
        this.md5 = md5.cloneHash();
        this.sha1 = sha1.cloneHash();
    }

    public TlsHandshakeHash notifyPRFDetermined()
    {
        return this;
    }

    public void trackHashAlgorithm(short hashAlgorithm)
    {
        throw new IllegalStateException("CombinedHash only supports calculating the legacy PRF for handshake hash");
    }

    public void sealHashAlgorithms()
    {
    }

    public TlsHandshakeHash stopTracking()
    {
        return new CombinedHash(this);
    }

    public TlsHash forkPRFHash()
    {
        return new CombinedHash(this);
    }

    public byte[] getFinalHash(short hashAlgorithm)
    {
        throw new IllegalStateException("CombinedHash doesn't support multiple hashes");
    }

    public void update(byte[] input, int inOff, int len)
    {
        md5.update(input, inOff, len);
        sha1.update(input, inOff, len);
    }

    public byte[] calculateHash()
    {
        if (context != null && TlsUtils.isSSL(context))
        {
            ssl3Complete(md5, SSL3Mac.IPAD, SSL3Mac.OPAD, 48);
            ssl3Complete(sha1, SSL3Mac.IPAD, SSL3Mac.OPAD, 40);
        }

        return Arrays.concatenate(md5.calculateHash(), sha1.calculateHash());
    }

    public TlsHash cloneHash()
    {
        return new CombinedHash(this);
    }

    public void reset()
    {
        md5.reset();
        sha1.reset();
    }

    protected void ssl3Complete(TlsHash d, byte[] ipad, byte[] opad, int padLength)
    {
        byte[] master_secret = context.getSecurityParameters().masterSecret;

        d.update(master_secret, 0, master_secret.length);
        d.update(ipad, 0, padLength);

        byte[] tmp = d.calculateHash();

        d.update(master_secret, 0, master_secret.length);
        d.update(opad, 0, padLength);
        d.update(tmp, 0, tmp.length);
    }
}
