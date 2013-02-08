package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * A combined hash, which implements md5(m) || sha1(m).
 */
class CombinedHash implements Digest
{
    protected TlsClientContext context;
    protected MD5Digest md5;
    protected SHA1Digest sha1;

    CombinedHash()
    {
        this.md5 = new MD5Digest();
        this.sha1 = new SHA1Digest();
    }

    CombinedHash(TlsClientContext context)
    {
        this.context = context;
        this.md5 = new MD5Digest();
        this.sha1 = new SHA1Digest();
    }

    CombinedHash(CombinedHash t)
    {
        this.context = t.context;
        this.md5 = new MD5Digest(t.md5);
        this.sha1 = new SHA1Digest(t.sha1);
    }

    /**
     * @see org.bouncycastle.crypto.Digest#getAlgorithmName()
     */
    public String getAlgorithmName()
    {
        return md5.getAlgorithmName() + " and " + sha1.getAlgorithmName();
    }

    /**
     * @see org.bouncycastle.crypto.Digest#getDigestSize()
     */
    public int getDigestSize()
    {
        return 16 + 20;
    }

    /**
     * @see org.bouncycastle.crypto.Digest#update(byte)
     */
    public void update(byte in)
    {
        md5.update(in);
        sha1.update(in);
    }

    /**
     * @see org.bouncycastle.crypto.Digest#update(byte[],int,int)
     */
    public void update(byte[] in, int inOff, int len)
    {
        md5.update(in, inOff, len);
        sha1.update(in, inOff, len);
    }

    /**
     * @see org.bouncycastle.crypto.Digest#doFinal(byte[],int)
     */
    public int doFinal(byte[] out, int outOff)
    {
        if (context != null)
        {
            boolean isTls = context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
    
            if (!isTls)
            {
                ssl3Complete(md5, SSL3Mac.MD5_IPAD, SSL3Mac.MD5_OPAD);
                ssl3Complete(sha1, SSL3Mac.SHA1_IPAD, SSL3Mac.SHA1_OPAD);
            }
        }

        int i1 = md5.doFinal(out, outOff);
        int i2 = sha1.doFinal(out, outOff + 16);
        return i1 + i2;
    }

    /**
     * @see org.bouncycastle.crypto.Digest#reset()
     */
    public void reset()
    {
        md5.reset();
        sha1.reset();
    }

    protected void ssl3Complete(Digest d, byte[] ipad, byte[] opad)
    {
        byte[] secret = context.getSecurityParameters().masterSecret;

        d.update(secret, 0, secret.length);
        d.update(ipad, 0, ipad.length);

        byte[] tmp = new byte[d.getDigestSize()];
        d.doFinal(tmp, 0);

        d.update(secret, 0, secret.length);
        d.update(opad, 0, opad.length);
        d.update(tmp, 0, tmp.length);
    }
}
