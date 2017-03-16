package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Arrays;

/**
 * A combined hash, which implements md5(m) || sha1(m).
 */
public class CombinedHash
    implements TlsHash
{
    protected TlsContext context;
    protected TlsCrypto crypto;
    protected TlsHash md5;
    protected TlsHash sha1;

    CombinedHash(TlsContext context, TlsHash md5, TlsHash sha1)
    {
        this.context = context;
        this.crypto = context.getCrypto();
        this.md5 = md5;
        this.sha1 = sha1;
    }

    public CombinedHash(TlsCrypto crypto)
    {
        this.crypto = crypto;
        this.md5 = crypto.createHash(HashAlgorithm.md5);
        this.sha1 = crypto.createHash(HashAlgorithm.sha1);
    }

    public CombinedHash(CombinedHash t)
    {
        this.context = t.context;
        this.crypto = t.crypto;
        this.md5 = (TlsHash)t.md5.clone();
        this.sha1 = (TlsHash)t.sha1.clone();
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
            byte[] ipad = SSL3Constants.getInputPad();
            byte[] opad = SSL3Constants.getOutputPad();

            ssl3Complete(md5, ipad, opad, 48);
            ssl3Complete(sha1, ipad, opad, 40);
        }

        return Arrays.concatenate(md5.calculateHash(), sha1.calculateHash());
    }

    public Object clone()
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
        byte[] master_secret = crypto.adoptSecret(context.getSecurityParameters().getMasterSecret()).extract();

        d.update(master_secret, 0, master_secret.length);
        d.update(ipad, 0, padLength);

        byte[] tmp = d.calculateHash();

        d.update(master_secret, 0, master_secret.length);
        d.update(opad, 0, padLength);
        d.update(tmp, 0, tmp.length);
    }
}
