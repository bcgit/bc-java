package org.bouncycastle.openpgp.test;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.provider.digest.BCMessageDigest;

public class SHA256
    extends BCMessageDigest
    implements Cloneable
{
    public SHA256()
    {
        super(SHA256Digest.newInstance());
    }

    public Object clone()
        throws CloneNotSupportedException
    {
        SHA256 d = (SHA256)super.clone();
        d.digest = SHA256Digest.newInstance(digest);

        return d;
    }
}
