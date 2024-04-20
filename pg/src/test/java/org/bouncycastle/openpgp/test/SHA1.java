package org.bouncycastle.openpgp.test;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jcajce.provider.digest.BCMessageDigest;

public class SHA1
    extends BCMessageDigest
    implements Cloneable
{
    public SHA1()
    {
        super(new SHA1Digest());
    }

    public Object clone()
        throws CloneNotSupportedException
    {
        SHA1 d = (SHA1)super.clone();
        d.digest = new SHA1Digest((SHA1Digest)digest);

        return d;
    }
}
