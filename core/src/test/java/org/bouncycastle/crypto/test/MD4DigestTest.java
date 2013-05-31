package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;

/**
 * standard vector test for MD4 from RFC 1320.
 */
public class MD4DigestTest
    extends DigestTest
{
    static private String[] messages =
    {
        "",
        "a",
        "abc",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };
    
    static private String[] digests =
    {
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "bde52cb31de33e46245e05fbdbd6fb24",
        "a448017aaf21d8525fc10ae87aa6729d",
        "e33b4ddc9c38f2199c3e7b164fcc0536"
    };

    MD4DigestTest()
    {
        super(new MD4Digest(), messages, digests);
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new MD4Digest((MD4Digest)digest);
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new MD4DigestTest());
    }
}
