package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;

/**
 * standard vector test for MD2
 * from RFC1319 by B.Kaliski of RSA Laboratories April 1992
 *
 */
public class MD2DigestTest
    extends DigestTest
{
    static final String messages[] =
    {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };
    
    static final String digests[] =
    { 
        "8350e5a3e24c153df2275c9f80692773",
        "32ec01ec4a6dac72c0ab96fb34c0b5d1",
        "da853b0d3f88d99b30283a69e6ded6bb",
        "ab4f496bfb2a530b219ff33031fe06b0",
        "4e8ddff3650292ab5a4108c3aa47940b",
        "da33def2a42df13975352846c30338cd",
        "d5976f79d83d3a0dc9806c3c66f3efd8" 
    };
    
    MD2DigestTest()
    {
        super(new MD2Digest(), messages, digests);
    }
 
    protected Digest cloneDigest(
        Digest digest)
    {
        return new MD2Digest((MD2Digest)digest);
    }

    public static void main(
        String[]    args)
    {
        runTest(new MD2DigestTest());
    }
}
