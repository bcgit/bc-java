package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;

/**
 * RIPEMD128 Digest Test
 */
public class RIPEMD128DigestTest
    extends DigestTest
{
    final static String[] messages = {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };

    final static String[] digests = {
        "cdf26213a150dc3ecb610f18f6b38b46",
        "86be7afa339d0fc7cfc785e72f578d33",
        "c14a12199c66e4ba84636b0f69144c77",
        "9e327b3d6e523062afc1132d7df9d1b8",
        "fd2aa607f71dc8f510714922b371834e",
        "a1aa0689d0fafa2ddc22e88b49133a06",
        "d1e959eb179c911faea4624c60c5c702",
        "3f45ef194732c2dbb2c4a2c769795fa3"
    };

    final static String million_a_digest = "4a7f5723f954eba1216c9d8f6320431f";
        
    RIPEMD128DigestTest()
    {
        super(new RIPEMD128Digest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();
        
        millionATest(million_a_digest);
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new RIPEMD128Digest((RIPEMD128Digest)digest);
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new RIPEMD128DigestTest());
    }
}
