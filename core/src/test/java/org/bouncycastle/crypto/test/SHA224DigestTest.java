package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;

/**
 * standard vector test for SHA-224 from RFC 3874 - only the last three are in
 * the RFC.
 */
public class SHA224DigestTest
    extends DigestTest
{
    private static String[] messages =
    {
        "",
        "a",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    };
    
    private static String[] digests =
    {
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
    };
    
    // 1 million 'a'
    static private String  million_a_digest = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";

    SHA224DigestTest()
    {
        super(new SHA224Digest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        millionATest(million_a_digest);
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new SHA224Digest((SHA224Digest)digest);
    }

    protected Digest cloneDigest(byte[] encodedState)
    {
        return new SHA224Digest(encodedState);
    }

    public static void main(
        String[]    args)
    {
        runTest(new SHA224DigestTest());
    }
}
