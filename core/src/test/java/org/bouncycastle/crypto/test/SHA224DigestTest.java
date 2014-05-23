package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.util.encoders.Hex;

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
        
        // test state encoding; 
        byte[] lastV = toByteArray(messages[messages.length - 1]);
        byte[] lastDigest = Hex.decode(digests[digests.length - 1]);

        SHA224Digest digest = new SHA224Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];

        digest.update(lastV, 0, lastV.length/2);

        // copy the Digest
        SHA224Digest copy1 = new SHA224Digest(digest.getEncodedState());
        SHA224Digest copy2 = new SHA224Digest(copy1.getEncodedState());

        digest.update(lastV, lastV.length / 2, lastV.length - lastV.length / 2);

        digest.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing state vector test", digests[digests.length - 1], new String(Hex.encode(resBuf)));
        }

        copy1.update(lastV, lastV.length/2, lastV.length - lastV.length/2);
        copy1.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing state copy1 vector test", digests[digests.length - 1], new String(Hex.encode(resBuf)));
        }

        copy2.update(lastV, lastV.length / 2, lastV.length - lastV.length / 2);
        copy2.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing state copy2 vector test", digests[digests.length - 1], new String(Hex.encode(resBuf)));
        }
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new SHA224Digest((SHA224Digest)digest);
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new SHA224DigestTest());
    }
}
