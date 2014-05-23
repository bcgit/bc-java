package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * standard vector test for SHA-1 from "Handbook of Applied Cryptography", page 345.
 */
public class SHA1DigestTest
    extends DigestTest
{
    private static String[] messages =
    {
         "",
         "a",
         "abc",
         "abcdefghijklmnopqrstuvwxyz"
    };
    
    private static String[] digests =
    {
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"
    };
    
    SHA1DigestTest()
    {
        super(new SHA1Digest(), messages, digests);
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new SHA1Digest((SHA1Digest)digest);
    }

    public void performTest()
    {
        super.performTest();

        // test state encoding;

        byte[] lastV = toByteArray(messages[messages.length - 1]);
        byte[] lastDigest = Hex.decode(digests[digests.length - 1]);

        SHA1Digest digest = new SHA1Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];

        digest.update(lastV, 0, lastV.length/2);

        // copy the Digest
        SHA1Digest copy1 = new SHA1Digest(digest.getEncodedState());
        SHA1Digest copy2 = new SHA1Digest(copy1.getEncodedState());

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

    public static void main(
        String[]    args)
    {
        runTest(new SHA1DigestTest());
    }
}
