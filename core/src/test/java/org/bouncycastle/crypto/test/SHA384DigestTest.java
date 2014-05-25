package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * standard vector test for SHA-384 from FIPS Draft 180-2.
 *
 * Note, the first two vectors are _not_ from the draft, the last three are.
 */
public class SHA384DigestTest
    extends DigestTest
{
    private static String[] messages =
    {
        "",
        "a",
        "abc",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    };

    private static String[] digests =
    {
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
    };

    static private String  million_a_digest = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985";

    SHA384DigestTest()
    {
        super(new SHA384Digest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        millionATest(million_a_digest);

        // test state encoding;

        byte[] lastV = toByteArray(messages[messages.length - 1]);
        byte[] lastDigest = Hex.decode(digests[digests.length - 1]);

        SHA384Digest digest = new SHA384Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];

        digest.update(lastV, 0, lastV.length / 2);

        // copy the Digest
        SHA384Digest copy1 = new SHA384Digest(digest.getEncodedState());
        SHA384Digest copy2 = new SHA384Digest(copy1.getEncodedState());

        digest.update(lastV, lastV.length / 2, lastV.length - lastV.length / 2);

        digest.doFinal(resBuf, 0);

        if (!areEqual(lastDigest, resBuf))
        {
            fail("failing state vector test", digests[digests.length - 1], new String(Hex.encode(resBuf)));
        }

        copy1.update(lastV, lastV.length / 2, lastV.length - lastV.length / 2);
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
        return new SHA384Digest((SHA384Digest)digest);
    }

    public static void main(
        String[]    args)
    {
        runTest(new SHA384DigestTest());
    }
}
