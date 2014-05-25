package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.util.encoders.Hex;

/**
 * standard vector test for SHA-512/256 from FIPS 180-4.
 *
 * Note, only the last 2 message entries are FIPS originated..
 */
public class SHA512t256DigestTest
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
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8",
        "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23",
        "3928E184FB8690F840DA3988121D31BE65CB9D3EF83EE6146FEAC861E19B563A"
    };

    // 1 million 'a'
    static private String  million_a_digest = "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21";

    SHA512t256DigestTest()
    {
        super(new SHA512tDigest(256), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        millionATest(million_a_digest);

        // test state encoding;

        byte[] lastV = toByteArray(messages[messages.length - 1]);
        byte[] lastDigest = Hex.decode(digests[digests.length - 1]);

        SHA512tDigest digest = new SHA512tDigest(256);
        byte[] resBuf = new byte[digest.getDigestSize()];

        digest.update(lastV, 0, lastV.length / 2);

        // copy the Digest
        SHA512tDigest copy1 = new SHA512tDigest(digest.getEncodedState());
        SHA512tDigest copy2 = new SHA512tDigest(copy1.getEncodedState());

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
        return new SHA512tDigest((SHA512tDigest)digest);
    }

    public static void main(
        String[]    args)
    {
        runTest(new SHA512t256DigestTest());
    }
}
