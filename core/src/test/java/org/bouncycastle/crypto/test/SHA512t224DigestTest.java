package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.util.encoders.Hex;

/**
 * standard vector test for SHA-512/224 from FIPS 180-4.
 *
 * Note, only the last 2 message entries are FIPS originated..
 */
public class SHA512t224DigestTest
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
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327",
        "4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA",
        "23FEC5BB94D60B23308192640B0C453335D664734FE40E7268674AF9"
    };

    // 1 million 'a'
    static private String  million_a_digest = "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287";

    SHA512t224DigestTest()
    {
        super(new SHA512tDigest(224), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        millionATest(million_a_digest);

        // test state encoding;

        byte[] lastV = toByteArray(messages[messages.length - 1]);
        byte[] lastDigest = Hex.decode(digests[digests.length - 1]);

        SHA512tDigest digest = new SHA512tDigest(224);
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
        runTest(new SHA512t224DigestTest());
    }
}
