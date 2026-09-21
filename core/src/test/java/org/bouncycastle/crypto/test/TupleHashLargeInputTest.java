package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.TupleHash;
import org.bouncycastle.crypto.digests.XofUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * TupleHash over a single element of 2^28 bytes - the smallest element whose length in bits does
 * not fit in an int. The expected value is built by driving cSHAKE with the byte string NIST
 * Special Publication 800-185 section 5.3 prescribes, whose encode_string prefix (section 2.3.3)
 * is computed here in long arithmetic.
 * <p>
 * Allocates around 512 MiB transiently, so it belongs in RegressionTest.slowTests.
 * </p>
 */
public class TupleHashLargeInputTest
    extends SimpleTest
{
    private static final int ELEMENT_SIZE = 1 << 28;

    public String getName()
    {
        return "TupleHashLargeInput";
    }

    public void performTest()
        throws Exception
    {
        byte[] data = new byte[ELEMENT_SIZE];

        TupleHash tHash = new TupleHash(128, new byte[0]);

        tHash.update(data, 0, data.length);

        byte[] res = new byte[tHash.getDigestSize()];

        tHash.doFinal(res, 0);

        CSHAKEDigest cshake = new CSHAKEDigest(128, Strings.toByteArray("TupleHash"), new byte[0]);

        byte[] pre = XofUtils.leftEncode(data.length * 8L);

        cshake.update(pre, 0, pre.length);
        cshake.update(data, 0, data.length);

        byte[] post = XofUtils.rightEncode(res.length * 8L);

        cshake.update(post, 0, post.length);

        byte[] expected = new byte[res.length];

        cshake.doFinal(expected, 0, expected.length);

        isTrue("large element encoded at the wrong length", Arrays.areEqual(expected, res));
    }

    public static void main(
        String[] args)
    {
        runTest(new TupleHashLargeInputTest());
    }
}
