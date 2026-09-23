package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.XofUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * left_encode and right_encode from NIST Special Publication 800-185 sections 2.3.1 and 2.3.2,
 * over lengths either side of the point where a bit count stops fitting in an int.
 */
public class XofUtilsTest
    extends SimpleTest
{
    public String getName()
    {
        return "XofUtils";
    }

    public void performTest()
        throws Exception
    {
        testLeftEncode();
        testRightEncode();
        testNegativeLength();
    }

    private void testLeftEncode()
    {
        isTrue("left_encode 0", Arrays.areEqual(Hex.decode("0100"), XofUtils.leftEncode(0)));
        isTrue("left_encode 8", Arrays.areEqual(Hex.decode("0108"), XofUtils.leftEncode(8)));
        isTrue("left_encode 2048", Arrays.areEqual(Hex.decode("020800"), XofUtils.leftEncode(2048)));

        // the bit length of the smallest byte string whose bit length overflows an int, and of
        // the largest one a byte array can hold
        isTrue("left_encode 2^31", Arrays.areEqual(Hex.decode("0480000000"), XofUtils.leftEncode((1L << 28) * 8)));
        isTrue("left_encode 2^32", Arrays.areEqual(Hex.decode("050100000000"), XofUtils.leftEncode(1L << 32)));
        isTrue("left_encode max", Arrays.areEqual(Hex.decode("0503fffffff8"), XofUtils.leftEncode(Integer.MAX_VALUE * 8L)));
    }

    private void testRightEncode()
    {
        isTrue("right_encode 0", Arrays.areEqual(Hex.decode("0001"), XofUtils.rightEncode(0)));
        isTrue("right_encode 512", Arrays.areEqual(Hex.decode("020002"), XofUtils.rightEncode(512)));
        isTrue("right_encode 2^32", Arrays.areEqual(Hex.decode("010000000005"), XofUtils.rightEncode(1L << 32)));
    }

    private void testNegativeLength()
    {
        testException("'strLen' cannot be negative", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                XofUtils.leftEncode(-1L);
            }
        });

        testException("'strLen' cannot be negative", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                XofUtils.rightEncode(Long.MIN_VALUE);
            }
        });
    }

    public static void main(
        String[] args)
    {
        runTest(new XofUtilsTest());
    }
}
