package org.bouncycastle.crypto.test;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

public class BigIntegersTest
    extends SimpleTest
{
    public String getName()
    {
        return "BigIntegers";
    }

    public void performTest()
        throws Exception
    {
        isTrue(1 == BigIntegers.asUnsignedByteArray(BigIntegers.ZERO).length);
        isTrue(1 == BigIntegers.getUnsignedByteLength(BigIntegers.ZERO));
        isTrue(1 == BigIntegers.getUnsignedByteLength(BigIntegers.ONE));
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new BigIntegersTest());
    }
}
