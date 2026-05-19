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
        // TODO: with the change to createRandomPrime() these tests are possibly not relevant.
//        BigInteger min = BigInteger.valueOf(5);
//        isTrue(min.equals(BigIntegers.createRandomPrime(min.bitLength(), 1,
//            new TestRandomData(BigIntegers.asUnsignedByteArray(min)))));

//        BigInteger max = BigInteger.valueOf(743);
//        isTrue(max.equals(BigIntegers.createRandomPrime(max.bitLength(), 1,
//            new TestRandomData(BigIntegers.asUnsignedByteArray(max)))));

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
